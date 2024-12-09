/*
 *     _         _      _____                   
 *    / \  _   _| |_ __|_   _| __ __ _  ___ ___ 
 *   / _ \| | | | __/ _ \| || '__/ _` |/ __/ _ \
 *  / ___ \ |_| | || (_) | || | | (_| | (_|  __/
 * /_/   \_\__,_|\__\___/|_||_|  \__,_|\___\___|
 * 
 * Gregory J. Duck
 *
 * Copyright (C) National University of Singapore
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * The AutoTrace instrumentation module.
 */

#include "stdlib.c"

#include <stddef.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

static bool option_tty = false;

#define NAME        "AutoTrace"
#define PREFIX      "AUTOTRACE"

#define RED         (option_tty? "\33[31m": "")
#define GREEN       (option_tty? "\33[32m": "")
#define YELLOW      (option_tty? "\33[33m": "")
#define OFF         (option_tty? "\33[0m" : "")

#define EXIT_ERROR  66
#define EXIT_STOP  	67

#define PATH_MAX    4096

/*
 * Error reporting.
 */
#define error(msg, ...)                                     	\
    do {                                                    	\
        fprintf(stderr, "%serror%s: " msg "\n", RED, OFF,   	\
            ##__VA_ARGS__);                                 	\
        exit(EXIT_ERROR);                                      	\
    } while (false)
#define warning(msg, ...)                                     	\
    do {                                                    	\
        fprintf(stderr, "%swarning%s: " msg "\n", YELLOW, OFF,	\
            ##__VA_ARGS__);                                 	\
    } while (false)

/*
 * Thread/location representation.
 */
struct THREAD
{
    pid_t tid;				// Real thread ID
    int id;					// Simplified thread ID
};
typedef struct THREAD THREAD;

/*
 * Instrumentation "shared" state.
 *
 * This allows multiple binaries to be instrumented, and they will all share
 * the same "state", rather than independent states (the E9Tool default).
 */
struct SHARED
{
    mutex_t lock;
    struct malloc_pool_s *pool;
    const char *progname;   // This program's name
    const char *dumpname;   // Dump file name
    void *threads;          // Threads
    int id;                 // Next thread id
    int dump;               // Full trace dump
    bool comma;             // Need comma?
    bool tty;               // isatty?
};

/*
 * We place the "shared" state at a fixed address, so other instances of this
 * instrumentation can find it.  This may break programs that also use this
 * address.  However, most programs should not use this address.
 */
#define S           ((SHARED *)0xaab0000000)

/*
 * Prototypes.
 */
void fini(void);
static void handler(int sig);

/*
 * Normalize a JSON string.
 */
static ssize_t normalize_string(const char *s, char t, char *buf, size_t size)
{
    if (s == NULL)
        return 0;
    bool done = false;
    size_t k = 0;
    for (size_t i = 0; !done && s[i] != '\0'; i++)
    {
        char c = s[i];
        switch (c)
        {
            case '\"': case '\\':
                if (k < size) buf[k++] = '\\';
                if (k < size) buf[k++] = c;
                break;
            case '\t': case '\n': case '\r': case '\b': case '\f':
                if (k < size) buf[k++] = '\\';
                if (k < size)
                {
                    switch (c)
                    {
                        case '\t': buf[k++] = 't'; break;
                        case '\n': buf[k++] = 'n'; break;
                        case '\b': buf[k++] = 'b'; break;
                        case '\f': buf[k++] = 'f'; break;
                        case '\r': buf[k++] = 'r'; break;
                    }
                }
                break;
            default:
                if ((uint8_t)c < 0x20 || (uint8_t)c > 0x7E)
                {
                    if (k < size) buf[k++] = '\\';
                    if (k < size) buf[k++] = 'x';
                    if (k < size) buf[k++] = '0';
                    if (k < size) buf[k++] = '0';
                    const char *X = "0123456789ABCDEF";
                    if (k < size) buf[k++] = X[(uint8_t)c >> 4];
                    if (k < size) buf[k++] = X[(uint8_t)c & 0x7];
                }
                else if (k < size)
                    buf[k++] = c;
                break;
        }
        done = (c == t);
    }
    if (k < size)
        buf[k] = '\0';
    return (ssize_t)k;
}

/*
 * Normalize a path.  DWARF paths may contain "../", "./", etc.
 */
static ssize_t normalize_path(const char *path, char *buf, size_t size)
{
    size_t MAX = PATH_MAX / 2, i = 0, k = 0;
    const char *dirs[MAX];
    const char *ptr = path;
    while (ptr != NULL)
    {
        const char *dir = ptr;
        const char *next = strchr(ptr, '/');
        ptr = (next == NULL? NULL: next+1);
        if (dir[0] == '/' || dir[0] == '\0')
        {
            if (i == 0)
                dirs[i++] = dir;
        }
        else if (dir[0] == '.' && (dir[1] == '/' || dir[1] == '\0'))
            ;
        else if (dir[0] == '.' && dir[1] == '.' &&
                (dir[2] == '/' || dir[2] == '\0'))
        {
            if (i > 0)
                i--;
        }
        else if (i >= MAX)
            error("failed to normalize path \"%s\"; path is too long", path);
        else
            dirs[i++] = dir;
    }
    ptr = buf;
    for (size_t j = 0; j < i; j++)
        k += normalize_string(dirs[j], '/', buf + k, size - k);
    if (k < size)
        buf[k] = '\0';
    return (ssize_t)k;
}

/*
 * Get a (normalized) thread ID.
 */
static int thread_compare(const void *a, const void *b)
{
    const THREAD *t = (THREAD *)a;
    const THREAD *u = (THREAD *)b;
    return (int)t->tid - (int)u->tid;
}
static int thread_id(void)
{
    /*
     * BUG: The following code assumes that tid's are never reused.  This is
     *      almost always true for real programs, but not guaranteed.
     */
	static pid_t cached_tid = 0;
    static int   cached_id  = 0;
    pid_t tid = gettid();
	if (tid == cached_tid)
        return cached_id;
    THREAD key;
    key.tid = tid;

    void *node = tfind(&key, &S->threads, thread_compare);
    if (node == NULL)
    {
        THREAD *self = (THREAD *)pool_malloc(S->pool, sizeof(THREAD));
        if (self == NULL)
            error("failed to allocated %zu bytes: %s", sizeof(THREAD),
                strerror(errno));
        self->tid = tid;
        self->id  = ++S->id;
        node = tsearch(self, &S->threads, thread_compare);
        if (node == NULL)
            error("failed to create THREAD %d: %s", self->id, strerror(errno));
    }
    const THREAD *self = *(THREAD **)node;
    cached_tid = self->tid;
    cached_id  = self->id;
    return self->id;
}

/*
 * Write an output entry.
 */
static void output(const char *kind, int id, const char *func,
    const char *file, unsigned line)
{
    char buf[BUFSIZ];
    size_t size = sizeof(buf);
    ssize_t r = snprintf(buf, size, "%s\t{\"event\": \"%s\", \"thread\": %d, "
        "\"func\": \"", (S->comma? ",\n": ""), kind, id);
    if (r < 0 || (size_t)r >= size)
    {
        output_error:
        error("failed to output %s event", kind);
    }
    r += normalize_string(func, '\0', buf+r, size-r);
    if ((size_t)r >= size)
        goto output_error;
    ssize_t t = snprintf(buf+r, size-r, "\", \"file\": \"");
    r += t;
    if (t < 0 || (size_t)r >= size)
        goto output_error;

    r += normalize_path(file, buf+r, size-r);
    if ((size_t)r >= size)
        goto output_error;
    t = snprintf(buf+r, size-r, "\", \"line\": %u}", line);
    r += t;
    if (t < 0 || (size_t)r >= size)
        goto output_error;
    write(S->dump, buf, r);
    S->comma = true;
}

/*
 * hit_line() is the main instrumentation entry point; called for every line.
 */
void hit_line(const char *func, const char *file, unsigned line)
{
    if (mutex_lock(&S->lock) < 0)
        return;
    output("LINE", thread_id(), func, file, line);
    mutex_unlock(&S->lock);
}

/*
 * hit_call() is called for each function call.
 */
void hit_call(const char *func, const char *file, unsigned line)
{
    if (mutex_lock(&S->lock) < 0)
        return;
    output("CALL", thread_id(), func, file, line);
    mutex_unlock(&S->lock);
}

/*
 * hit_return() is called for each return.
 */
void hit_return(const char *func, const char *file, unsigned line)
{
    if (mutex_lock(&S->lock) < 0)
        return;
    output("RETURN", thread_id(), func, file, line);
    mutex_unlock(&S->lock);
}

/*
 * Called on entry.
 */
void init(int argc, char **argv, char **envp)
{
    size_t size = MA_PAGE_SIZE;
    void *ptr = mmap((void *)S, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED)
        error("failed to map common area: %s", strerror(errno));
    if (ptr != (void *)S)
    {
        fprintf(stderr, "%s" NAME "%s: skip init\n", GREEN, OFF);
        // Already initialized by another binary:
        (void)munmap(ptr, size);
        option_tty = S->tty;
        return;
    }
    option_tty = S->tty = isatty(STDERR_FILENO);
    fprintf(stderr, "%s" NAME "%s: init\n", GREEN, OFF);
    S->pool = &malloc_pool;

    char path[PATH_MAX+1] = {0};
    if (readlink("/proc/self/exe", path, sizeof(path)-1) < 0)
        error("failed to read program name: %s", strerror(errno));
    size_t len = strlen(path);
    char *progname = (char *)pool_malloc(S->pool, len+1);
    if (progname == NULL)
        error("failed to duplicate program name: %s", strerror(errno));
    memcpy(progname, path, len+1);
    S->progname = progname;

    environ = envp;

    const char *val = getenv(PREFIX "_DUMP");
    S->dumpname = (val == NULL? PREFIX ".json.gz": val);

    // Fork-off a gzip process for compression:
    int fds[2];
    if (pipe(fds) < 0)
        error("failed to create pipe: %s", strerror(errno));
    pid_t child = fork();
    if (child < 0)
        error("failed to fork process: %s", strerror(errno));
    if (child == 0)
    {
        close(fds[1]);
        int fd = open(S->dumpname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0)
            error("failed to open \"%s\" for writing: %s", S->dumpname,
                strerror(errno));
        dup2(fd, STDOUT_FILENO);
        close(fd);
        dup2(fds[0], STDIN_FILENO);
        close(fds[0]);
        const char * const argv[] = {"gzip", "--stdout", NULL};
        execve("/bin/gzip", (char * const *)argv, environ);
        error("failed to execute `gzip' command: %s", strerror(errno));
    }
    close(fds[0]);
    S->dump = fds[1];
    const char begin[] = "[\n";
    write(S->dump, begin, sizeof(begin)-1);
    S->comma = false;

    // Make sure crashes call fini()
    signal(SIGSEGV, handler);
    signal(SIGBUS,  handler);
    signal(SIGFPE,  handler);
    signal(SIGILL,  handler);
    signal(SIGABRT, handler);

    // Block any attempt by the program to install other handlers:
    if (getenv(PREFIX "_SECCOMP") != NULL)
    {
        struct sock_filter filter[] =
        {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigaction, 0, 4),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                offsetof(struct seccomp_data, args[2])),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 0),   // "succeed"
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog fprog =
        {
            (unsigned short)(sizeof(filter) / sizeof(filter[0])),
            filter
        };
        if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, /*flags=*/0x0,
                &fprog) < 0)
            warning("failed to set seccomp filter: %s", strerror(errno));
    }
}

/*
 * Called on exit.
 */
void fini(void)
{
    if (S->dump <= 0)
        return;
    const char end[] = "\n]\n";
    write(S->dump, end, sizeof(end)-1);
    close(S->dump);
    fprintf(stderr, "%s" NAME "%s: write dump \"%s\"...\n",
        GREEN, OFF, S->dumpname);
}

/*
 * Called on fast _exit().
 */
void hit_quit(int code)
{
    // Make sure _exit() and _Exit() call fini()
    fini();
    exit(code);
    abort();
}

/*
 * Called on signal.
 */
static void handler(int sig)
{
    fini();
    exit(EXIT_STOP);
}

