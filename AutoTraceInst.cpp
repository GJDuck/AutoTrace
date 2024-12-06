/*
 *     _         _      _____                   
 *    / \  _   _| |_ __|_   _| __ __ _  ___ ___ 
 *   / _ \| | | | __/ _ \| || '__/ _` |/ __/ _ \
 *  / ___ \ |_| | || (_) | || | | (_| | (_|  __/
 * /_/   \_\__,_|\__\___/|_||_|  \__,_|\___\___|
 * 
 * Gregory J. Duck
 */

#include "stdlib.c"

static bool option_tty = false;

#define NAME        "AutoTrace"

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
struct LOC
{
    const char *file;
    size_t len;
    unsigned line;
};

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
    LOC start;              // Start location
    LOC stop;               // Stop location
    const char *dumpname;   // Dump file name
    void *threads;          // Threads
    int id;                 // Next thread id
    int dump;               // Full trace dump
    bool disabled;          // Disabled?
    bool comma;             // Need comma?
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
    {
        const char *dir = dirs[j];
        bool done = false;
        for (size_t l = 0; !done && dir[l] != '\0'; l++)
        {
            if (k < size)
                buf[k++] = dir[l];
            done = (dir[l] == '/');
        }
    }
    if (k < size)
        buf[k++] = '\0';
    return (ssize_t)(k-1);
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
    pid_t tid = gettid();
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
    return self->id;
}

/*
 * Match a location.
 */
static bool match(const LOC *loc, const char *file, unsigned line)
{
    if (loc->line != line || loc->file == NULL)
        return false;
    size_t len = strlen(file);
    if (len >= loc->len && strcmp(file + (len - loc->len), loc->file) == 0)
        return true;
    else
        return false;
}

/*
 * Write an output entry.
 */
static void output(const char *kind, int id, const char *file, unsigned line,
    void *addr)
{
    char buf[BUFSIZ];
    size_t size = sizeof(buf);
    ssize_t r = snprintf(buf, size, "%s\t{\"event\": \"%s\", \"thread\": %d, "
        "\"file\": \"", (S->comma? ",\n": ""), kind, id);
    if (r < 0 || (size_t)r >= size)
    {
        output_error:
        error("failed to output event");
    }
    r += normalize_path(file, buf+r, size-r);
    if ((size_t)r >= size)
        goto output_error;
    ssize_t t = snprintf(buf+r, size-r, "\", \"line\": %u}", line);
    r += t;
    if (t < 0 || (size_t)r >= size)
        goto output_error;
    write(S->dump, buf, r);
    S->comma = true;
}

/*
 * hit_line() is the main instrumentation entry point; called for every line.
 */
void hit_line(const char *func, const char *file, unsigned line, void *addr)
{
    if (mutex_lock(&S->lock) < 0)
        return;

    if (S->disabled)
    {
        if (!match(&S->start, file, line))
        {
            mutex_unlock(&S->lock);
            return;
        }
        S->disabled = false;
    }

    output("LINE", thread_id(), file, line, addr);

    if (match(&S->stop, file, line))
    {
        // Artificial "crash":
        fini();
        exit(EXIT_STOP);
    }

    mutex_unlock(&S->lock);
}

/*
 * hit_call() is called for each function call.
 */
void hit_call(const char *file, unsigned line, void *addr)
{
    if (mutex_lock(&S->lock) < 0)
        return;

    output("CALL", thread_id(), file, line, addr);

    mutex_unlock(&S->lock);
}

/*
 * hit_return() is called for each return.
 */
void hit_return(const char *file, unsigned line, void *addr)
{
    if (mutex_lock(&S->lock) < 0)
        return;

    output("RET ", thread_id(), file, line, addr);

    mutex_unlock(&S->lock);
}

/*
 * Parse a location (file:line)
 */
static void parse_loc(const char *str, LOC *loc)
{
    char buf[BUFSIZ];
    int colon = -1;
    for (int i = 0; i < sizeof(buf)-1 && str[i] != '\0'; i++)
    {
        buf[i] = str[i];
        colon = (str[i] == ':'? i: colon);
    }
    if (colon <= 0 || str[colon+1] == '\0')
        error("failed to parse location \"%s\"; missing `:'", loc);
    int val = atoi(str+colon+1);
    if (val <= 0)
        error("failed to parse location \"%s\"; inlocid line", loc);
    loc->line = (unsigned)val;
    buf[colon] = '\0';
    loc->file = strdup(buf);
    if (loc->file == NULL)
        error("failed to duplicat filename: %s", strerror(errno));
    loc->len = strlen(loc->file);
}

static void handler(int sig);

#include <stddef.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

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
        return;
    }
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

    const char *val = getenv("TRACE_START");
    if (val != NULL)
    {
        S->disabled = true;
        parse_loc(val, &S->start);
    }

    val = getenv("TRACE_STOP");
    if (val != NULL)
        parse_loc(val, &S->stop);

    val = getenv("TRACE_DUMP");
    S->dumpname = (val == NULL? "TRACE.json.gz": val);
//    S->dump = open(S->dumpname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
//    if (S->dump < 0)
//        error("failed to open \"%s\" for writing: %s", S->dumpname,
//            strerror(errno));

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
        dup(fd, STDOUT_FILENO);
        close(fd);
        dup(fds[0], STDIN_FILENO);
        close(fds[0]);
        const char *argv[] = {"gzip", "--stdout", NULL};
        execve("/bin/gzip", argv, environ);
        error("failed to execute `gzip' command: %s", strerror(errno));
    }
    close(fds[0]);
    S->dump = fds[1];
    fputs("[\n", S->dump);
    S->comma = false;

    // Make sure crashes call fini()
    signal(SIGSEGV, handler);
    signal(SIGBUS,  handler);
    signal(SIGFPE,  handler);
    signal(SIGILL,  handler);
    signal(SIGABRT, handler);

    // Block any attempt by the program to install other handlers:
    if (getenv("TRACE_SECCOMP") != NULL)
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

void fini(void)
{
    if (S->dump <= 0)
        return;
    const char *end[] = "\n]\n";
    write(S->dump, end, sizeof(end)-1);
    close(S->dump);
    fprintf(stderr, "%s" NAME "%s: write dump \"%s\"...\n",
        GREEN, OFF, S->dumpname);
}

void quit(int code)
{
    // Make sure _exit() and _Exit() call fini()
    fini();
    exit(code);
    abort();
}

static void handler(int sig)
{
    fini();
    exit(EXIT_STOP);
}

