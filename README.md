# AutoTrace -- Simple Line-based Tracing

AutoTrace is a simple tool that can generate a source-based execution trace of
a program in terms of file names and line numbers.
The trace is intended to be used by other tools.

## Build

To build AutoTrace, simply run the `build.sh` script:

        $ ./build.sh

## Usage

To use AutoTrace

1. First, build the target program with debug information (`-g`) and
   optimization disabled (`-O0`):

        $ CFLAGS="-O0 -g" ./configure
        $ make
        ...

2. Next, instrument the program using the `AutoTrace` script:

        $ ./AutoTrace instrument /path/to/program

   This will generate an instrumented version (`program.autotrace`) of the
   original program.
   Alternatively, you can also use the following command to *replace* the
   original program with the instrumented version:

        $ ./AutoTrace replace /path/to/program

3. Next, run the instrumented program with some test case:

        $ ./program.autotrace [ARGS ...]

   This will generate an `AUTOTRACE.json.gz` file, which contains all traced
   events.
   See below for the format.

## Trace Format

The generated `AUTOTRACE.json.gz` contains JSON entries of the following form:

        {"event": EVENT, "thread": THREAD, "func": FUNC, "file": FILE, "line": LINE}

Where:

* `EVENT`: is the event type.
  Current supported events include:
  - `"LINE"`: The source line was executed.
  - `"CALL"`: The current function was called (function entry).
  - `"RETURN"`: The current function returns (function exit).
* `THREAD`: a normalized thread ID, starting from zero.
* `FUNC`: the current function name.
* `FILE`: the absolute path of the source file name.
* `LINE`: the current line number.

The JSON entries are in order of execution, i.e., the `AUTOTRACE.json.gz` is a
representation of the execution trace of the program, in terms of source files
and line numbers.

Note that the `AUTOTRACE.json.gz` file may get very large, depending on the
length of the trace.

## About

AutoTrace is built on top of [E9Patch](https://github.com/GJDuck/e9patch).

Basically, AutoTrace instruments each source-based line to emit information
each time the line is executed.

## License

GPLv3

