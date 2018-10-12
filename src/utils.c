#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <execinfo.h>

#include "utils.h"

#define BACKTRACE_MAX 128

void __attribute__((noreturn)) panic(const char* fmt, ...)
{
  void *buffer[BACKTRACE_MAX];
  va_list ap;
  int n;

  fprintf(stderr, "\n================================ PANIC ================================\n");
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  n = backtrace(buffer, BACKTRACE_MAX);
  backtrace_symbols_fd(buffer, n, STDOUT_FILENO);
  abort();
}

void _expect(bool cond, const char* expr, const char* file, int line)
{
  if (!cond) {
    fprintf(stderr, "%s:%u expect: %s\n", file, line, expr);
    panic("");
  }
}

void throwErrnoIfMinus(int x, const char* expr, const char* file, int line)
{
  if (x < 0) {
    fprintf(stderr, "%s:%u: %s returned %d, error: %s\n", file, line, expr, x, strerror(errno));
    panic("");
  }
}

static int debug_level;

void debug_init(int level) {
  debug_level = level;
}

static const char* prefix[] = {" CRIT", "ERROR", " LOG ", " INFO", "DEBUG" };

void _debug_printf(int level, bool hasPrefix, const char* fmt, ...)
{
  FILE* fp = stdout;
  if (level > DEBUG_DEBUG) level = DEBUG_DEBUG;

  if (debug_level >= level) {
    va_list ap;
    if (level <= DEBUG_ERROR) fp = stderr;
    if(hasPrefix) fprintf(fp, "[%s] ", prefix[level]);
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    if (fp == stderr) abort();
    va_end(ap);
  }
}
