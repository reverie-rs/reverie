#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>

#include "utils.h"

void _expect(bool cond, const char* expr, const char* file, int line)
{
  if (!cond) {
    fprintf(stderr, "%s:%u expect: %s\n", file, line, expr);
    abort();
  }
}

void throwErrnoIfMinus(int x, const char* expr, const char* file, int line)
{
  if (x < 0) {
    fprintf(stderr, "%s:%u: %s returned %d, error: %s\n", file, line, expr, x, strerror(errno));
    abort();
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
