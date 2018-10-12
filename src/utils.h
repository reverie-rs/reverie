#ifndef _MY_UTILS_H
#define _MY_UTILS_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#define Expect(expr) ( _expect(expr, #expr, __FILE__, __LINE__) )
#define ThrowErrnoIfMinus(expr) ( throwErrnoIfMinus(expr, #expr, __FILE__, __LINE__) )

extern void _expect(bool cond, const char* expr, const char* file, int line);
extern void throwErrnoIfMinus(int x, const char* expr, const char* file, int line);
extern void panic(const char* fmt, ...);

extern void debug_init(int level);

extern void _debug_printf(int level, bool prefix, const char* fmt, ...);

enum {
	DEBUG_CRITICAL,
	DEBUG_ERROR,
	DEBUG_LOG,
	DEBUG_INFO,
	DEBUG_DEBUG,
};

#define crit(...) _debug_printf(DEBUG_CRITICAL, true, __VA_ARGS__)
#define error(...) _debug_printf(DEBUG_ERROR, true, __VA_ARGS__)
#define log(...) _debug_printf(DEBUG_LOG, true, __VA_ARGS__)
#define info(...) _debug_printf(DEBUG_INFO, true, __VA_ARGS__)
#define debug(...) _debug_printf(DEBUG_DEBUG, true, __VA_ARGS__)

#define crit_( ...) _debug_printf(DEBUG_CRITICAL, false,  __VA_ARGS__)
#define error_( ...) _debug_printf(DEBUG_ERROR, false,  __VA_ARGS__)
#define log_( ...) _debug_printf(DEBUG_LOG, false,  __VA_ARGS__)
#define info_( ...) _debug_printf(DEBUG_INFO, false,  __VA_ARGS__)
#define debug_( ...) _debug_printf(DEBUG_DEBUG, false,  __VA_ARGS__)

#endif
