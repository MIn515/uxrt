#pragma once
#include "selfe_types.h"

extern char *strcpy(char *s1, const char *s2);
extern void debug_puts(char* s);
extern void *memcpy(void *dest, const void *src, selfe_size_t n);
extern void *memset(void *s, int c, selfe_size_t n);

#define ROUND_UP(n, b) \
    ({ typeof (n) _n = (n); \
       typeof (b) _b = (b); \
       (_n + (_n % _b == 0 ? 0 : (_b - (_n % _b)))); \
    })
