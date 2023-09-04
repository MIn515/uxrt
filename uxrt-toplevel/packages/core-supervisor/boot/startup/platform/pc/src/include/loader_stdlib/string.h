#ifndef __LOADER_STDLIB_STRING_H
#define __LOADER_STDLIB_STRING_H
#define strerror loader_strerror
#include <string.h>
size_t strlcpy(char *dst, const char *src, size_t dstsize);

#endif /*__LOADER_STDLIB_STRING_H*/
