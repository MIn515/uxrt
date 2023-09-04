#ifndef __CORE_ERROR_H
#define __CORE_ERROR_H
const char *loader_strerror(int errnum);
void loader_perror(const char *str);
#endif
