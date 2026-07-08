#ifndef ARMOS_BSDSED_UTIL_H
#define ARMOS_BSDSED_UTIL_H

#include <stddef.h>
#include <stdio.h>

void setprogname(const char *name);
const char *getprogname(void);

void *emalloc(size_t size);
void *ecalloc(size_t count, size_t size);
void *erealloc(void *ptr, size_t size);
char *estrdup(const char *s);

#ifndef ARMOS_HAVE_GETLINE
ssize_t getline(char **linep, size_t *linecap, FILE *stream);
#endif

#endif /* ARMOS_BSDSED_UTIL_H */

