#ifndef ARMOS_BSDINSTALL_MD5_H
#define ARMOS_BSDINSTALL_MD5_H

#include <stddef.h>

typedef struct {
    unsigned long opaque;
} MD5_CTX;

void MD5Init(MD5_CTX *ctx);
void MD5Update(MD5_CTX *ctx, const void *data, size_t len);
char *MD5End(MD5_CTX *ctx, char *buf);
char *MD5File(const char *path, char *buf);

#endif /* ARMOS_BSDINSTALL_MD5_H */
