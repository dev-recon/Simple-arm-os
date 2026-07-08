#ifndef ARMOS_BSDINSTALL_SHA1_H
#define ARMOS_BSDINSTALL_SHA1_H

#include <stddef.h>

typedef struct {
    unsigned long opaque;
} SHA1_CTX;

void SHA1Init(SHA1_CTX *ctx);
void SHA1Update(SHA1_CTX *ctx, const void *data, size_t len);
char *SHA1End(SHA1_CTX *ctx, char *buf);
char *SHA1File(const char *path, char *buf);

#endif /* ARMOS_BSDINSTALL_SHA1_H */
