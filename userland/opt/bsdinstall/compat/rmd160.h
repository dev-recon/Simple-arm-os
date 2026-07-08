#ifndef ARMOS_BSDINSTALL_RMD160_H
#define ARMOS_BSDINSTALL_RMD160_H

#include <stddef.h>

typedef struct {
    unsigned long opaque;
} RMD160_CTX;

void RMD160Init(RMD160_CTX *ctx);
void RMD160Update(RMD160_CTX *ctx, const void *data, size_t len);
char *RMD160End(RMD160_CTX *ctx, char *buf);
char *RMD160File(const char *path, char *buf);

#endif /* ARMOS_BSDINSTALL_RMD160_H */
