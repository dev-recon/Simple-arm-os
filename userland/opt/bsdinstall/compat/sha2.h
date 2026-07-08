#ifndef ARMOS_BSDINSTALL_SHA2_H
#define ARMOS_BSDINSTALL_SHA2_H

#include <stddef.h>

typedef struct {
    unsigned long opaque;
} SHA256_CTX;

typedef struct {
    unsigned long opaque;
} SHA384_CTX;

typedef struct {
    unsigned long opaque;
} SHA512_CTX;

void SHA256_Init(SHA256_CTX *ctx);
void SHA256_Update(SHA256_CTX *ctx, const void *data, size_t len);
char *SHA256_End(SHA256_CTX *ctx, char *buf);
char *SHA256_File(const char *path, char *buf);

void SHA384_Init(SHA384_CTX *ctx);
void SHA384_Update(SHA384_CTX *ctx, const void *data, size_t len);
char *SHA384_End(SHA384_CTX *ctx, char *buf);
char *SHA384_File(const char *path, char *buf);

void SHA512_Init(SHA512_CTX *ctx);
void SHA512_Update(SHA512_CTX *ctx, const void *data, size_t len);
char *SHA512_End(SHA512_CTX *ctx, char *buf);
char *SHA512_File(const char *path, char *buf);

#endif /* ARMOS_BSDINSTALL_SHA2_H */
