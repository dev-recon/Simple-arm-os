/*
 * ArmOS zlib smoke test.
 *
 * Compresses and decompresses a short payload using libz.a and verifies that
 * the round trip preserves the data.
 */

#include <stdio.h>
#include <string.h>
#include <zlib.h>

int main(void)
{
    const unsigned char input[] =
        "ArmOS zlib test: framebuffer today, images tomorrow.";
    unsigned char compressed[256];
    unsigned char output[256];
    uLong compressed_len = sizeof(compressed);
    uLong output_len = sizeof(output);
    int ret;

    ret = compress2(compressed, &compressed_len, input, sizeof(input), Z_BEST_COMPRESSION);
    if (ret != Z_OK) {
        printf("ztest: compress2 failed: %d\n", ret);
        return 1;
    }

    ret = uncompress(output, &output_len, compressed, compressed_len);
    if (ret != Z_OK) {
        printf("ztest: uncompress failed: %d\n", ret);
        return 1;
    }

    if (output_len != sizeof(input) || memcmp(output, input, sizeof(input)) != 0) {
        printf("ztest: roundtrip mismatch\n");
        return 1;
    }

    printf("zlib %s compressed %lu bytes to %lu bytes\n",
           zlibVersion(), (unsigned long)sizeof(input), (unsigned long)compressed_len);
    printf("ZTEST_OK\n");
    return 0;
}
