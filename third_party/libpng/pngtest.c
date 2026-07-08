/*
 * ArmOS libpng smoke test.
 *
 * Encodes a tiny RGB image to an in-memory PNG, decodes it again from memory,
 * and verifies that the pixels survived the round trip exactly.
 */

#include <setjmp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>
#include <zlib.h>

#define PNGTEST_WIDTH 8
#define PNGTEST_HEIGHT 8
#define PNGTEST_COMPONENTS 3

struct pngtest_buffer {
    unsigned char *data;
    size_t size;
    size_t capacity;
    size_t offset;
};

static void fill_rgb(unsigned char *image)
{
    unsigned y;

    for (y = 0; y < PNGTEST_HEIGHT; y++) {
        unsigned x;

        for (x = 0; x < PNGTEST_WIDTH; x++) {
            unsigned idx = (y * PNGTEST_WIDTH + x) * PNGTEST_COMPONENTS;
            image[idx + 0] = (unsigned char)(30 + x * 20);
            image[idx + 1] = (unsigned char)(80 + y * 15);
            image[idx + 2] = (unsigned char)(200 - x * 10);
        }
    }
}

static int ensure_capacity(struct pngtest_buffer *buffer, size_t extra)
{
    size_t needed = buffer->size + extra;
    size_t capacity = buffer->capacity;
    unsigned char *data;

    if (needed <= capacity)
        return 0;

    if (capacity == 0)
        capacity = 256;

    while (capacity < needed)
        capacity *= 2;

    data = (unsigned char *)realloc(buffer->data, capacity);
    if (!data)
        return 1;

    buffer->data = data;
    buffer->capacity = capacity;
    return 0;
}

static void write_png_data(png_structp png, png_bytep data, png_size_t length)
{
    struct pngtest_buffer *buffer = (struct pngtest_buffer *)png_get_io_ptr(png);

    if (ensure_capacity(buffer, length) != 0)
        png_error(png, "pngtest: out of memory");

    memcpy(buffer->data + buffer->size, data, length);
    buffer->size += length;
}

static void flush_png_data(png_structp png)
{
    (void)png;
}

static void read_png_data(png_structp png, png_bytep data, png_size_t length)
{
    struct pngtest_buffer *buffer = (struct pngtest_buffer *)png_get_io_ptr(png);

    if (buffer->offset + length > buffer->size)
        png_error(png, "pngtest: read past end of buffer");

    memcpy(data, buffer->data + buffer->offset, length);
    buffer->offset += length;
}

static int encode_png(const unsigned char *image,
                      unsigned char **out,
                      size_t *out_size)
{
    png_structp png = NULL;
    png_infop info = NULL;
    png_bytep rows[PNGTEST_HEIGHT];
    struct pngtest_buffer buffer;
    unsigned y;

    memset(&buffer, 0, sizeof(buffer));

    png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png)
        return 1;

    info = png_create_info_struct(png);
    if (!info) {
        png_destroy_write_struct(&png, NULL);
        return 1;
    }

    if (setjmp(png_jmpbuf(png))) {
        png_destroy_write_struct(&png, &info);
        free(buffer.data);
        return 1;
    }

    for (y = 0; y < PNGTEST_HEIGHT; y++)
        rows[y] = (png_bytep)&image[y * PNGTEST_WIDTH * PNGTEST_COMPONENTS];

    png_set_write_fn(png, &buffer, write_png_data, flush_png_data);
    png_set_IHDR(png, info, PNGTEST_WIDTH, PNGTEST_HEIGHT, 8,
                 PNG_COLOR_TYPE_RGB, PNG_INTERLACE_NONE,
                 PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);
    png_write_info(png, info);
    png_write_image(png, rows);
    png_write_end(png, info);
    png_destroy_write_struct(&png, &info);

    *out = buffer.data;
    *out_size = buffer.size;
    return 0;
}

static int decode_png(const unsigned char *png_data,
                      size_t png_size,
                      unsigned char *out,
                      size_t out_size)
{
    png_structp png = NULL;
    png_infop info = NULL;
    png_bytep rows[PNGTEST_HEIGHT];
    struct pngtest_buffer buffer;
    png_uint_32 width;
    png_uint_32 height;
    int bit_depth;
    int color_type;
    unsigned y;

    if (out_size < PNGTEST_WIDTH * PNGTEST_HEIGHT * PNGTEST_COMPONENTS)
        return 1;

    memset(&buffer, 0, sizeof(buffer));
    buffer.data = (unsigned char *)png_data;
    buffer.size = png_size;

    png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png)
        return 1;

    info = png_create_info_struct(png);
    if (!info) {
        png_destroy_read_struct(&png, NULL, NULL);
        return 1;
    }

    if (setjmp(png_jmpbuf(png))) {
        png_destroy_read_struct(&png, &info, NULL);
        return 1;
    }

    png_set_read_fn(png, &buffer, read_png_data);
    png_read_info(png, info);
    png_get_IHDR(png, info, &width, &height, &bit_depth, &color_type,
                 NULL, NULL, NULL);

    if (width != PNGTEST_WIDTH || height != PNGTEST_HEIGHT ||
        bit_depth != 8 || color_type != PNG_COLOR_TYPE_RGB) {
        png_destroy_read_struct(&png, &info, NULL);
        return 1;
    }

    for (y = 0; y < PNGTEST_HEIGHT; y++)
        rows[y] = &out[y * PNGTEST_WIDTH * PNGTEST_COMPONENTS];

    png_read_image(png, rows);
    png_read_end(png, info);
    png_destroy_read_struct(&png, &info, NULL);
    return 0;
}

static int verify_pixels(const unsigned char *expected,
                         const unsigned char *actual,
                         size_t size)
{
    size_t i;

    for (i = 0; i < size; i++) {
        if (expected[i] != actual[i]) {
            printf("pngtest: mismatch at byte %u got=%u expected=%u\n",
                   (unsigned)i, actual[i], expected[i]);
            return 1;
        }
    }

    return 0;
}

int main(void)
{
    unsigned char image[PNGTEST_WIDTH * PNGTEST_HEIGHT * PNGTEST_COMPONENTS];
    unsigned char decoded[PNGTEST_WIDTH * PNGTEST_HEIGHT * PNGTEST_COMPONENTS];
    unsigned char *png_data = NULL;
    size_t png_size = 0;

    fill_rgb(image);
    memset(decoded, 0, sizeof(decoded));

    if (encode_png(image, &png_data, &png_size) != 0 || !png_data) {
        printf("pngtest: encode failed\n");
        return 1;
    }

    if (decode_png(png_data, png_size, decoded, sizeof(decoded)) != 0) {
        free(png_data);
        printf("pngtest: decode failed\n");
        return 1;
    }

    if (verify_pixels(image, decoded, sizeof(image)) != 0) {
        free(png_data);
        return 1;
    }

    printf("libpng %s zlib %s encoded %u RGB bytes to %u PNG bytes\n",
           PNG_LIBPNG_VER_STRING, zlibVersion(),
           (unsigned)sizeof(image), (unsigned)png_size);
    printf("PNGTEST_OK\n");
    free(png_data);
    return 0;
}
