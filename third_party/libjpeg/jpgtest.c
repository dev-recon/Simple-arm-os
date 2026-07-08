/*
 * ArmOS libjpeg smoke test.
 *
 * Encodes a tiny RGB image into an in-memory JPEG, decodes it again from
 * memory, and verifies the decoded image shape and a representative color.
 */

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jpeglib.h>

#define JPGTEST_WIDTH 8
#define JPGTEST_HEIGHT 8
#define JPGTEST_COMPONENTS 3

struct jpgtest_error {
    struct jpeg_error_mgr pub;
    jmp_buf jump;
};

static void jpgtest_error_exit(j_common_ptr cinfo)
{
    struct jpgtest_error *err = (struct jpgtest_error *)cinfo->err;
    longjmp(err->jump, 1);
}

static void fill_rgb(unsigned char *image)
{
    unsigned y;

    for (y = 0; y < JPGTEST_HEIGHT; y++) {
        unsigned x;

        for (x = 0; x < JPGTEST_WIDTH; x++) {
            unsigned idx = (y * JPGTEST_WIDTH + x) * JPGTEST_COMPONENTS;
            image[idx + 0] = 200;
            image[idx + 1] = 40;
            image[idx + 2] = 90;
        }
    }
}

static int encode_jpeg(const unsigned char *image,
                       unsigned char **out,
                       size_t *out_size)
{
    struct jpeg_compress_struct cinfo;
    struct jpgtest_error jerr;
    JSAMPROW row[1];

    memset(&cinfo, 0, sizeof(cinfo));
    cinfo.err = jpeg_std_error(&jerr.pub);
    jerr.pub.error_exit = jpgtest_error_exit;
    if (setjmp(jerr.jump)) {
        jpeg_destroy_compress(&cinfo);
        return 1;
    }

    jpeg_create_compress(&cinfo);
    jpeg_mem_dest(&cinfo, out, out_size);
    cinfo.image_width = JPGTEST_WIDTH;
    cinfo.image_height = JPGTEST_HEIGHT;
    cinfo.input_components = JPGTEST_COMPONENTS;
    cinfo.in_color_space = JCS_RGB;
    jpeg_set_defaults(&cinfo);
    jpeg_set_quality(&cinfo, 90, TRUE);
    jpeg_start_compress(&cinfo, TRUE);

    while (cinfo.next_scanline < cinfo.image_height) {
        row[0] = (JSAMPROW)&image[cinfo.next_scanline * JPGTEST_WIDTH * JPGTEST_COMPONENTS];
        jpeg_write_scanlines(&cinfo, row, 1);
    }

    jpeg_finish_compress(&cinfo);
    jpeg_destroy_compress(&cinfo);
    return 0;
}

static int decode_jpeg(const unsigned char *jpeg_data,
                       size_t jpeg_size,
                       unsigned char *out,
                       size_t out_size)
{
    struct jpeg_decompress_struct cinfo;
    struct jpgtest_error jerr;
    JSAMPROW row[1];
    size_t stride;

    memset(&cinfo, 0, sizeof(cinfo));
    cinfo.err = jpeg_std_error(&jerr.pub);
    jerr.pub.error_exit = jpgtest_error_exit;
    if (setjmp(jerr.jump)) {
        jpeg_destroy_decompress(&cinfo);
        return 1;
    }

    jpeg_create_decompress(&cinfo);
    jpeg_mem_src(&cinfo, jpeg_data, jpeg_size);
    jpeg_read_header(&cinfo, TRUE);
    cinfo.out_color_space = JCS_RGB;
    jpeg_start_decompress(&cinfo);

    if (cinfo.output_width != JPGTEST_WIDTH ||
        cinfo.output_height != JPGTEST_HEIGHT ||
        cinfo.output_components != JPGTEST_COMPONENTS) {
        jpeg_destroy_decompress(&cinfo);
        return 1;
    }

    stride = cinfo.output_width * cinfo.output_components;
    if (stride * cinfo.output_height > out_size) {
        jpeg_destroy_decompress(&cinfo);
        return 1;
    }

    while (cinfo.output_scanline < cinfo.output_height) {
        row[0] = &out[cinfo.output_scanline * stride];
        jpeg_read_scanlines(&cinfo, row, 1);
    }

    jpeg_finish_decompress(&cinfo);
    jpeg_destroy_decompress(&cinfo);
    return 0;
}

static int close_enough(unsigned char got, unsigned char expected)
{
    int delta = (int)got - (int)expected;
    if (delta < 0)
        delta = -delta;
    return delta <= 32;
}

int main(void)
{
    unsigned char image[JPGTEST_WIDTH * JPGTEST_HEIGHT * JPGTEST_COMPONENTS];
    unsigned char decoded[JPGTEST_WIDTH * JPGTEST_HEIGHT * JPGTEST_COMPONENTS];
    unsigned char *jpeg_data = NULL;
    size_t jpeg_size = 0;

    fill_rgb(image);
    memset(decoded, 0, sizeof(decoded));

    if (encode_jpeg(image, &jpeg_data, &jpeg_size) != 0 || !jpeg_data) {
        printf("jpgtest: encode failed\n");
        return 1;
    }

    if (decode_jpeg(jpeg_data, jpeg_size, decoded, sizeof(decoded)) != 0) {
        free(jpeg_data);
        printf("jpgtest: decode failed\n");
        return 1;
    }

    if (!close_enough(decoded[0], image[0]) ||
        !close_enough(decoded[1], image[1]) ||
        !close_enough(decoded[2], image[2])) {
        printf("jpgtest: color mismatch got=%u,%u,%u expected=%u,%u,%u\n",
               decoded[0], decoded[1], decoded[2], image[0], image[1], image[2]);
        free(jpeg_data);
        return 1;
    }

    printf("libjpeg %d encoded %u RGB bytes to %u JPEG bytes\n",
           JPEG_LIB_VERSION, (unsigned)sizeof(image), (unsigned)jpeg_size);
    printf("JPGTEST_OK\n");
    free(jpeg_data);
    return 0;
}
