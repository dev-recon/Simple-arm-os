/*
 * ArmOS libtiff smoke test.
 *
 * Writes a tiny uncompressed grayscale TIFF, reads it back through
 * libtiff, and verifies dimensions plus pixel data.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tiffio.h>

#define TIFFTEST_WIDTH 8
#define TIFFTEST_HEIGHT 8
#define TIFFTEST_COMPONENTS 1
#define TIFFTEST_PATH "tifftest.tif"

static void fill_gray(unsigned char *image)
{
    unsigned y;

    for (y = 0; y < TIFFTEST_HEIGHT; y++) {
        unsigned x;

        for (x = 0; x < TIFFTEST_WIDTH; x++) {
            unsigned idx = y * TIFFTEST_WIDTH + x;
            image[idx] = (unsigned char)(20 + x * 17 + y * 9);
        }
    }
}

static int write_tiff(const unsigned char *image)
{
    TIFF *tif;
    unsigned y;

    tif = TIFFOpen(TIFFTEST_PATH, "w");
    if (!tif)
        return 1;

    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, TIFFTEST_WIDTH);
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, TIFFTEST_HEIGHT);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, TIFFTEST_COMPONENTS);
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(tif, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT);
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_MINISBLACK);
    TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
    TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, TIFFTEST_HEIGHT);

    for (y = 0; y < TIFFTEST_HEIGHT; y++) {
        const unsigned char *row = &image[y * TIFFTEST_WIDTH * TIFFTEST_COMPONENTS];
        if (TIFFWriteScanline(tif, (void *)row, y, 0) < 0) {
            TIFFClose(tif);
            return 1;
        }
    }

    TIFFClose(tif);
    return 0;
}

static int read_tiff(unsigned char *out, size_t out_size)
{
    TIFF *tif;
    uint32_t width = 0;
    uint32_t height = 0;
    uint16_t samples = 0;
    uint16_t bits = 0;
    uint16_t compression = 0;
    unsigned y;

    if (out_size < TIFFTEST_WIDTH * TIFFTEST_HEIGHT * TIFFTEST_COMPONENTS)
        return 1;

    tif = TIFFOpen(TIFFTEST_PATH, "r");
    if (!tif)
        return 1;

    TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width);
    TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height);
    TIFFGetField(tif, TIFFTAG_SAMPLESPERPIXEL, &samples);
    TIFFGetField(tif, TIFFTAG_BITSPERSAMPLE, &bits);
    TIFFGetField(tif, TIFFTAG_COMPRESSION, &compression);

    if (width != TIFFTEST_WIDTH || height != TIFFTEST_HEIGHT ||
        samples != TIFFTEST_COMPONENTS || bits != 8 ||
        compression != COMPRESSION_NONE) {
        TIFFClose(tif);
        return 1;
    }

    for (y = 0; y < TIFFTEST_HEIGHT; y++) {
        unsigned char *row = &out[y * TIFFTEST_WIDTH * TIFFTEST_COMPONENTS];
        if (TIFFReadScanline(tif, row, y, 0) < 0) {
            TIFFClose(tif);
            return 1;
        }
    }

    TIFFClose(tif);
    return 0;
}

static int verify_pixels(const unsigned char *expected,
                         const unsigned char *actual,
                         size_t size)
{
    size_t i;

    for (i = 0; i < size; i++) {
        if (expected[i] != actual[i]) {
            printf("tifftest: mismatch at byte %u got=%u expected=%u\n",
                   (unsigned)i, actual[i], expected[i]);
            return 1;
        }
    }

    return 0;
}

int main(void)
{
    unsigned char image[TIFFTEST_WIDTH * TIFFTEST_HEIGHT * TIFFTEST_COMPONENTS];
    unsigned char decoded[TIFFTEST_WIDTH * TIFFTEST_HEIGHT * TIFFTEST_COMPONENTS];

    fill_gray(image);
    memset(decoded, 0, sizeof(decoded));
    remove(TIFFTEST_PATH);

    if (write_tiff(image) != 0) {
        printf("tifftest: write failed\n");
        remove(TIFFTEST_PATH);
        return 1;
    }

    if (read_tiff(decoded, sizeof(decoded)) != 0) {
        printf("tifftest: read failed\n");
        remove(TIFFTEST_PATH);
        return 1;
    }

    if (verify_pixels(image, decoded, sizeof(image)) != 0) {
        remove(TIFFTEST_PATH);
        return 1;
    }

    printf("libtiff %s wrote %u uncompressed grayscale bytes\n",
           TIFFGetVersion(), (unsigned)sizeof(image));
    printf("TIFFTEST_OK\n");
    remove(TIFFTEST_PATH);
    return 0;
}
