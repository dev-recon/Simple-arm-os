/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/programs/fbview/fbview.c
 * Layer: Userland / graphics test tool
 * Description: Decode JPEG/PNG/TIFF files and paint them to /dev/fb0.
 */

#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fb.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <jpeglib.h>
#include <png.h>
#include <tiffio.h>

struct image {
    uint32_t width;
    uint32_t height;
    uint32_t *argb;
};

struct jpeg_error_jump {
    struct jpeg_error_mgr pub;
    jmp_buf jump;
};

static void free_image(struct image *image)
{
    if (!image)
        return;
    free(image->argb);
    memset(image, 0, sizeof(*image));
}

static uint32_t pack_argb(unsigned a, unsigned r, unsigned g, unsigned b)
{
    return ((uint32_t)a << 24) | ((uint32_t)r << 16) |
           ((uint32_t)g << 8) | (uint32_t)b;
}

static int alloc_image(struct image *image, uint32_t width, uint32_t height)
{
    size_t count;

    if (width == 0 || height == 0)
        return 1;

    count = (size_t)width * (size_t)height;
    if (count / width != height)
        return 1;
    if (count > SIZE_MAX / sizeof(uint32_t))
        return 1;

    image->argb = (uint32_t *)malloc(count * sizeof(uint32_t));
    if (!image->argb)
        return 1;

    image->width = width;
    image->height = height;
    return 0;
}

static int read_signature(const char *path, unsigned char sig[8])
{
    FILE *fp = fopen(path, "rb");
    size_t got;

    if (!fp)
        return 1;

    memset(sig, 0, 8);
    got = fread(sig, 1, 8, fp);
    fclose(fp);
    return got == 0;
}

static void jpeg_error_exit(j_common_ptr cinfo)
{
    struct jpeg_error_jump *err = (struct jpeg_error_jump *)cinfo->err;
    longjmp(err->jump, 1);
}

static int load_jpeg(const char *path, struct image *image)
{
    FILE *fp = NULL;
    struct jpeg_decompress_struct cinfo;
    struct jpeg_error_jump jerr;
    JSAMPROW row[1];
    unsigned char *rowbuf = NULL;
    uint32_t y;

    memset(&cinfo, 0, sizeof(cinfo));

    fp = fopen(path, "rb");
    if (!fp) {
        perror("fbview: fopen jpeg");
        return 1;
    }

    cinfo.err = jpeg_std_error(&jerr.pub);
    jerr.pub.error_exit = jpeg_error_exit;
    if (setjmp(jerr.jump)) {
        jpeg_destroy_decompress(&cinfo);
        free(rowbuf);
        fclose(fp);
        return 1;
    }

    jpeg_create_decompress(&cinfo);
    jpeg_stdio_src(&cinfo, fp);
    jpeg_read_header(&cinfo, TRUE);
    cinfo.out_color_space = JCS_RGB;
    jpeg_start_decompress(&cinfo);

    if (alloc_image(image, cinfo.output_width, cinfo.output_height) != 0) {
        jpeg_destroy_decompress(&cinfo);
        fclose(fp);
        return 1;
    }

    rowbuf = (unsigned char *)malloc(cinfo.output_width * cinfo.output_components);
    if (!rowbuf) {
        jpeg_destroy_decompress(&cinfo);
        fclose(fp);
        return 1;
    }

    y = 0;
    while (cinfo.output_scanline < cinfo.output_height) {
        uint32_t x;
        row[0] = rowbuf;
        jpeg_read_scanlines(&cinfo, row, 1);
        for (x = 0; x < image->width; x++) {
            unsigned idx = x * cinfo.output_components;
            image->argb[(size_t)y * image->width + x] =
                pack_argb(0xff, rowbuf[idx], rowbuf[idx + 1], rowbuf[idx + 2]);
        }
        y++;
    }

    free(rowbuf);
    jpeg_finish_decompress(&cinfo);
    jpeg_destroy_decompress(&cinfo);
    fclose(fp);
    return 0;
}

static int load_png(const char *path, struct image *image)
{
    FILE *fp = NULL;
    png_structp png = NULL;
    png_infop info = NULL;
    png_bytep *rows = NULL;
    png_bytep pixels = NULL;
    png_uint_32 width;
    png_uint_32 height;
    png_size_t rowbytes;
    int bit_depth;
    int color_type;
    uint32_t y;

    fp = fopen(path, "rb");
    if (!fp) {
        perror("fbview: fopen png");
        return 1;
    }

    png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png) {
        fclose(fp);
        return 1;
    }

    info = png_create_info_struct(png);
    if (!info) {
        png_destroy_read_struct(&png, NULL, NULL);
        fclose(fp);
        return 1;
    }

    if (setjmp(png_jmpbuf(png))) {
        free(rows);
        free(pixels);
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return 1;
    }

    png_init_io(png, fp);
    png_read_info(png, info);
    png_get_IHDR(png, info, &width, &height, &bit_depth, &color_type,
                 NULL, NULL, NULL);

    if (bit_depth == 16)
        png_set_strip_16(png);
    if (color_type == PNG_COLOR_TYPE_PALETTE)
        png_set_palette_to_rgb(png);
    if (color_type == PNG_COLOR_TYPE_GRAY && bit_depth < 8)
        png_set_expand_gray_1_2_4_to_8(png);
    if (png_get_valid(png, info, PNG_INFO_tRNS))
        png_set_tRNS_to_alpha(png);
    if (color_type == PNG_COLOR_TYPE_GRAY ||
        color_type == PNG_COLOR_TYPE_GRAY_ALPHA)
        png_set_gray_to_rgb(png);
    if (!(color_type & PNG_COLOR_MASK_ALPHA))
        png_set_filler(png, 0xff, PNG_FILLER_AFTER);

    png_read_update_info(png, info);
    rowbytes = png_get_rowbytes(png, info);

    if (alloc_image(image, width, height) != 0) {
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return 1;
    }
    if (rowbytes == 0 || height > SIZE_MAX / rowbytes ||
        height > SIZE_MAX / sizeof(png_bytep)) {
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return 1;
    }

    pixels = (png_bytep)malloc(rowbytes * height);
    rows = (png_bytep *)malloc(sizeof(png_bytep) * height);
    if (!pixels || !rows) {
        free(rows);
        free(pixels);
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return 1;
    }

    for (y = 0; y < height; y++)
        rows[y] = pixels + rowbytes * y;

    png_read_image(png, rows);
    png_read_end(png, info);

    for (y = 0; y < height; y++) {
        uint32_t x;
        png_bytep src = rows[y];
        for (x = 0; x < width; x++) {
            png_bytep p = src + x * 4u;
            image->argb[(size_t)y * width + x] =
                pack_argb(p[3], p[0], p[1], p[2]);
        }
    }

    free(rows);
    free(pixels);
    png_destroy_read_struct(&png, &info, NULL);
    fclose(fp);
    return 0;
}

static int load_tiff(const char *path, struct image *image)
{
    TIFF *tif;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t *raster;
    uint32_t y;

    tif = TIFFOpen(path, "r");
    if (!tif)
        return 1;

    TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width);
    TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height);
    if (alloc_image(image, width, height) != 0) {
        TIFFClose(tif);
        return 1;
    }

    raster = (uint32_t *)malloc((size_t)width * height * sizeof(uint32_t));
    if (!raster) {
        TIFFClose(tif);
        return 1;
    }

    if (!TIFFReadRGBAImageOriented(tif, width, height, raster,
                                   ORIENTATION_TOPLEFT, 0)) {
        free(raster);
        TIFFClose(tif);
        return 1;
    }

    for (y = 0; y < height; y++) {
        uint32_t x;
        for (x = 0; x < width; x++) {
            uint32_t abgr = raster[(size_t)y * width + x];
            image->argb[(size_t)y * width + x] =
                pack_argb(TIFFGetA(abgr), TIFFGetR(abgr), TIFFGetG(abgr),
                          TIFFGetB(abgr));
        }
    }

    free(raster);
    TIFFClose(tif);
    return 0;
}

static int load_image(const char *path, struct image *image)
{
    unsigned char sig[8];

    if (read_signature(path, sig) != 0) {
        perror("fbview: read signature");
        return 1;
    }

    if (sig[0] == 0xff && sig[1] == 0xd8)
        return load_jpeg(path, image);

    if (png_sig_cmp(sig, 0, 8) == 0)
        return load_png(path, image);

    if ((sig[0] == 'I' && sig[1] == 'I' && sig[2] == 42 && sig[3] == 0) ||
        (sig[0] == 'M' && sig[1] == 'M' && sig[2] == 0 && sig[3] == 42))
        return load_tiff(path, image);

    printf("fbview: unsupported image format: %s\n", path);
    return 1;
}

static int write_full(int fd, const void *buffer, size_t count)
{
    const char *cursor = (const char *)buffer;
    size_t done = 0;

    while (done < count) {
        ssize_t written = write(fd, cursor + done, count - done);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0)
            return -1;
        done += (size_t)written;
    }

    return 0;
}

static int validate_fb(const struct armos_fb_info *info)
{
    return info->bpp == 32 && info->format == ARMOS_FB_FORMAT_ARGB8888 &&
           info->pitch >= (uint64_t)info->width * 4u &&
           info->size >= (uint64_t)info->pitch * info->height;
}

static int paint_framebuffer(int fd, const struct armos_fb_info *fb,
                             const struct image *image)
{
    uint8_t *row;
    uint32_t draw_w = image->width;
    uint32_t draw_h = image->height;
    uint32_t off_x;
    uint32_t off_y;
    uint32_t y;

    if (draw_w > fb->width || draw_h > fb->height) {
        uint64_t sx = ((uint64_t)fb->width << 32) / image->width;
        uint64_t sy = ((uint64_t)fb->height << 32) / image->height;
        uint64_t scale = sx < sy ? sx : sy;

        draw_w = (uint32_t)(((uint64_t)image->width * scale) >> 32);
        draw_h = (uint32_t)(((uint64_t)image->height * scale) >> 32);
        if (draw_w == 0)
            draw_w = 1;
        if (draw_h == 0)
            draw_h = 1;
    }

    off_x = (fb->width - draw_w) / 2u;
    off_y = (fb->height - draw_h) / 2u;

    row = (uint8_t *)malloc(fb->pitch);
    if (!row) {
        perror("fbview: malloc row");
        return 1;
    }

    for (y = 0; y < fb->height; y++) {
        uint32_t *dst = (uint32_t *)row;
        uint32_t x;

        memset(row, 0, fb->pitch);
        if (y >= off_y && y < off_y + draw_h) {
            uint32_t sy = ((y - off_y) * image->height) / draw_h;

            for (x = 0; x < draw_w; x++) {
                uint32_t sx = (x * image->width) / draw_w;
                dst[off_x + x] = image->argb[(size_t)sy * image->width + sx];
            }
        }

        if (lseek(fd, (off_t)((uint64_t)y * fb->pitch), SEEK_SET) < 0) {
            perror("fbview: lseek");
            free(row);
            return 1;
        }
        if (write_full(fd, row, fb->pitch) < 0) {
            perror("fbview: write");
            free(row);
            return 1;
        }
    }

    free(row);
    printf("fbview: %ux%u -> /dev/fb0 %ux%u draw=%ux%u+%u+%u\n",
           (unsigned)image->width, (unsigned)image->height,
           (unsigned)fb->width, (unsigned)fb->height,
           (unsigned)draw_w, (unsigned)draw_h, (unsigned)off_x,
           (unsigned)off_y);
    return 0;
}

static void usage(void)
{
    printf("usage: fbview IMAGE\n");
    printf("supported formats: JPEG, PNG, TIFF\n");
}

int main(int argc, char **argv)
{
    struct image image;
    struct armos_fb_info fb;
    int fd;
    int status = 1;

    memset(&image, 0, sizeof(image));

    if (argc != 2) {
        usage();
        return 1;
    }

    if (load_image(argv[1], &image) != 0) {
        printf("fbview: failed to decode %s\n", argv[1]);
        free_image(&image);
        return 1;
    }

    fd = open("/dev/fb0", O_RDWR, 0);
    if (fd < 0) {
        perror("fbview: open /dev/fb0");
        free_image(&image);
        return 1;
    }

    if (ioctl(fd, ARMOS_FBIOGET_INFO, &fb) < 0) {
        perror("fbview: ioctl ARMOS_FBIOGET_INFO");
        goto out;
    }

    if (!validate_fb(&fb)) {
        printf("fbview: unsupported framebuffer %ux%u pitch=%u bpp=%u format=%u size=%u\n",
               (unsigned)fb.width, (unsigned)fb.height, (unsigned)fb.pitch,
               (unsigned)fb.bpp, (unsigned)fb.format, (unsigned)fb.size);
        goto out;
    }

    if (paint_framebuffer(fd, &fb, &image) != 0)
        goto out;

    printf("FBVIEW_OK\n");
    status = 0;

out:
    close(fd);
    free_image(&image);
    return status;
}
