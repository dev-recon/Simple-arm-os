/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/programs/fbtest/fbtest.c
 * Layer: Userland / test or sample program
 * Description: Smoke test for /dev/fb0 raw framebuffer access.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fb.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

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

static uint32_t fb_pixel(unsigned x, unsigned y, const struct armos_fb_info *info)
{
    unsigned width = info->width ? info->width : 1;
    unsigned height = info->height ? info->height : 1;
    unsigned tile = ((x / 64u) ^ (y / 64u)) & 1u;
    uint8_t r = (uint8_t)((x * 255u) / width);
    uint8_t g = (uint8_t)((y * 255u) / height);
    uint8_t b = tile ? 0xffu : 0x40u;

    return 0xff000000u | ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
}

static int paint_framebuffer(int fd, const struct armos_fb_info *info)
{
    unsigned y;
    uint8_t *row;

    row = malloc(info->pitch);
    if (!row) {
        perror("fbtest: malloc");
        return 1;
    }

    for (y = 0; y < info->height; y++) {
        unsigned x;
        uint32_t *pixels = (uint32_t *)row;

        memset(row, 0, info->pitch);
        for (x = 0; x < info->width; x++)
            pixels[x] = fb_pixel(x, y, info);

        if (lseek(fd, (off_t)(y * info->pitch), SEEK_SET) < 0) {
            perror("fbtest: lseek");
            free(row);
            return 1;
        }
        if (write_full(fd, row, info->pitch) < 0) {
            perror("fbtest: write");
            free(row);
            return 1;
        }
    }

    free(row);
    return 0;
}

int main(void)
{
    struct armos_fb_info info;
    struct stat st;
    uint32_t first_pixel;
    uint32_t expected;
    int fd;

    fd = open("/dev/fb0", O_RDWR, 0);
    if (fd < 0) {
        perror("fbtest: open /dev/fb0");
        return 1;
    }

    if (ioctl(fd, ARMOS_FBIOGET_INFO, &info) < 0) {
        perror("fbtest: ioctl ARMOS_FBIOGET_INFO");
        close(fd);
        return 1;
    }

    if (info.bpp != 32 || info.format != ARMOS_FB_FORMAT_ARGB8888 ||
        info.pitch < info.width * 4u || info.size < info.pitch * info.height) {
        printf("fbtest: unsupported framebuffer %ux%u pitch=%u bpp=%u format=%u size=%u\n",
               (unsigned)info.width, (unsigned)info.height, (unsigned)info.pitch,
               (unsigned)info.bpp, (unsigned)info.format, (unsigned)info.size);
        close(fd);
        return 1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fbtest: fstat");
        close(fd);
        return 1;
    }

    printf("fbtest: /dev/fb0 %ux%u pitch=%u bpp=%u size=%u stat_size=%ld\n",
           (unsigned)info.width, (unsigned)info.height, (unsigned)info.pitch,
           (unsigned)info.bpp, (unsigned)info.size, (long)st.st_size);

    if (paint_framebuffer(fd, &info) != 0) {
        close(fd);
        return 1;
    }

    if (lseek(fd, 0, SEEK_SET) < 0) {
        perror("fbtest: rewind");
        close(fd);
        return 1;
    }
    if (read(fd, &first_pixel, sizeof(first_pixel)) != (ssize_t)sizeof(first_pixel)) {
        perror("fbtest: readback");
        close(fd);
        return 1;
    }

    expected = fb_pixel(0, 0, &info);
    if (first_pixel != expected) {
        printf("fbtest: readback mismatch got=0x%08x expected=0x%08x\n",
               (unsigned)first_pixel, (unsigned)expected);
        close(fd);
        return 1;
    }

    close(fd);
    printf("FBTEST_OK\n");
    return 0;
}
