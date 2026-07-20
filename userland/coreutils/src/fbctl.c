/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/fbctl.c
 * Layer: Userland / system utilities
 *
 * Responsibilities:
 * - Query the orientation of the active ArmOS framebuffer.
 * - Request portrait or landscape orientation through the /dev/fb0 ABI.
 * - Request a new firmware framebuffer mode when the backend supports it.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fb.h>
#include <sys/ioctl.h>
#include <unistd.h>

static const char *orientation_name(uint32_t orientation)
{
    switch (orientation) {
    case ARMOS_FB_ORIENTATION_PORTRAIT:
        return "portrait";
    case ARMOS_FB_ORIENTATION_LANDSCAPE:
        return "landscape";
    default:
        return "unknown";
    }
}

static void usage(void)
{
    fprintf(stderr,
            "usage: fbctl orientation\n"
            "       fbctl rotate portrait|landscape\n"
            "       fbctl mode WIDTHxHEIGHT\n");
}

static int parse_mode(const char *text, struct armos_fb_mode *mode)
{
    char *end;
    unsigned long width;
    unsigned long height;

    if (!text || !mode)
        return -1;

    width = strtoul(text, &end, 10);
    if (end == text || (*end != 'x' && *end != 'X') || width > UINT32_MAX)
        return -1;

    text = end + 1;
    height = strtoul(text, &end, 10);
    if (end == text || *end != '\0' || height > UINT32_MAX ||
        width == 0 || height == 0)
        return -1;

    mode->width = (uint32_t)width;
    mode->height = (uint32_t)height;
    return 0;
}

int main(int argc, char **argv)
{
    struct armos_fb_orientation orientation;
    struct armos_fb_info info;
    struct armos_fb_mode mode;
    int fd;

    if (argc != 2 && argc != 3) {
        usage();
        return 1;
    }

    fd = open("/dev/fb0", O_RDWR, 0);
    if (fd < 0) {
        perror("fbctl: open /dev/fb0");
        return 1;
    }

    if (argc == 2 && strcmp(argv[1], "orientation") == 0) {
        if (ioctl(fd, ARMOS_FBIOGET_ORIENTATION, &orientation) < 0) {
            perror("fbctl: get orientation");
            close(fd);
            return 1;
        }
    } else if (argc == 3 && strcmp(argv[1], "rotate") == 0) {
        if (strcmp(argv[2], "portrait") == 0)
            orientation.orientation = ARMOS_FB_ORIENTATION_PORTRAIT;
        else if (strcmp(argv[2], "landscape") == 0)
            orientation.orientation = ARMOS_FB_ORIENTATION_LANDSCAPE;
        else {
            usage();
            close(fd);
            return 1;
        }

        if (ioctl(fd, ARMOS_FBIOSET_ORIENTATION, &orientation) < 0) {
            if (errno == ENOTSUP)
                fprintf(stderr, "fbctl: framebuffer rotation is not supported\n");
            else
                perror("fbctl: set orientation");
            close(fd);
            return 1;
        }
    } else if (argc == 3 && strcmp(argv[1], "mode") == 0) {
        if (parse_mode(argv[2], &mode) < 0) {
            usage();
            close(fd);
            return 1;
        }
        if (ioctl(fd, ARMOS_FBIOSET_MODE, &mode) < 0) {
            if (errno == ENOTSUP)
                fprintf(stderr, "fbctl: framebuffer mode change is not supported\n");
            else
                perror("fbctl: set mode");
            close(fd);
            return 1;
        }
    } else {
        usage();
        close(fd);
        return 1;
    }

    if (ioctl(fd, ARMOS_FBIOGET_INFO, &info) < 0) {
        perror("fbctl: get framebuffer info");
        close(fd);
        return 1;
    }
    if (ioctl(fd, ARMOS_FBIOGET_ORIENTATION, &orientation) < 0) {
        perror("fbctl: get orientation");
        close(fd);
        return 1;
    }

    printf("%s %ux%u\n", orientation_name(orientation.orientation),
           (unsigned)info.width, (unsigned)info.height);
    close(fd);
    return 0;
}
