/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/stat.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>

static const char *file_type(mode_t mode)
{
    if (S_ISDIR(mode)) return "directory";
    if (S_ISREG(mode)) return "regular file";
    if (S_ISCHR(mode)) return "character device";
    if (S_ISBLK(mode)) return "block device";
    if (S_ISFIFO(mode)) return "fifo";
    if (S_ISLNK(mode)) return "symbolic link";
    if (S_ISSOCK(mode)) return "socket";
    return "unknown";
}

static void mode_string(mode_t mode, char *out)
{
    out[0]  = S_ISDIR(mode) ? 'd' : S_ISLNK(mode) ? 'l' :
              S_ISCHR(mode) ? 'c' : S_ISBLK(mode) ? 'b' :
              S_ISFIFO(mode) ? 'p' : S_ISSOCK(mode) ? 's' : '-';
    out[1]  = (mode & 0400) ? 'r' : '-';
    out[2]  = (mode & 0200) ? 'w' : '-';
    out[3]  = (mode & 0100) ? 'x' : '-';
    out[4]  = (mode & 0040) ? 'r' : '-';
    out[5]  = (mode & 0020) ? 'w' : '-';
    out[6]  = (mode & 0010) ? 'x' : '-';
    out[7]  = (mode & 0004) ? 'r' : '-';
    out[8]  = (mode & 0002) ? 'w' : '-';
    out[9]  = (mode & 0001) ? 'x' : '-';
    out[10] = '\0';
}

static void format_time(uint32_t ts, char *out)
{
    static const int mdays[12] = {31,28,31,30,31,30,31,31,30,31,30,31};

    uint32_t sec = ts % 60; ts /= 60;
    uint32_t min = ts % 60; ts /= 60;
    uint32_t hour = ts % 24; ts /= 24;
    uint32_t days = ts;
    uint32_t year = 1970;

    for (;;) {
        int leap = (year % 4 == 0) && (year % 100 != 0 || year % 400 == 0);
        uint32_t yd = 365u + (uint32_t)leap;
        if (days < yd) break;
        days -= yd;
        year++;
    }

    int leap = (year % 4 == 0) && (year % 100 != 0 || year % 400 == 0);
    int month = 0;
    for (; month < 12; month++) {
        int md = mdays[month] + (month == 1 && leap ? 1 : 0);
        if ((int)days < md) break;
        days -= (uint32_t)md;
    }

    sprintf(out, "%04u-%02u-%02u %02u:%02u:%02u",
            year, (uint32_t)month + 1, days + 1, hour, min, sec);
}

static void format_mode_octal(mode_t mode, char *out)
{
    unsigned value = (unsigned)(mode & 07777);

    out[0] = (char)('0' + ((value >> 9) & 7));
    out[1] = (char)('0' + ((value >> 6) & 7));
    out[2] = (char)('0' + ((value >> 3) & 7));
    out[3] = (char)('0' + (value & 7));
    out[4] = '\0';
}

static int print_stat(const char *path)
{
    struct stat st;
    char perms[11];
    char mode_oct[5];
    char atime[24];
    char mtime[24];
    char ctime[24];

    if (stat(path, &st) < 0) {
        printf("stat: cannot stat '%s'\n", path);
        return 1;
    }

    mode_string(st.st_mode, perms);
    format_mode_octal(st.st_mode, mode_oct);
    format_time((uint32_t)st.st_atime, atime);
    format_time((uint32_t)st.st_mtime, mtime);
    format_time((uint32_t)st.st_ctime, ctime);

    printf("  File: %s\n", path);
    printf("  Size: %-10u Blocks: %-8u IO Block: %-6u %s\n",
           (uint32_t)st.st_size, (uint32_t)st.st_blocks,
           (uint32_t)st.st_blksize, file_type(st.st_mode));
    printf("Device: %-10u Inode: %-10u Links: %u\n",
           (uint32_t)st.st_dev, (uint32_t)st.st_ino, (uint32_t)st.st_nlink);
    printf("Access: (%s/%s)  Uid: %u   Gid: %u\n",
           mode_oct, perms, (uint32_t)st.st_uid, (uint32_t)st.st_gid);
    printf("Access: %s\n", atime);
    printf("Modify: %s\n", mtime);
    printf("Change: %s\n", ctime);

    return 0;
}

int main(int argc, char **argv)
{
    int status = 0;

    if (argc < 2) {
        printf("usage: stat FILE...\n");
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (print_stat(argv[i]) != 0)
            status = 1;
        if (i + 1 < argc)
            printf("\n");
    }

    return status;
}
