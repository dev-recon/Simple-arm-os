/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/system/tools/fsck-lite.c
 * Layer: Userland / system service
 * Description: System-level userspace component for ArmOS.
 */

#include <stdio.h>
#include <string.h>
#include "arm_os_abi.h"

static void print_ext2_check(void)
{
    FILE* f = fopen("/proc/fs/ext2/check", "r");
    char line[160];

    if (!f)
        return;

    while (fgets(line, sizeof(line), f))
        printf("%s", line);
    fclose(f);
}

static int check_path(const char* path)
{
    struct statfs st;
    int status = 0;

    if (statfs(path, &st) < 0) {
        printf("%s: statfs failed\n", path);
        return 1;
    }

    printf("%s: block=%u blocks=%u free=%u avail=%u files=%u ffree=%u namelen=%u\n",
           path, st.f_bsize, st.f_blocks, st.f_bfree, st.f_bavail,
           st.f_files, st.f_ffree, st.f_namelen);

    if (st.f_bsize == 0 || st.f_blocks == 0) {
        printf("%s: invalid block geometry\n", path);
        status = 1;
    }
    if (st.f_bfree > st.f_blocks || st.f_bavail > st.f_blocks) {
        printf("%s: inconsistent free block counters\n", path);
        status = 1;
    }
    if (st.f_files && st.f_ffree > st.f_files) {
        printf("%s: inconsistent free inode counters\n", path);
        status = 1;
    }

    if (st.f_type == 0xEF53) {
        print_ext2_check();
    }

    if (status == 0)
        printf("%s: looks plausible\n", path);
    return status;
}

int main(int argc, char** argv)
{
    int status = 0;

    if (argc == 1)
        return check_path("/");

    for (int i = 1; i < argc; i++) {
        if (check_path(argv[i]) != 0)
            status = 1;
    }

    return status;
}
