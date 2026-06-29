/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/ls.c
 * Layer: Userland / core utility
 * Description: POSIX-like command-line utility for ArmOS.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include "arm_os_abi.h"

#define BUF_SIZE 4096
#define LS_MAX_SIMPLE_ENTRIES 128
#define LS_SIMPLE_NAME_LEN 80
#define LS_SIMPLE_COL_WIDTH 18
#define LS_MAX_USERS 16
#define LS_USER_NAME_LEN 32

struct dirent_raw {
    uint32_t d_ino;
    uint32_t d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
};

struct simple_entry {
    char name[LS_SIMPLE_NAME_LEN];
    int is_dir;
};

struct user_entry {
    unsigned uid;
    unsigned gid;
    char name[LS_USER_NAME_LEN];
};

static struct user_entry users[LS_MAX_USERS];
static int user_count = 0;
static int users_loaded = 0;

static void load_users(void)
{
    FILE *f;
    char line[256];

    if (users_loaded)
        return;
    users_loaded = 1;

    f = fopen("/etc/passwd", "r");
    if (!f)
        return;

    while (user_count < LS_MAX_USERS && fgets(line, sizeof(line), f)) {
        char *name = strtok(line, ":");
        char *passwd = strtok(NULL, ":");
        char *uid_s = strtok(NULL, ":");
        char *gid_s = strtok(NULL, ":");

        (void)passwd;
        if (!name || !uid_s || !gid_s)
            continue;

        users[user_count].uid = (unsigned)strtoul(uid_s, NULL, 10);
        users[user_count].gid = (unsigned)strtoul(gid_s, NULL, 10);
        strncpy(users[user_count].name, name, sizeof(users[user_count].name) - 1);
        users[user_count].name[sizeof(users[user_count].name) - 1] = '\0';
        user_count++;
    }

    fclose(f);
}

static const char *name_for_uid(unsigned uid, char *fallback, size_t fallback_size)
{
    load_users();
    for (int i = 0; i < user_count; i++) {
        if (users[i].uid == uid)
            return users[i].name;
    }

    snprintf(fallback, fallback_size, "%u", uid);
    return fallback;
}

static const char *name_for_gid(unsigned gid, char *fallback, size_t fallback_size)
{
    load_users();
    for (int i = 0; i < user_count; i++) {
        if (users[i].gid == gid)
            return users[i].name;
    }

    snprintf(fallback, fallback_size, "%u", gid);
    return fallback;
}

static void perm_string(mode_t mode, char *out)
{
    out[0]  = S_ISDIR(mode) ? 'd' :
              S_ISLNK(mode) ? 'l' :
              S_ISCHR(mode) ? 'c' :
              S_ISBLK(mode) ? 'b' : '-';
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
    static const char *mon[12] = {
        "Jan","Feb","Mar","Apr","May","Jun",
        "Jul","Aug","Sep","Oct","Nov","Dec"
    };
    static const int mdays[12] = {31,28,31,30,31,30,31,31,30,31,30,31};

    ts /= 60;
    uint32_t min  = ts % 60; ts /= 60;
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
    int m = 0;
    for (m = 0; m < 12; m++) {
        int md = mdays[m] + (m == 1 && leap ? 1 : 0);
        if ((int)days < md) break;
        days -= (uint32_t)md;
    }
    sprintf(out, "%s %2u %02u:%02u", mon[m], days + 1, hour, min);
}

static void print_long(const char *name, struct stat *st, const char *link_target)
{
    char perms[11];
    char tstr[16];
    char user_fallback[12];
    char group_fallback[12];
    const char *user;
    const char *group;

    perm_string(st->st_mode, perms);
    format_time((uint32_t)st->st_mtime, tstr);
    user = name_for_uid((unsigned)st->st_uid, user_fallback, sizeof(user_fallback));
    group = name_for_gid((unsigned)st->st_gid, group_fallback, sizeof(group_fallback));
    int nl = S_ISDIR(st->st_mode) ? 2 : 1;
    if (S_ISLNK(st->st_mode) && link_target)
        printf("%s %d %-8s %-8s %8u %s %s -> %s\n",
               perms, nl, user, group, (uint32_t)st->st_size, tstr, name, link_target);
    else if (S_ISDIR(st->st_mode))
        printf("%s %d %-8s %-8s %8u %s \033[1;34m%s\033[0m\n",
               perms, nl, user, group, (uint32_t)st->st_size, tstr, name);
    else
        printf("%s %d %-8s %-8s %8u %s %s\n",
               perms, nl, user, group, (uint32_t)st->st_size, tstr, name);
}

static void print_long_path(const char *display_name, const char *path)
{
    struct stat st;
    char target[512];
    char *link_target = NULL;
    int n;

    if (lstat(path, &st) < 0) {
        printf("?????????? ? ?        ?               ?            %s\n", display_name);
        return;
    }

    if (S_ISLNK(st.st_mode)) {
        n = readlink(path, target, sizeof(target) - 1);
        if (n >= 0) {
            target[n] = '\0';
            link_target = target;
        }
    }

    print_long(display_name, &st, link_target);
}

static void print_simple_entries(struct simple_entry *entries, int count)
{
    int col = 0;

    for (int i = 0; i < count; i++) {
        int len = strlen(entries[i].name);
        int pad = LS_SIMPLE_COL_WIDTH - len;

        if (entries[i].is_dir)
            printf("\033[1;34m%s\033[0m", entries[i].name);
        else
            printf("%s", entries[i].name);

        if (i == count - 1) {
            printf("\n");
            break;
        }

        if (++col >= 4) {
            printf("\n");
            col = 0;
        } else {
            if (pad < 2)
                pad = 2;
            while (pad-- > 0)
                printf(" ");
        }
    }

    if (count == 0)
        printf("\n");
}

static int ls_dir(const char *path, int long_fmt, int show_all)
{
    char *buf = malloc(BUF_SIZE);
    struct simple_entry *entries = NULL;
    int entry_count = 0;
    if (!buf) return 1;

    if (!long_fmt) {
        entries = malloc(sizeof(struct simple_entry) * LS_MAX_SIMPLE_ENTRIES);
        if (!entries) {
            free(buf);
            return 1;
        }
    }

    int fd = open(path, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) {
        printf("ls: cannot open directory '%s'\n", path);
        free(entries);
        free(buf);
        return 1;
    }

    ssize_t n;
    while ((n = getdents(fd, buf, BUF_SIZE)) > 0) {
        char *ptr = buf;
        while (ptr < buf + n) {
            struct dirent_raw *e = (struct dirent_raw *)ptr;
            if (e->d_reclen == 0) break;

            if ((!show_all && e->d_name[0] == '.') || e->d_ino == 0) {
                ptr += e->d_reclen;
                continue;
            }

            if (long_fmt) {
                char fullpath[512];
                int plen = strlen(path);
                memcpy(fullpath, path, (size_t)plen);
                if (plen > 0 && fullpath[plen - 1] != '/') fullpath[plen++] = '/';
                strcpy(fullpath + plen, e->d_name);

                print_long_path(e->d_name, fullpath);
            } else {
                if (entry_count < LS_MAX_SIMPLE_ENTRIES) {
                    strncpy(entries[entry_count].name, e->d_name, LS_SIMPLE_NAME_LEN - 1);
                    entries[entry_count].name[LS_SIMPLE_NAME_LEN - 1] = '\0';
                    entries[entry_count].is_dir = (e->d_type == 4);
                    entry_count++;
                }
            }
            ptr += e->d_reclen;
        }
    }

    close(fd);

    if (!long_fmt)
        print_simple_entries(entries, entry_count);

    free(entries);
    free(buf);
    return n < 0 ? 1 : 0;
}

static int ls_file(const char *path, int long_fmt)
{
    if (long_fmt) {
        struct stat st;
        if (lstat(path, &st) < 0) {
            printf("ls: cannot stat '%s'\n", path);
            return 1;
        }
        print_long_path(path, path);
    } else {
        printf("%s\n", path);
    }
    return 0;
}

int main(int argc, char **argv)
{
    int long_fmt = 0;
    int show_all = 0;
    int npath = 0;
    const char *paths[64];

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] != '\0') {
            for (int j = 1; argv[i][j]; j++) {
                if (argv[i][j] == 'l') {
                    long_fmt = 1;
                } else if (argv[i][j] == 'a') {
                    show_all = 1;
                } else {
                    printf("ls: invalid option -- '%c'\n", argv[i][j]);
                    return 1;
                }
            }
        } else if (npath < 64) {
            paths[npath++] = argv[i];
        }
    }

    if (npath == 0) {
        paths[0] = ".";
        npath = 1;
    }

    int status = 0;
    int print_header = (npath > 1);

    for (int i = 0; i < npath; i++) {
        struct stat st;
        int stat_result;

        if (long_fmt)
            stat_result = lstat(paths[i], &st);
        else
            stat_result = stat(paths[i], &st);

        if (stat_result < 0) {
            printf("ls: cannot access '%s'\n", paths[i]);
            status = 1;
            continue;
        }

        if (long_fmt && S_ISLNK(st.st_mode)) {
            if (ls_file(paths[i], long_fmt) != 0)
                status = 1;
        } else if (S_ISDIR(st.st_mode)) {
            if (print_header)
                printf("%s:\n", paths[i]);
            if (ls_dir(paths[i], long_fmt, show_all) != 0)
                status = 1;
            if (print_header && i < npath - 1)
                printf("\n");
        } else {
            if (ls_file(paths[i], long_fmt) != 0)
                status = 1;
        }
    }

    return status;
}
