#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PATH_BUF 512

static int parse_uint(const char *s, unsigned *out)
{
    unsigned value = 0;

    if (!s || !*s || !out)
        return -1;

    while (*s) {
        if (*s < '0' || *s > '9')
            return -1;
        value = value * 10u + (unsigned)(*s - '0');
        s++;
    }

    *out = value;
    return 0;
}

static int parse_owner_group(const char *spec, uid_t *owner, gid_t *group)
{
    char owner_buf[16];
    char group_buf[16];
    int owner_len = 0;
    int group_len = 0;
    int seen_colon = 0;
    unsigned value;

    if (!spec || !*spec || !owner || !group)
        return -1;

    *owner = (uid_t)-1;
    *group = (gid_t)-1;

    for (const char *p = spec; *p; p++) {
        if (*p == ':') {
            if (seen_colon)
                return -1;
            seen_colon = 1;
            continue;
        }

        if (!seen_colon) {
            if (owner_len >= (int)sizeof(owner_buf) - 1)
                return -1;
            owner_buf[owner_len++] = *p;
        } else {
            if (group_len >= (int)sizeof(group_buf) - 1)
                return -1;
            group_buf[group_len++] = *p;
        }
    }

    owner_buf[owner_len] = '\0';
    group_buf[group_len] = '\0';

    if (owner_len > 0) {
        if (parse_uint(owner_buf, &value) < 0)
            return -1;
        *owner = (uid_t)value;
    }

    if (seen_colon && group_len > 0) {
        if (parse_uint(group_buf, &value) < 0)
            return -1;
        *group = (gid_t)value;
    }

    if (*owner == (uid_t)-1 && *group == (gid_t)-1)
        return -1;

    return 0;
}

static void join_path(char* out, size_t out_size, const char* dir, const char* name)
{
    size_t len = strlen(dir);
    snprintf(out, out_size, "%s%s%s", dir, (len > 0 && dir[len - 1] == '/') ? "" : "/", name);
}

static int chown_path(const char* path, uid_t owner, gid_t group, int recursive)
{
    struct stat st;
    int status = 0;

    errno = 0;
    if (chown(path, owner, group) < 0) {
        printf("chown: cannot change owner of '%s' (errno=%d)\n", path, errno);
        status = 1;
    }

    if (!recursive || lstat(path, &st) < 0 || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
        return status;

    int fd = open(path, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0)
        return 1;

    char buf[1024];
    int n;
    while ((n = getdents(fd, buf, sizeof(buf))) > 0) {
        int pos = 0;
        while (pos < n) {
            struct linux_dirent* entry = (struct linux_dirent*)(buf + pos);
            char child[PATH_BUF];

            if (entry->d_reclen == 0)
                break;
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                join_path(child, sizeof(child), path, entry->d_name);
                if (chown_path(child, owner, group, recursive) != 0)
                    status = 1;
            }
            pos += entry->d_reclen;
        }
    }

    if (n < 0)
        status = 1;
    close(fd);
    return status;
}

int main(int argc, char **argv)
{
    uid_t owner;
    gid_t group;
    int status = 0;
    int recursive = 0;
    int spec_index = 1;

    if (argc > 1 && strcmp(argv[1], "-R") == 0) {
        recursive = 1;
        spec_index = 2;
    }

    if (argc < spec_index + 2) {
        printf("Usage: chown [-R] OWNER[:GROUP] FILE...\n");
        return 1;
    }

    if (parse_owner_group(argv[spec_index], &owner, &group) < 0) {
        printf("chown: invalid owner '%s'\n", argv[spec_index]);
        return 1;
    }

    for (int i = spec_index + 1; i < argc; i++) {
        if (chown_path(argv[i], owner, group, recursive) != 0)
            status = 1;
    }

    return status;
}
