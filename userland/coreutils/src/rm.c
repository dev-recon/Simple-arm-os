#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

#define RM_DIR_BUF_SIZE 512
#define RM_PATH_MAX     512

static int join_path(const char *dir, const char *name, char *out, int out_size)
{
    int dir_len;
    int name_len;
    int need_slash;

    if (!dir || !name || !out || out_size <= 0)
        return -1;

    dir_len = strlen(dir);
    name_len = strlen(name);
    need_slash = dir_len > 0 && dir[dir_len - 1] != '/';

    if (dir_len + need_slash + name_len + 1 > out_size)
        return -1;

    strcpy(out, dir);
    if (need_slash)
        strcat(out, "/");
    strcat(out, name);
    return 0;
}

static int is_dot_entry(const char *name)
{
    return strcmp(name, ".") == 0 || strcmp(name, "..") == 0;
}

static int remove_path(const char *path, int recursive, int force)
{
    struct stat st;

    errno = 0;
    if (stat(path, &st) < 0) {
        if (force && errno == ENOENT)
            return 0;
        if (!force)
            printf("rm: cannot remove '%s'\n", path);
        return -1;
    }

    if (!S_ISDIR(st.st_mode)) {
        if (unlink(path) < 0) {
            if (force && errno == ENOENT)
                return 0;
            if (!force)
                printf("rm: cannot remove '%s'\n", path);
            return -1;
        }
        return 0;
    }

    if (!recursive) {
        if (!force)
            printf("rm: cannot remove '%s': is a directory\n", path);
        return -1;
    }

    int fd = open(path, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) {
        if (!force)
            printf("rm: cannot open directory '%s'\n", path);
        return -1;
    }

    char buf[RM_DIR_BUF_SIZE];
    int status = 0;
    int n;
    while ((n = getdents(fd, buf, sizeof(buf))) > 0) {
        int pos = 0;

        while (pos < n) {
            struct linux_dirent *entry = (struct linux_dirent *)(buf + pos);
            char child[RM_PATH_MAX];

            if (entry->d_reclen == 0)
                break;

            if (!is_dot_entry(entry->d_name)) {
                if (join_path(path, entry->d_name, child, sizeof(child)) < 0) {
                    if (!force)
                        printf("rm: path too long: '%s/%s'\n", path, entry->d_name);
                    status = -1;
                } else if (remove_path(child, recursive, force) < 0) {
                    status = -1;
                }
            }

            pos += entry->d_reclen;
        }
    }
    close(fd);

    if (n < 0) {
        if (!force)
            printf("rm: cannot read directory '%s'\n", path);
        status = -1;
    }

    if (rmdir(path) < 0) {
        if (!force)
            printf("rm: cannot remove directory '%s'\n", path);
        status = -1;
    }

    return status;
}

int main(int argc, char **argv)
{
    int force = 0;
    int recursive = 0;
    int first_path = 1;

    for (; first_path < argc; first_path++) {
        if (strcmp(argv[first_path], "--") == 0) {
            first_path++;
            break;
        }
        if (argv[first_path][0] != '-' || argv[first_path][1] == '\0')
            break;

        for (const char *opt = argv[first_path] + 1; *opt; opt++) {
            if (*opt == 'f') {
                force = 1;
            } else if (*opt == 'r' || *opt == 'R') {
                recursive = 1;
            } else {
                printf("rm: unsupported option '-%c'\n", *opt);
                printf("Usage: rm [-f] [-r] <file>...\n");
                return 1;
            }
        }
    }

    if (first_path >= argc)
        return force ? 0 : (printf("Usage: rm [-f] [-r] <file>...\n"), 1);

    int status = 0;
    for (int i = first_path; i < argc; i++) {
        if (remove_path(argv[i], recursive, force) < 0)
            status = 1;
    }
    return status;
}
