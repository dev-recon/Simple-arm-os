#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define WHICH_PATH_MAX 512

static int has_slash(const char *s)
{
    return s && strchr(s, '/') != NULL;
}

static int is_executable_file(const char *path)
{
    struct stat st;

    if (stat(path, &st) < 0)
        return 0;
    if (!S_ISREG(st.st_mode))
        return 0;

    return access(path, X_OK) == 0;
}

static int build_path(const char *dir, int dir_len, const char *name,
                      char *out, int out_size)
{
    int name_len = (int)strlen(name);
    int pos = 0;

    if (!dir || dir_len == 0) {
        if (name_len + 2 > out_size)
            return -1;
        out[pos++] = '.';
    } else {
        if (dir_len + 1 >= out_size)
            return -1;
        memcpy(out, dir, (size_t)dir_len);
        pos = dir_len;
    }

    if (pos > 0 && out[pos - 1] != '/') {
        if (pos + 1 >= out_size)
            return -1;
        out[pos++] = '/';
    }

    if (pos + name_len >= out_size)
        return -1;

    memcpy(out + pos, name, (size_t)name_len + 1);
    return 0;
}

static int find_command(const char *name, char *out, int out_size)
{
    const char *path;
    const char *entry;

    if (!name || !*name)
        return -1;

    if (has_slash(name)) {
        if ((int)strlen(name) >= out_size)
            return -1;
        strcpy(out, name);
        return is_executable_file(out) ? 0 : -1;
    }

    path = getenv("PATH");
    if (!path || !*path)
        path = "/usr/bin:/bin";

    entry = path;
    while (1) {
        const char *next = strchr(entry, ':');
        int len = next ? (int)(next - entry) : (int)strlen(entry);

        if (build_path(entry, len, name, out, out_size) == 0 &&
            is_executable_file(out))
            return 0;

        if (!next)
            break;
        entry = next + 1;
    }

    return -1;
}

int main(int argc, char **argv)
{
    int status = 0;
    char path[WHICH_PATH_MAX];

    if (argc < 2) {
        printf("usage: which COMMAND...\n");
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (find_command(argv[i], path, sizeof(path)) == 0) {
            printf("%s\n", path);
        } else {
            status = 1;
        }
    }

    return status;
}
