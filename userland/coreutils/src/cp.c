#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define BUF_SIZE 512

int main(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: cp <src> <dst>\n");
        return 1;
    }

    /* Si la destination est un répertoire, construire dst/basename(src) */
    char dst_path[512];
    struct stat st;
    if (stat(argv[2], &st) == 0 && S_ISDIR(st.st_mode)) {
        const char *p = argv[1], *base = argv[1];
        for (; *p; p++) if (*p == '/') base = p + 1;
        int len = strlen(argv[2]);
        snprintf(dst_path, sizeof(dst_path), "%s%s%s",
                 argv[2], argv[2][len - 1] == '/' ? "" : "/", base);
    } else {
        snprintf(dst_path, sizeof(dst_path), "%s", argv[2]);
    }

    int src = open(argv[1], O_RDONLY, 0);
    if (src < 0) {
        printf("cp: cannot open '%s'\n", argv[1]);
        return 1;
    }

    int dst = open(dst_path, O_CREAT | O_WRONLY, 0644);
    if (dst < 0) {
        printf("cp: cannot create '%s'\n", dst_path);
        close(src);
        return 1;
    }

    char buf[BUF_SIZE];
    int n;
    while ((n = read(src, buf, BUF_SIZE)) > 0) {
        if (write(dst, buf, n) != n) {
            printf("cp: write error\n");
            close(src);
            close(dst);
            return 1;
        }
    }

    close(src);
    close(dst);
    return n < 0 ? 1 : 0;
}
