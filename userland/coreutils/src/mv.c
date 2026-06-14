#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define BUF_SIZE 512

static int copy_and_delete(const char *src_path, const char *dst_path)
{
    int src = open(src_path, O_RDONLY, 0);
    if (src < 0) { printf("mv: cannot open '%s'\n", src_path); return 1; }

    int dst = open(dst_path, O_CREAT | O_WRONLY, 0644);
    if (dst < 0) {
        printf("mv: cannot create '%s'\n", dst_path);
        close(src);
        return 1;
    }

    char buf[BUF_SIZE];
    int n;
    while ((n = read(src, buf, BUF_SIZE)) > 0) {
        if (write(dst, buf, n) != n) {
            printf("mv: write error\n");
            close(src); close(dst);
            return 1;
        }
    }
    close(src);
    close(dst);

    if (n < 0) { printf("mv: read error\n"); return 1; }
    if (unlink(src_path) < 0) { printf("mv: cannot remove '%s'\n", src_path); return 1; }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: mv <src> <dst>\n");
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

    /* Essayer rename() en premier (atomique, pas de copie) */
    if (rename(argv[1], dst_path) == 0)
        return 0;

    /* Fallback : copie + suppression */
    return copy_and_delete(argv[1], dst_path);
}
