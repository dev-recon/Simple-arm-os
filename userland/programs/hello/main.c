#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int main(int argc, char **argv, char **envp)
{
    FILE *f;
    struct stat st;
    char *buf;

    printf("newlib: hello argc=%d argv0=%s envp=%p\n",
           argc, argc > 0 ? argv[0] : "?", envp);

    buf = malloc(512);
    if (!buf) {
        perror("newlib: malloc");
        return 1;
    }

    strcpy(buf, "newlib malloc/string path works");
    printf("newlib: %s\n", buf);
    free(buf);

    f = fopen("/tmp/newlib-test.txt", "w");
    if (!f) {
        perror("newlib: fopen write");
        return 1;
    }
    fprintf(f, "written by newlib stdio\n");
    fclose(f);

    if (stat("/tmp/newlib-test.txt", &st) < 0) {
        perror("newlib: stat");
        return 1;
    }
    printf("newlib: stat size=%ld mode=0%o\n", (long)st.st_size, st.st_mode);

    if (rename("/tmp/newlib-test.txt", "/tmp/newlib-renamed.txt") < 0) {
        perror("newlib: rename");
        return 1;
    }

    if (remove("/tmp/newlib-renamed.txt") < 0) {
        perror("newlib: remove");
        return 1;
    }

    printf("newlib: smoke test passed\n");
    return 0;
}

