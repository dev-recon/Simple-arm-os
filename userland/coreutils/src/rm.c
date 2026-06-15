#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char **argv)
{
    int force = 0;
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
            } else {
                printf("rm: unsupported option '-%c'\n", *opt);
                printf("Usage: rm [-f] <file>...\n");
                return 1;
            }
        }
    }

    if (first_path >= argc)
        return force ? 0 : (printf("Usage: rm [-f] <file>...\n"), 1);

    int status = 0;
    for (int i = first_path; i < argc; i++) {
        errno = 0;
        if (unlink(argv[i]) < 0) {
            if (force && errno == ENOENT)
                continue;
            printf("rm: cannot remove '%s'\n", argv[i]);
            status = 1;
        }
    }
    return status;
}
