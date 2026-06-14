#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: touch <file>...\n");
        return 1;
    }

    int status = 0;
    for (int i = 1; i < argc; i++) {
        int fd = open(argv[i], O_CREAT | O_RDWR, 0644);
        if (fd < 0) {
            printf("touch: cannot create '%s'\n", argv[i]);
            status = 1;
        } else {
            close(fd);
        }
    }
    return status;
}
