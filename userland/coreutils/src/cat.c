#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

static int cat_fd(int fd)
{
    char buffer[512];
    int n;

    while ((n = read(fd, buffer, sizeof(buffer))) > 0) {
        if (write(STDOUT_FILENO, buffer, n) != n)
            return 1;
    }

    return n < 0 ? 1 : 0;
}

int main(int argc, char** argv)
{
    int i;
    int status = 0;

    if (argc < 2)
        return cat_fd(STDIN_FILENO);

    for (i = 1; i < argc; i++) {
        int fd = open(argv[i], O_RDONLY, 0);
        if (fd < 0) {
            printf("cat: cannot open %s\n", argv[i]);
            status = 1;
            continue;
        }

        if (cat_fd(fd) != 0)
            status = 1;
        close(fd);
    }

    return status;
}
