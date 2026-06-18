#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int append = 0;
    int first = 1;
    int fds[16];
    int nfds = 0;
    char buf[512];
    int n;
    int status = 0;

    if (argc > 1 && strcmp(argv[1], "-a") == 0) {
        append = 1;
        first = 2;
    }

    for (int i = first; i < argc && nfds < (int)(sizeof(fds) / sizeof(fds[0])); i++) {
        int flags = O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC);
        int fd = open(argv[i], flags, 0644);
        if (fd < 0) {
            printf("tee: cannot open '%s'\n", argv[i]);
            status = 1;
            continue;
        }
        fds[nfds++] = fd;
    }

    while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        if (write(STDOUT_FILENO, buf, n) != n)
            status = 1;
        for (int i = 0; i < nfds; i++) {
            if (write(fds[i], buf, n) != n)
                status = 1;
        }
    }

    for (int i = 0; i < nfds; i++)
        close(fds[i]);

    return n < 0 ? 1 : status;
}
