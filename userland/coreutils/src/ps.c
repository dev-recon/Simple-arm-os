#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#define PROC_BUF_SIZE 4096

static int is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static int read_file(const char *path, char *buf, int size)
{
    int fd;
    int n;

    if (!buf || size <= 1)
        return -1;

    fd = open(path, O_RDONLY, 0);
    if (fd < 0)
        return -1;

    n = read(fd, buf, size - 1);
    close(fd);

    if (n < 0)
        return -1;

    buf[n] = '\0';
    return n;
}

static const char *parse_int(const char *p, int *out)
{
    int sign = 1;
    int value = 0;

    while (*p == ' ' || *p == '\t')
        p++;

    if (*p == '-') {
        sign = -1;
        p++;
    }

    if (!is_digit(*p))
        return NULL;

    while (is_digit(*p)) {
        value = value * 10 + (*p - '0');
        p++;
    }

    *out = value * sign;
    return p;
}

static int parse_proc_stat(const char *buf, int *pid, int *tty, char *name, int name_size)
{
    const char *p;
    const char *start;
    const char *end;
    int dummy;
    int len;

    p = parse_int(buf, pid);
    if (!p)
        return -1;

    while (*p == ' ')
        p++;
    if (*p != '(')
        return -1;

    start = ++p;
    end = start;
    while (*end && *end != ')')
        end++;
    if (*end != ')')
        return -1;

    len = (int)(end - start);
    if (len >= name_size)
        len = name_size - 1;
    memcpy(name, start, (size_t)len);
    name[len] = '\0';

    p = end + 1;
    while (*p == ' ')
        p++;
    if (*p)
        p++; /* state */

    p = parse_int(p, &dummy); /* ppid */
    if (!p) return -1;
    p = parse_int(p, &dummy); /* pgid */
    if (!p) return -1;
    p = parse_int(p, &dummy); /* sid */
    if (!p) return -1;
    p = parse_int(p, tty);
    if (!p) return -1;

    return 0;
}

static void print_tty(int tty)
{
    if (tty >= 0)
        printf("tty%d", tty);
    else
        printf("?");
}

int main(void)
{
    char *dirbuf;
    char statbuf[512];
    int fd;
    int n;

    dirbuf = malloc(PROC_BUF_SIZE);
    if (!dirbuf) {
        printf("ps: out of memory\n");
        return 1;
    }

    fd = open("/proc", O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) {
        printf("ps: cannot open /proc\n");
        free(dirbuf);
        return 1;
    }

    printf("%5s %-8s %8s %s\n", "PID", "TTY", "TIME", "CMD");

    while ((n = getdents(fd, dirbuf, PROC_BUF_SIZE)) > 0) {
        char *ptr = dirbuf;

        while (ptr < dirbuf + n) {
            struct linux_dirent *e = (struct linux_dirent *)ptr;
            char path[64];
            char name[64];
            int pid;
            int tty;

            if (e->d_reclen == 0)
                break;

            if (e->d_ino != 0 && is_digit(e->d_name[0])) {
                sprintf(path, "/proc/%s/stat", e->d_name);
                if (read_file(path, statbuf, sizeof(statbuf)) >= 0 &&
                    parse_proc_stat(statbuf, &pid, &tty, name, sizeof(name)) == 0) {
                    printf("%5d ", pid);
                    print_tty(tty);
                    printf("%*s %8s %s\n", tty >= 0 ? 4 : 7, "", "0:00.00", name);
                }
            }

            ptr += e->d_reclen;
        }
    }

    close(fd);
    free(dirbuf);
    return n < 0 ? 1 : 0;
}
