#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static int parse_octal_mode(const char *s, mode_t *out)
{
    unsigned value = 0;
    int digits = 0;

    if (!s || !*s || !out)
        return -1;

    while (*s) {
        if (*s < '0' || *s > '7')
            return -1;
        value = (value << 3) + (unsigned)(*s - '0');
        if (value > 07777)
            return -1;
        digits++;
        s++;
    }

    if (digits < 3 || digits > 4)
        return -1;

    *out = (mode_t)value;
    return 0;
}

static int parse_symbolic_mode(const char *s, mode_t old_mode, mode_t *out)
{
    unsigned who = 0;
    unsigned perms = 0;
    char op;

    if (!s || !*s || !out)
        return -1;

    while (*s == 'u' || *s == 'g' || *s == 'o' || *s == 'a') {
        if (*s == 'u' || *s == 'a') who |= 0700;
        if (*s == 'g' || *s == 'a') who |= 0070;
        if (*s == 'o' || *s == 'a') who |= 0007;
        s++;
    }

    if (who == 0)
        who = 0777;

    op = *s++;
    if (op != '+' && op != '-' && op != '=')
        return -1;

    while (*s) {
        if (*s == 'r') perms |= 0444;
        else if (*s == 'w') perms |= 0222;
        else if (*s == 'x') perms |= 0111;
        else return -1;
        s++;
    }

    perms &= who;

    if (op == '+')
        *out = old_mode | perms;
    else if (op == '-')
        *out = old_mode & ~perms;
    else
        *out = (old_mode & ~who) | perms;

    *out &= 07777;
    return 0;
}

static int parse_mode_for_path(const char *spec, const char *path, mode_t *out)
{
    struct stat st;

    if (parse_octal_mode(spec, out) == 0)
        return 0;

    if (stat(path, &st) < 0)
        return -1;

    return parse_symbolic_mode(spec, st.st_mode & 07777, out);
}

int main(int argc, char **argv)
{
    int status = 0;

    if (argc < 3) {
        printf("Usage: chmod MODE FILE...\n");
        return 1;
    }

    for (int i = 2; i < argc; i++) {
        mode_t mode;

        if (parse_mode_for_path(argv[1], argv[i], &mode) < 0) {
            printf("chmod: invalid mode '%s' or cannot stat '%s'\n", argv[1], argv[i]);
            status = 1;
            continue;
        }

        errno = 0;
        if (chmod(argv[i], mode) < 0) {
            printf("chmod: cannot change mode of '%s' (errno=%d)\n", argv[i], errno);
            status = 1;
        }
    }

    return status;
}
