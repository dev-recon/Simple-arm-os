#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int print_user_name(unsigned uid)
{
    FILE *f = fopen("/etc/passwd", "r");
    char line[256];

    if (!f)
        return -1;

    while (fgets(line, sizeof(line), f)) {
        char *name = strtok(line, ":");
        char *x = strtok(NULL, ":");
        char *uid_s = strtok(NULL, ":");
        (void)x;
        if (name && uid_s && (unsigned)strtoul(uid_s, NULL, 10) == uid) {
            printf("%s\n", name);
            fclose(f);
            return 0;
        }
    }

    fclose(f);
    return -1;
}

int main(void)
{
    unsigned uid = (unsigned)getuid();

    if (print_user_name(uid) == 0)
        return 0;

    printf("%u\n", uid);
    return 0;
}
