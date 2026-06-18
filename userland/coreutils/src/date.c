#include <stdio.h>
#include <time.h>

int main(int argc, char **argv)
{
    time_t now;
    struct tm *tm;
    char buf[64];

    (void)argv;
    if (argc > 1) {
        printf("date: setting date is not supported\n");
        return 1;
    }

    now = time(NULL);
    tm = localtime(&now);
    if (!tm) {
        printf("date: cannot read time\n");
        return 1;
    }

    if (strftime(buf, sizeof(buf), "%a %b %d %H:%M:%S UTC %Y", tm) == 0)
        return 1;
    printf("%s\n", buf);
    return 0;
}
