#include <stdio.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    for (char **p = environ; p && *p; p++)
        printf("%s\n", *p);

    return 0;
}
