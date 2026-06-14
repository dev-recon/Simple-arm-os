#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: sleep <seconds>\n");
        return 1;
    }

    unsigned int seconds = (unsigned int)atoi(argv[1]);
    sleep(seconds);
    return 0;
}
