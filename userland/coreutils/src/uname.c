#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    int all = argc > 1 && strcmp(argv[1], "-a") == 0;

    if (argc > 1 && !all) {
        printf("usage: uname [-a]\n");
        return 1;
    }

    if (all)
        printf("ArmOS armos 0.1 armv7l ARM Cortex-A15\n");
    else
        printf("ArmOS\n");

    return 0;
}
