/*
 * TinyCC native ArmOS smoke test.
 *
 * This source is staged into the test filesystem so it can be compiled from
 * inside mash using /usr/bin/tcc, the ArmOS wrapper around /opt/tcc/bin/tcc.
 */

#include <stdio.h>

int main(int argc, char **argv)
{
    int i;

    printf("hello from native TinyCC on ArmOS\n");
    printf("argc=%d\n", argc);
    for (i = 0; i < argc; i++)
        printf("argv[%d]=%s\n", i, argv[i]);

    return 42;
}
