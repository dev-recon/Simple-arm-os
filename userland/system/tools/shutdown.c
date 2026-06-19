#include <stdio.h>
#include <unistd.h>

int main(void)
{
    printf("shutdown: powering off system...\n");
    sys_shutdown();
    printf("shutdown: kernel poweroff returned unexpectedly\n");
    return 1;
}
