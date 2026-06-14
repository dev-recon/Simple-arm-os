#include <stdio.h>
#include <unistd.h>

int main(void)
{
    char cwd[256];

    if (!getcwd(cwd, sizeof(cwd))) {
        printf("pwd: getcwd failed\n");
        return 1;
    }

    printf("%s\n", cwd);
    return 0;
}
