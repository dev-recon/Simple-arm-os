#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    int version = 22 ;

    printf("Hello from userspace version %d!\n", version);
    printf("My PID: %d\n", getpid());
    printf("Exiting for now with the value %d\n", version);

    exit(version);
}