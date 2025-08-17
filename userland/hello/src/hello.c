#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    int version = 22 ;
    
    printf("******************************************************\n");
    printf("*************** HELLO FROM USER SPACE ****************\n");
    printf("*************** This process is going to fork() ******\n");
    printf("******************************************************\n");

    int child_pid = fork();
    if (child_pid == 0) {
        printf("Child process running!\n");
        exit(42);
    } else {
        printf("Parent created child PID %d\n", child_pid);
    } 
    
    exit(version);
}