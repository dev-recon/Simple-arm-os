#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    int version = 22 ;
    
     int child_pid = fork();
    if (child_pid == 0) {
        printf("Child process running!\n");
        exit(42);
    } else {
        printf("Parent created child PID %d\n", child_pid);
    } 
    
    exit(version);
}