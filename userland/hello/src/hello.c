#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    int version = 11 ;
    
    printf("******************************************************\n");
    printf("*************** HELLO FROM USER SPACE ****************\n");
    printf("*************** This process is going to fork() ******\n");
    printf("******************************************************\n");

    int child_pid = fork();
    if (child_pid == 0) {
        printf("                 ************ Child process running!\n");
        printf("                 ************ Will be exiting with value %d!\n", version);
        exit(version);
    } else {

        int status = 0;
        printf("Cool thing happened in user space\n");
        printf("Speaking from Parent %d\n", getpid());
        printf("Parent created child PID %d\n", child_pid);
        printf("Waiting for my child process\n");
        printf("Taking a while ......\n");
        printf("Will be exiting soon with status code %d ......\n", version+1);

        int waited_pid = waitpid(child_pid, &status, 0);
        printf("Parent waked up waited_pid %d, son status = %d\n", waited_pid, status);

        exit(version+1);
    } 

}