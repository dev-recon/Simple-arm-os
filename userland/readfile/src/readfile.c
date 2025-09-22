#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    int version = 33 ;

    printf("Hello from userspace version %d!\n", version);
    printf("My PID: %d\n", getpid());

    const char* path = "/readme.txt";
        
    int fd = open(path , 0, 0);
    if(fd>0)
    {
        char buf[520] ;
        char line[51] ;
            
        printf("Got file descriptor FD = %d\n", fd);

        if(read(fd, buf, 512 ))
        {
            printf("managed to read buffer from file %c\n", buf[0] );
            for(int i = 0; i < 10 ; i++)
            {
                for( int j = 0 ; j < 50 ; j++)
                {
                    line[j] = buf[j + 50*i];
                    //printf("%c", line[j] );
                }
                line[50] = '\0';
                printf("%s\n", line);
            }
        }

        close(fd);
    }

    exit(version);
}