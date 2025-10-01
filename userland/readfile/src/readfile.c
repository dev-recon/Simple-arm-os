#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>

void test_mkdir_rmdir() {
    /* Créer un répertoire */
    if (mkdir("/test_dir", 0755) == 0) {
        printf("Directory created successfully\n");
        
        /* Supprimer le répertoire */
/*         if (rmdir("/test_dir") == 0) {
            printf("Directory removed successfully\n");
        } else {
            printf("Failed to remove directory\n");
        }  */
    } else {
        printf("Failed to create directory\n");
    }
}

void test_unlink() {
    int fd;
    const char* path = "/test_dir/unlink.txt";
    /* Créer un fichier de test */
    fd = open(path, O_CREAT , 0644);
    printf("AFTER OPEN fd = %d for filepath = %s\n", fd, path);
    if (fd >= 0) {

        int count = write(fd, "Test file for unlink", 20);
        printf("WROTE count = %d bytes\n", count);
        close(fd);

        /* Vérifier qu'il existe */
        fd = open(path, O_RDONLY,0);
        if (fd >= 0) {
            close(fd);
            printf("File exists, now unlinking...\n");
            
            /* Supprimer le fichier */
            if (unlink(path) == 0) {
                printf("File unlinked successfully\n");
                
                /* Vérifier qu'il n'existe plus */
                fd = open(path, O_RDONLY,0);
                if (fd < 0) {
                    printf("Confirmed: file no longer exists\n");
                } else {
                    printf("ERROR: file still exists!\n");
                    close(fd);
                }
            } else {
                printf("Failed to unlink file\n");
            }
        }
    }
}


void test_chdir() {
    int fd;
    const char* path = "unlink.txt";

    // Créer un répertoire 
    if (mkdir("/test_dir", 0755) == 0) {
        printf("Directory created successfully\n");

        //char cwd[256] ;
        char *cwd = NULL;
        cwd = getcwd(NULL, 0);
      
        printf("Current Working Directory is %s, 0x%08X\n", cwd, cwd);

        int ret = chdir("/test_dir");
       
        printf("CHDIR returned with %d\n", ret);

        cwd = getcwd(NULL, 0);
      
        printf("New Current Working Directory is %s\n", cwd);

        free(cwd);

            // Créer un fichier de test 
        fd = open(path, O_CREAT , 0644);
        printf("AFTER OPEN fd = %d for filepath = %s\n", fd, path);
        if (fd >= 0) {

            int new_fd = dup2(fd, 10);
            printf("AFTER DUP NEW fd = %d for filepath = %s\n", new_fd, path);

            int count = write(new_fd, "J'aime ma fille YASMINE ...", 27);
            printf("WROTE count = %d bytes\n", count);
            close(new_fd);

            // Vérifier qu'il existe 
            fd = open(path, O_RDONLY,0);
            if (fd >= 0) {
                close(fd);
                printf("File exists, now unlinking...\n");
                
/*                 // Supprimer le fichier 
                if (unlink(path) == 0) {
                    printf("File unlinked successfully\n");
                    
                    // Vérifier qu'il n'existe plus 
                    fd = open(path, O_RDONLY,0);
                    if (fd < 0) {
                        printf("Confirmed: file no longer exists\n");
                    } else {
                        printf("ERROR: file still exists!\n");
                        close(fd);
                    }
                } else {
                    printf("Failed to unlink file\n");
                } */
            }
        } 

    } else {
        printf("Failed to create directory\n");
    }
}

int test_stat(void) {
    struct stat st;
    
    if (stat("readme.txt", &st) == 0) {
        printf("File size: %ld bytes\n", st.st_size);
        printf("Permissions: %d\n", st.st_mode & 0777);
        
        if (S_ISREG(st.st_mode)) {
            printf("Regular file\n");
        }
    }
    
    return 0;
}


int main() {
    int version = 33 ;

    printf("Hello from userspace version %d!\n", version);
    printf("My PID: %d\n", getpid());

    const char* path = "/readme.txt";
    struct stat st;
        
    int fd = open(path , 0, 0);
    char buffer[10];
    
    if (fd < 0) {
        printf("Failed to open file %s\n", path);
        exit(version);
    }

    fstat(fd, &st);
    printf("File exists, size: %ld\n", st.st_size);

    /* Lire depuis le début */
    read(fd, buffer, 5);
    buffer[5] = '\0';
    printf("Position 0-4: '%s'\n", buffer);
    
    /* Aller à la position 10 */
    off_t pos = lseek(fd, 10, SEEK_SET);
    printf("Seeked to position: %ld\n", pos);
    
    /* Lire 5 bytes depuis la position 10 */
    read(fd, buffer, 5);
    buffer[5] = '\0';
    printf("Position 10-14: '%s'\n", buffer);
    
    /* Aller à la fin du fichier */
    pos = lseek(fd, 0, SEEK_END);
    printf("File size: %ld bytes\n", pos);
    
    /* Reculer de 10 bytes */
    pos = lseek(fd, -10, SEEK_CUR);
    printf("10 bytes from end: position %ld\n", pos);

    close(fd);



    //test_mkdir_rmdir();

    //test_unlink();

    test_chdir();

    //test_stat();

    exit(version);
}