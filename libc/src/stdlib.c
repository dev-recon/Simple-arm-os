#include <../include/stdarg.h>
#include <../include/stddef.h>
#include <../include/unistd.h>
#include <../include/errno.h>
#include <../include/stdio.h>

char* getcwd(char *buf, size_t size) {
    char* result_buf;
    int syscall_result;
    
    /* Si buf est NULL, allouer automatiquement */
    if (buf == NULL) {
        if (size == 0) {
            size = 256;  /* Taille par défaut */
        }
        result_buf = malloc(size);
        if (!result_buf) {
            errno = ENOMEM;
            return NULL;
        }
    } else {
        result_buf = buf;
    }
    
    /* Appeler votre syscall */
    syscall_result = _getcwd(result_buf, size);
    
    if (syscall_result < 0) {
        /* Erreur - errno déjà défini par le syscall */
        if (buf == NULL) {
            free(result_buf);  /* Libérer si on avait alloué */
        }
        return NULL;
    }
    
    /* Succès - retourner le buffer */
    return result_buf;
}