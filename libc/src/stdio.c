#include <../include/stdarg.h>
#include <../include/stddef.h>
#include <../include/unistd.h>


// Buffer pour printf (évite les appels syscall trop fréquents)
static char printf_buffer[1024];
static size_t printf_buf_pos = 0;


int vprintf(const char* format, va_list args);

static int itoa(long val, char *str) {
    if (val == 0) {
        str[0] = '0';
        str[1] = '\0';
        return 1;
    }
    
    int i = 0;
    int negative = 0;
    
    if (val < 0) {
        negative = 1;
        val = -val;
    }
    
    while (val > 0) {
        str[i++] = '0' + (val % 10);
        val /= 10;
    }
    
    if (negative) {
        str[i++] = '-';
    }
    
    str[i] = '\0';
    
    /* Inverser la chaine */
    for (int j = 0; j < i / 2; j++) {
        char temp = str[j];
        str[j] = str[i - 1 - j];
        str[i - 1 - j] = temp;
    }
    
    return i;
}

static int utoa(unsigned long val, char *str, int base) {
    if (val == 0) {
        str[0] = '0';
        str[1] = '\0';
        return 1;
    }
    
    char digits[] = "0123456789abcdef";
    int i = 0;
    
    while (val > 0) {
        str[i++] = digits[val % base];
        val /= base;
    }
    
    str[i] = '\0';
    
    /* Inverser la chaine */
    for (int j = 0; j < i / 2; j++) {
        char temp = str[j];
        str[j] = str[i - 1 - j];
        str[i - 1 - j] = temp;
    }
    
    return i;
}

static int ptoa(void *ptr, char *str) {
    unsigned long addr = (unsigned long)ptr;
    str[0] = '0';
    str[1] = 'x';
    int len = utoa(addr, str + 2, 16);
    return len + 2;
}


static void printf_flush(void) {
    if (printf_buf_pos > 0) {
        write(1, printf_buffer, printf_buf_pos);
        printf_buf_pos = 0;
    }
}

static void printf_putc(char c) {
    printf_buffer[printf_buf_pos++] = c;
    
    // Flush si buffer plein ou newline
    if (printf_buf_pos >= sizeof(printf_buffer) - 1 || c == '\n') {
        printf_flush();
    }
}

// Fonction printf utilisateur
int printf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    int result = vprintf(format, args);
    
    va_end(args);
    return result;
}

int vprintf(const char* format, va_list args) {
    // Réutiliser votre code de formatage existant !
    // Mais au lieu d'écrire directement, utiliser printf_putc
    
    const char* p;
    int written = 0;
    
    for (p = format; *p; p++) {
        if (*p != '%') {
            printf_putc(*p);
            written++;
            continue;
        }
        
        p++; // Skip '%'
        
        switch (*p) {
            case 'c': {
                char c = (char)va_arg(args, int);
                printf_putc(c);
                written++;
                break;
            }
            
            case 's': {
                const char* s = va_arg(args, const char*);
                if (!s) s = "(null)";
                while (*s) {
                    printf_putc(*s++);
                    written++;
                }
                break;
            }
            
            case 'd': {
                int d = va_arg(args, int);
                char buf[32];
                int len = itoa(d, buf);
                for (int i = 0; i < len; i++) {
                    printf_putc(buf[i]);
                    written++;
                }
                break;
            }
            
            case 'x': {
                unsigned int u = va_arg(args, unsigned int);
                char buf[32];
                int len = utoa(u, buf, 16);
                for (int i = 0; i < len; i++) {
                    printf_putc(buf[i]);
                    written++;
                }
                break;
            }
            
            // Autres formats...
        }
    }
    
    printf_flush();  // S'assurer que tout est affiché
    return written;
}