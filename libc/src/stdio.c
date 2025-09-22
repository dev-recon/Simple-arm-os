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

/* Fonction pour gerer les largeurs de champ */
static void print_padding(char pad_char, int width) {
    for (int i = 0; i < width; i++) {
        printf_putc(pad_char);
    }
}

/* Fonction principale kvprintf */
int vprintf(const char *format, va_list args) {
    if (!format) return -1;
    
    const char *fmt = format;
    int count = 0;
    
    while (*fmt) {
        if (*fmt == '%' && *(fmt + 1)) {
            fmt++;
            
            /* Gestion des flags */
            int left_align = 0;
            int zero_pad = 0;
            //int show_sign = 0;
            //int space_prefix = 0;
            
            while (*fmt == '-' || *fmt == '0' || *fmt == '+' || *fmt == ' ') {
                if (*fmt == '-') left_align = 1;
                else if (*fmt == '0') zero_pad = 1;
                //else if (*fmt == '+') show_sign = 1;
                //else if (*fmt == ' ') space_prefix = 1;
                fmt++;
            }
            
            /* Gestion de la largeur */
            int width = 0;
            while (*fmt >= '0' && *fmt <= '9') {
                width = width * 10 + (*fmt - '0');
                fmt++;
            }
            
            /* Gestion de la precision */
            int precision = -1;
            if (*fmt == '.') {
                fmt++;
                precision = 0;
                while (*fmt >= '0' && *fmt <= '9') {
                    precision = precision * 10 + (*fmt - '0');
                    fmt++;
                }
            }
            
            /* Gestion des modificateurs de longueur */
            int is_long = 0;
            int is_long_long = 0;
            
            if (*fmt == 'l') {
                is_long = 1;
                fmt++;
                if (*fmt == 'l') {
                    is_long_long = 1;
                    fmt++;
                }
            } else if (*fmt == 'z') {
                is_long = 1; /* size_t = unsigned long sur ARM64 */
                fmt++;
            }
            
            /* Traitement du specificateur */
            switch (*fmt) {
                case 'd':
                case 'i': {
                    long val;
                    if (is_long || is_long_long) {
                        val = va_arg(args, long);
                    } else {
                        val = va_arg(args, int);
                    }
                    
                    char temp[32];
                    int len = itoa(val, temp);
                    
                    if (!left_align && width > len) {
                        print_padding(zero_pad ? '0' : ' ', width - len);
                        count += width - len;
                    }
                    
                    for (int i = 0; i < len; i++) {
                        printf_putc(temp[i]);
                        count++;
                    }
                    
                    if (left_align && width > len) {
                        print_padding(' ', width - len);
                        count += width - len;
                    }
                    break;
                }
                
                case 'u': {
                    unsigned long val;
                    if (is_long || is_long_long) {
                        val = va_arg(args, unsigned long);
                    } else {
                        val = va_arg(args, unsigned int);
                    }
                    
                    char temp[32];
                    int len = utoa(val, temp, 10);
                    
                    if (!left_align && width > len) {
                        print_padding(zero_pad ? '0' : ' ', width - len);
                        count += width - len;
                    }
                    
                    for (int i = 0; i < len; i++) {
                        printf_putc(temp[i]);
                        count++;
                    }
                    
                    if (left_align && width > len) {
                        print_padding(' ', width - len);
                        count += width - len;
                    }
                    break;
                }
                
                case 'x':
                case 'X': {
                    unsigned long val;
                    if (is_long || is_long_long) {
                        val = va_arg(args, unsigned long);
                    } else {
                        val = va_arg(args, unsigned int);
                    }
                    
                    char temp[32];
                    int len = utoa(val, temp, 16);
                    
                    /* Convertir en majuscules si X */
                    if (*fmt == 'X') {
                        for (int i = 0; i < len; i++) {
                            if (temp[i] >= 'a' && temp[i] <= 'f') {
                                temp[i] = temp[i] - 'a' + 'A';
                            }
                        }
                    }
                    
                    if (!left_align && width > len) {
                        print_padding(zero_pad ? '0' : ' ', width - len);
                        count += width - len;
                    }
                    
                    for (int i = 0; i < len; i++) {
                        printf_putc(temp[i]);
                        count++;
                    }
                    
                    if (left_align && width > len) {
                        print_padding(' ', width - len);
                        count += width - len;
                    }
                    break;
                }
                
                case 'c': {
                    char c = (char)va_arg(args, int);
                    
                    if (!left_align && width > 1) {
                        print_padding(' ', width - 1);
                        count += width - 1;
                    }
                    
                    printf_putc(c);
                    count++;
                    
                    if (left_align && width > 1) {
                        print_padding(' ', width - 1);
                        count += width - 1;
                    }
                    break;
                }
                
                case 's': {
                    char *s = va_arg(args, char*);
                    if (!s) s = "(null)";
                    
                    int str_len = 0;
                    char *temp = s;
                    while (*temp++) str_len++; /* strlen */
                    
                    if (precision >= 0 && str_len > precision) {
                        str_len = precision;
                    }
                    
                    if (!left_align && width > str_len) {
                        print_padding(' ', width - str_len);
                        count += width - str_len;
                    }
                    
                    for (int i = 0; i < str_len; i++) {
                        printf_putc(s[i]);
                        count++;
                    }
                    
                    if (left_align && width > str_len) {
                        print_padding(' ', width - str_len);
                        count += width - str_len;
                    }
                    break;
                }
                
                case 'p': {
                    void *ptr = va_arg(args, void*);
                    char temp[32];
                    int len = ptoa(ptr, temp);
                    
                    for (int i = 0; i < len; i++) {
                        printf_putc(temp[i]);
                        count++;
                    }
                    break;
                }
                
                case '%': {
                    printf_putc('%');
                    count++;
                    break;
                }
                
                default:
                    printf_putc('%');
                    printf_putc(*fmt);
                    count += 2;
                    break;
            }
        } else {
            printf_putc(*fmt);
            count++;
        }
        fmt++;
    }
    
    return count;
}

int vprintf2(const char* format, va_list args) {
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