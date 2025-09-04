/* kernel/lib/kprintf.c - Version corrigee pour ARM32 */
#include <kernel/types.h>
#include <kernel/uart.h>
#include <kernel/stdarg.h>
#include <kernel/kprintf.h>


/* Fonctions externes supposees existantes */
extern void putchar_kernel(char c);
//extern int kprintf(const char *format, ...);

/* Variable globale de debug */
int DEBUG = 0;

/* Fonctions externes supposees existantes */
extern void putchar_kernel(char c);

/* Fonctions utilitaires internes */
static int itoa_local(long val, char *str) {
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

static int utoa_local(unsigned long val, char *str, int base) {
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

static int ptoa_local(void *ptr, char *str) {
    unsigned long addr = (unsigned long)ptr;
    str[0] = '0';
    str[1] = 'x';
    int len = utoa_local(addr, str + 2, 16);
    return len + 2;
}

/* Fonction pour gerer les largeurs de champ */
static void print_padding(char pad_char, int width) {
    for (int i = 0; i < width; i++) {
        putchar_kernel(pad_char);
    }
}

/* Fonction principale kvprintf */
int kvprintf(const char *format, va_list args) {
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
                    int len = itoa_local(val, temp);
                    
                    if (!left_align && width > len) {
                        print_padding(zero_pad ? '0' : ' ', width - len);
                        count += width - len;
                    }
                    
                    for (int i = 0; i < len; i++) {
                        putchar_kernel(temp[i]);
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
                    int len = utoa_local(val, temp, 10);
                    
                    if (!left_align && width > len) {
                        print_padding(zero_pad ? '0' : ' ', width - len);
                        count += width - len;
                    }
                    
                    for (int i = 0; i < len; i++) {
                        putchar_kernel(temp[i]);
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
                    int len = utoa_local(val, temp, 16);
                    
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
                        putchar_kernel(temp[i]);
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
                    
                    putchar_kernel(c);
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
                        putchar_kernel(s[i]);
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
                    int len = ptoa_local(ptr, temp);
                    
                    for (int i = 0; i < len; i++) {
                        putchar_kernel(temp[i]);
                        count++;
                    }
                    break;
                }
                
                case '%': {
                    putchar_kernel('%');
                    count++;
                    break;
                }
                
                default:
                    putchar_kernel('%');
                    putchar_kernel(*fmt);
                    count += 2;
                    break;
            }
        } else {
            putchar_kernel(*fmt);
            count++;
        }
        fmt++;
    }
    
    return count;
}

/* Fonction principale kprintf */
int kprintf(const char *format, ...) {
    va_list args;
    va_start(args, format);

       if (!format) {
        uart_puts("(null format)");
        return 0;
    }
    
    /* Buffer temporaire pour assembler la chaine */
    static char safe_buffer[1024];
    unsigned int buf_pos = 0;
    const char* p = format;
    
    while (*p && buf_pos < (sizeof(safe_buffer) - 1)) {
        /* Filtrer les caracteres non-ASCII des la source */
        if ((unsigned char)*p > 127) {
            if (buf_pos < sizeof(safe_buffer) - 1) {
                safe_buffer[buf_pos++] = '?';
            }
        } else {
            safe_buffer[buf_pos++] = *p;
        }
        p++;
    }
    
    safe_buffer[buf_pos] = '\0'; 

    int result = kvprintf(safe_buffer, args);
    va_end(args);
    return result;
}

/* Fonctions de gestion du debug */
void set_debug(int enable) {
    DEBUG = enable;
}

int get_debug(void) {
    return DEBUG;
}

/* Fonction de test pour kprintf */
void kprintf_test(void) {
    kprintf("=== TEST KPRINTF eTENDU ===\n");
    
    /* Test des formats de base */
    kprintf("Entier: %d\n", 42);
    kprintf("Entier negatif: %d\n", -42);
    kprintf("Unsigned: %u\n", 3000000000U);
    kprintf("Hex minuscule: %x\n", 255);
    kprintf("Hex majuscule: %X\n", 255);
    kprintf("Caractere: %c\n", 'A');
    kprintf("String: %s\n", "Hello, kernel!");
    kprintf("Pointeur: %p\n", (void*)0x40080000);
    
    /* Test des formats longs */
    kprintf("Long: %ld\n", 1234567890L);
    kprintf("Long unsigned: %lu\n", 4000000000UL);
    kprintf("Long hex: %x\n", 0xDEADBEEF);
    
    /* Test des largeurs */
    kprintf("Largeur 10: '%10d'\n", 42);
    kprintf("Largeur 10 aligne gauche: '%-10d'\n", 42);
    kprintf("Padding zero: '%08d'\n", 42);
    kprintf("String largeur: '%15s'\n", "test");
    
    /* Test du debug */
    set_debug(1);
    KDEBUG("Message de debug test\n");
    KINFO("Message d'info\n");
    KWARN("Message d'avertissement\n");
    KERROR("Message d'erreur\n");
    set_debug(0);
    
    kprintf("=== FIN TEST KPRINTF ===\n");
}
