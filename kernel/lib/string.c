/* kernel/lib/string.c */
#include <kernel/string.h>
#include <kernel/memory.h>
#include <kernel/stdarg.h>

void* memset(void* dest, int val, size_t len)
{
    unsigned char* d = (unsigned char*)dest;
    size_t i; /* Declaration GNU89 */
    
    for (i = 0; i < len; i++) {
        d[i] = (unsigned char)val;
    }
    
    return dest;
}

void* memcpy(void* dest, const void* src, size_t len)
{
    const unsigned char* s = (const unsigned char*)src;
    unsigned char* d = (unsigned char*)dest;
    size_t i; /* Declaration GNU89 */
    
    for (i = 0; i < len; i++) {
        d[i] = s[i];
    }
    
    return dest;
}

int memcmp(const void* s1, const void* s2, size_t n)
{
    const unsigned char* p1 = (const unsigned char*)s1;
    const unsigned char* p2 = (const unsigned char*)s2;
    size_t i; /* Declaration GNU89 */
    
    for (i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }
    
    return 0;
}

size_t strlen(const char* str)
{
    size_t len = 0;
    while (str[len]) {
        len++;
    }
    return len;
}

int strcmp(const char* s1, const char* s2)
{
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

int strncmp(const char* s1, const char* s2, size_t n)
{
    size_t i; /* Declaration GNU89 */
    
    for (i = 0; i < n; i++) {
        if (s1[i] != s2[i] || s1[i] == 0) {
            return s1[i] - s2[i];
        }
    }
    return 0;
}

char* strcpy(char* dest, const char* src)
{
    char* d = dest;
    while ((*dest++ = *src++));
    return d;
}

char* strncpy(char* dest, const char* src, size_t n)
{
    size_t i; /* Declaration GNU89 */
    
    for (i = 0; i < n && src[i] != 0; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = 0;
    }
    return dest;
}

char* strdup(const char* str)
{
    size_t len = strlen(str) + 1;
    char* dup = kmalloc(len);
    if (dup) {
        memcpy(dup, str, len);
    }
    return dup;
}

char* strchr(const char* s, int c)
{
    while (*s) {
        if (*s == c) {
            return (char*)s;
        }
        s++;
    }
    return (c == '\0') ? (char*)s : NULL;
}

char* strtok(char* str, const char* delim)
{
    static char* last_token = NULL;
    char* token_start;
    
    if (str != NULL) {
        last_token = str;
    } else {
        str = last_token;
    }
    
    if (str == NULL) {
        return NULL;
    }
    
    /* Skip leading delimiters */
    while (*str && strchr(delim, *str)) {
        str++;
    }
    
    if (*str == '\0') {
        last_token = NULL;
        return NULL;
    }
    
    token_start = str;
    
    /* Find end of token */
    while (*str && !strchr(delim, *str)) {
        str++;
    }
    
    if (*str) {
        *str = '\0';
        last_token = str + 1;
    } else {
        last_token = NULL;
    }
    
    return token_start;
}

void init_spinlock2(spinlock_t* lock)
{
    lock->locked = 0;
}

void spin_lock2(spinlock_t* lock)
{
    while (__sync_lock_test_and_set(&lock->locked, 1)) {
        /* Spin */
    }
}

void spin_unlock2(spinlock_t* lock)
{
    __sync_lock_release(&lock->locked);
}


char tolower(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}

char toupper(char c)
{
    if (c >= 'a' && c <= 'z') {
        return c - ('a' - 'A');
    }
    return c;
}

int isalpha(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

int isdigit(int c)
{
    return c >= '0' && c <= '9';
}

int isalnum(int c)
{
    return isalpha(c) || isdigit(c);
}

int isspace(int c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

char* strstr(const char* haystack, const char* needle)
{
    size_t needle_len = strlen(needle);
    size_t i, j;
    
    if (needle_len == 0) return (char*)haystack;
    
    for (i = 0; haystack[i]; i++) {
        for (j = 0; j < needle_len && haystack[i + j] == needle[j]; j++);
        if (j == needle_len) return (char*)&haystack[i];
    }
    return NULL;
}

char* strrchr(const char* s, int c)
{
    char* last = NULL;
    while (*s) {
        if (*s == c) last = (char*)s;
        s++;
    }
    return (c == '\0') ? (char*)s : last;
}


/* Ajouter a kernel/lib/string.c */

static int itoa_helper(int value, char* str, int base)
{
    char* ptr = str;
    char* ptr1 = str;
    char tmp_char;
    int tmp_value;
    int len = 0;
    
    /* Handle 0 explicitly */
    if (value == 0) {
        *ptr++ = '0';
        *ptr = '\0';
        return 1;
    }
    
    /* Handle negative numbers for base 10 */
    int is_negative = 0;
    if (value < 0 && base == 10) {
        is_negative = 1;
        value = -value;
    }
    
    /* Process individual digits */
    while (value != 0) {
        tmp_value = value;
        value /= base;
        *ptr++ = "0123456789abcdef"[tmp_value - value * base];
        len++;
    }
    
    /* Add negative sign */
    if (is_negative) {
        *ptr++ = '-';
        len++;
    }
    
    *ptr-- = '\0';
    
    /* Reverse string */
    while (ptr1 < ptr) {
        tmp_char = *ptr;
        *ptr-- = *ptr1;
        *ptr1++ = tmp_char;
    }
    
    return len;
}

static int utoa_helper(unsigned int value, char* str, int base)
{
    char* ptr = str;
    char* ptr1 = str;
    char tmp_char;
    unsigned int tmp_value;
    int len = 0;
    
    /* Handle 0 explicitly */
    if (value == 0) {
        *ptr++ = '0';
        *ptr = '\0';
        return 1;
    }
    
    /* Process individual digits */
    while (value != 0) {
        tmp_value = value;
        value /= base;
        *ptr++ = "0123456789abcdef"[tmp_value - value * base];
        len++;
    }
    
    *ptr-- = '\0';
    
    /* Reverse string */
    while (ptr1 < ptr) {
        tmp_char = *ptr;
        *ptr-- = *ptr1;
        *ptr1++ = tmp_char;
    }
    
    return len;
}

int snprintf(char* str, size_t size, const char* format, ...)
{
    va_list args;
    const char* p;
    char* out;
    char* out_end;
    int written = 0;
    int temp_len;
    char temp_buf[32];
    const char* s;
    int d;
    unsigned int u;
    char c;
    
    if (!str || size == 0) return 0;
    
    va_start(args, format);
    
    out = str;
    out_end = str + size - 1; /* Reserve space for null terminator */
    
    for (p = format; *p && out < out_end; p++) {
        if (*p != '%') {
            *out++ = *p;
            written++;
            continue;
        }
        
        p++; /* Skip '%' */
        
        /* Handle format specifiers */
        switch (*p) {
            case 'c':
                c = (char)va_arg(args, int);
                if (out < out_end) {
                    *out++ = c;
                    written++;
                }
                break;
                
            case 's':
                s = va_arg(args, const char*);
                if (!s) s = "(null)";
                while (*s && out < out_end) {
                    *out++ = *s++;
                    written++;
                }
                break;
                
            case 'd':
            case 'i':
                d = va_arg(args, int);
                temp_len = itoa_helper(d, temp_buf, 10);
                {
                    int i; /* Declaration GNU89 */
                    for (i = 0; i < temp_len && out < out_end; i++) {
                        *out++ = temp_buf[i];
                        written++;
                    }
                }
                break;
                
            case 'u':
                u = va_arg(args, unsigned int);
                temp_len = utoa_helper(u, temp_buf, 10);
                {
                    int i; /* Declaration GNU89 */
                    for (i = 0; i < temp_len && out < out_end; i++) {
                        *out++ = temp_buf[i];
                        written++;
                    }
                }
                break;
                
            case 'x':
                u = va_arg(args, unsigned int);
                temp_len = utoa_helper(u, temp_buf, 16);
                {
                    int i; /* Declaration GNU89 */
                    for (i = 0; i < temp_len && out < out_end; i++) {
                        *out++ = temp_buf[i];
                        written++;
                    }
                }
                break;
                
            case 'X':
                u = va_arg(args, unsigned int);
                temp_len = utoa_helper(u, temp_buf, 16);
                {
                    int i; /* Declaration GNU89 */
                    for (i = 0; i < temp_len && out < out_end; i++) {
                        char ch = temp_buf[i];
                        *out++ = (ch >= 'a' && ch <= 'f') ? ch - 'a' + 'A' : ch;
                        written++;
                    }
                }
                break;
                
            case '%':
                if (out < out_end) {
                    *out++ = '%';
                    written++;
                }
                break;
                
            case '.':
                /* Handle precision specifier like %.*s */
                if (*(p + 1) == '*' && *(p + 2) == 's') {
                    int max_len = va_arg(args, int);
                    s = va_arg(args, const char*);
                    if (!s) s = "(null)";
                    {
                        int count = 0;
                        while (*s && count < max_len && out < out_end) {
                            *out++ = *s++;
                            written++;
                            count++;
                        }
                    }
                    p += 2; /* Skip '*s' */
                } else {
                    /* Simple . handling - just copy the character */
                    if (out < out_end) {
                        *out++ = '.';
                        written++;
                    }
                }
                break;
                
            default:
                /* Unknown format specifier, just copy it */
                if (out < out_end) {
                    *out++ = '%';
                    written++;
                }
                if (out < out_end) {
                    *out++ = *p;
                    written++;
                }
                break;
        }
    }
    
    *out = '\0';
    va_end(args);
    
    return written;
}


/**
 * strcat - Concatene src a la fin de dest
 * @dest: Chaine de destination (doit avoir assez d'espace)
 * @src: Chaine source a ajouter
 * 
 * Retourne: Pointeur vers dest
 * 
 * ATTENTION: dest doit avoir assez d'espace pour dest + src + '\0'
 * Cette fonction est dangereuse (buffer overflow possible)
 */
char* strcat(char* dest, const char* src)
{
    char* original_dest = dest;
    
    if (!dest || !src) {
        return dest;
    }
    
    /* Aller a la fin de dest */
    while (*dest != '\0') {
        dest++;
    }
    
    /* Copier src a la fin de dest */
    while (*src != '\0') {
        *dest = *src;
        dest++;
        src++;
    }
    
    /* Terminer par null */
    *dest = '\0';
    
    return original_dest;
}

/* ========================================================================
 * FONCTION SeCURISeE POSIX : strncat()
 * ======================================================================== */

/**
 * strncat - Concatene au maximum n caracteres de src a dest
 * @dest: Chaine de destination
 * @src: Chaine source
 * @n: Nombre maximum de caracteres a copier
 * 
 * Retourne: Pointeur vers dest
 * 
 * Plus s-re que strcat() car limite le nombre de caracteres
 */
char* strncat(char* dest, const char* src, size_t n)
{
    char* original_dest = dest;
    
    if (!dest || !src || n == 0) {
        return dest;
    }
    
    /* Aller a la fin de dest */
    while (*dest != '\0') {
        dest++;
    }
    
    /* Copier au maximum n caracteres de src */
    while (*src != '\0' && n > 0) {
        *dest = *src;
        dest++;
        src++;
        n--;
    }
    
    /* Toujours terminer par null */
    *dest = '\0';
    
    return original_dest;
}
