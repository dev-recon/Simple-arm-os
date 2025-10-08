#include <../include/string.h>
#include <../include/stdio.h>

size_t strlen(const char* str) {
    const char* s = str;
    if (!str) return 0;
    
    while (*s) s++;
    return s - str;
}

char* strcpy(char* dest, const char* src) { 
    char* d = dest;
    if (!dest || !src) return dest;
    
    while ((*d++ = *src++));
    return dest;
} 

int strcmp(const char* s1, const char* s2) {
    if (!s1 && !s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;
    
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

void* memset(void* ptr, int value, size_t n) {
    unsigned char* p = (unsigned char*)ptr;
    if (!ptr) return ptr;
    
    while (n--) {
        *p++ = (unsigned char)value;
    }
    return ptr;
}

void* memcpy(void* dest, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    
    if (!dest || !src) return dest;
    
    while (n--) {
        *d++ = *s++;
    }
    return dest;
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
    char* dup = malloc(len);
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