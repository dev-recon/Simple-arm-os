/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: libc/src/string.c
 * Layer: Userland / legacy libc
 * Description: Legacy freestanding C runtime support kept for compatibility.
 */

#include <../include/string.h>
#include <../include/stdio.h>
#include <../include/errno.h>
#include <../include/limits.h>

static inline int is_space(char c) {
    return (c == ' ' || c == '\t' || c == '\n' || 
            c == '\r' || c == '\v' || c == '\f');
}

static inline int is_digit(char c) {
    return (c >= '0' && c <= '9');
}

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

long strtol(const char* str, char** endptr, int base) {
    long result = 0;
    int sign = 1;
    const char* start = str;
    
    if (!str) {
        if (endptr) *endptr = NULL;
        return 0;
    }
    
    /* Ignorer les espaces */
    while (is_space(*str)) str++;
    
    /* Signe */
    if (*str == '-') {
        sign = -1;
        str++;
    } else if (*str == '+') {
        str++;
    }
    
    /* Détection automatique de la base */
    if (base == 0) {
        if (*str == '0') {
            if (str[1] == 'x' || str[1] == 'X') {
                base = 16;
                str += 2;
            } else {
                base = 8;
                str++;
            }
        } else {
            base = 10;
        }
    } else if (base == 16 && *str == '0' && 
               (str[1] == 'x' || str[1] == 'X')) {
        str += 2;
    }
    
    /* Conversion */
    while (*str) {
        int digit;
        
        if (is_digit(*str)) {
            digit = *str - '0';
        } else if (*str >= 'a' && *str <= 'z') {
            digit = *str - 'a' + 10;
        } else if (*str >= 'A' && *str <= 'Z') {
            digit = *str - 'A' + 10;
        } else {
            break;
        }
        
        if (digit >= base) break;
        
        /* Vérifier le débordement */
        if (result > (LONG_MAX - digit) / base) {
            errno = ERANGE;
            if (endptr) *endptr = (char*)str;
            return (sign == 1) ? LONG_MAX : LONG_MIN;
        }
        
        result = result * base + digit;
        str++;
    }
    
    if (endptr) {
        *endptr = (char*)((str == start) ? start : str);
    }
    
    return sign * result;
}

/* atoi en termes de strtol */
int atoi(const char* str) {
    return (int)strtol(str, NULL, 10);
}