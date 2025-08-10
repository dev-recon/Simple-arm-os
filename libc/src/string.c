#include <../include/string.h>

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