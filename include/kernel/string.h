/* include/kernel/string.h */
#ifndef _KERNEL_STRING_H
#define _KERNEL_STRING_H

#include <kernel/types.h>
#include <kernel/spinlock.h>

/* Memory functions */
void* memset(void* dest, int val, size_t len);
void* memcpy(void* dest, const void* src, size_t len);
int memcmp(const void* s1, const void* s2, size_t n);

/* String functions */
size_t strlen(const char* str);
int strcmp(const char* s1, const char* s2);
int strncmp(const char* s1, const char* s2, size_t n);
char* strcpy(char* dest, const char* src);
char* strncpy(char* dest, const char* src, size_t n);
char* strdup(const char* str);
char* strchr(const char* s, int c);
char* strtok(char* str, const char* delim);
char* strstr(const char* haystack, const char* needle);
char* strrchr(const char* s, int c);
int snprintf(char* str, size_t size, const char* format, ...);

/* Character functions */
char tolower(char c);
char toupper(char c);
int isalpha(int c);
int isdigit(int c);
int isalnum(int c);
int isspace(int c);

char* strcat(char* dest, const char* src);
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
char* strncat(char* dest, const char* src, size_t n);

/* Spinlock functions */
//void init_spinlock(spinlock_t* lock);
//void spin_lock(spinlock_t* lock);
//void spin_unlock(spinlock_t* lock);

#endif /* _KERNEL_STRING_H */