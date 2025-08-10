#ifndef _STRING_H
#define _STRING_H

#include <stddef.h>

/* ========================================
 * String Manipulation Header - User Space
 * Manipulation de chaînes et mémoire
 * ======================================== */

/* ========================================
 * Manipulation de chaînes (str*)
 * ======================================== */

/* Longueur de chaîne */
size_t strlen(const char* str);
size_t strnlen(const char* str, size_t maxlen);

/* Copie de chaînes */
char* strcpy(char* dest, const char* src);
char* strncpy(char* dest, const char* src, size_t n);

/* Concaténation de chaînes */
char* strcat(char* dest, const char* src);
char* strncat(char* dest, const char* src, size_t n);

/* Comparaison de chaînes */
int strcmp(const char* s1, const char* s2);
int strncmp(const char* s1, const char* s2, size_t n);
int strcasecmp(const char* s1, const char* s2);  /* Extension */
int strncasecmp(const char* s1, const char* s2, size_t n);  /* Extension */

/* ========================================
 * Recherche dans les chaînes
 * ======================================== */

/* Recherche de caractère */
char* strchr(const char* str, int c);
char* strrchr(const char* str, int c);

/* Recherche de sous-chaîne */
char* strstr(const char* haystack, const char* needle);

/* Recherche avec jeu de caractères */
size_t strspn(const char* str, const char* accept);
size_t strcspn(const char* str, const char* reject);
char* strpbrk(const char* str, const char* accept);

/* ========================================
 * Tokenisation
 * ======================================== */

char* strtok(char* str, const char* delim);
char* strtok_r(char* str, const char* delim, char** saveptr);  /* Thread-safe */

/* ========================================
 * Duplication et transformation
 * ======================================== */

char* strdup(const char* str);        /* Extension POSIX */
char* strndup(const char* str, size_t n);  /* Extension POSIX */

/* ========================================
 * Manipulation de mémoire (mem*)
 * ======================================== */

/* Copie de mémoire */
void* memcpy(void* dest, const void* src, size_t n);
void* memmove(void* dest, const void* src, size_t n);

/* Remplissage de mémoire */
void* memset(void* ptr, int value, size_t n);
void* memchr(const void* ptr, int value, size_t n);

/* Comparaison de mémoire */
int memcmp(const void* ptr1, const void* ptr2, size_t n);

/* ========================================
 * Gestion d'erreurs
 * ======================================== */

/* Convertir errno en chaîne */
char* strerror(int errnum);

/* ========================================
 * Extensions utiles
 * ======================================== */

/* Copie sécurisée avec taille de destination */
size_t strlcpy(char* dest, const char* src, size_t size);
size_t strlcat(char* dest, const char* src, size_t size);

/* Initialisation sécurisée */
void* memzero(void* ptr, size_t n);  /* Alias pour clarté */

/* Test de chaîne vide */
int str_is_empty(const char* str);

/* ========================================
 * Macros utilitaires
 * ======================================== */

/* Sécurité : vérifier si pointeur valide */
#define STR_SAFE(str) ((str) ? (str) : "")

/* Comparaison avec NULL safety */
#define STR_EQUAL(a, b) (strcmp(STR_SAFE(a), STR_SAFE(b)) == 0)

/* ========================================
 * Constantes d'erreur
 * ======================================== */

/* Codes d'erreur pour certaines fonctions étendues */
#define EINVAL_STR  -1
#define ENOMEM_STR  -2
#define ERANGE_STR  -3

#endif /* _STRING_H */