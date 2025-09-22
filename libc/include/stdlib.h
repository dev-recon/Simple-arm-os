#ifndef _STDLIB_H
#define _STDLIB_H

#include <stddef.h>

/* ========================================
 * Standard Library Header - User Space
 * Gestion mémoire, conversion, utilitaires
 * ======================================== */

/* ========================================
 * Codes de sortie standard
 * ======================================== */

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

/* ========================================
 * Limites et constantes
 * ======================================== */

#define RAND_MAX 32767

/* Nombre maximum de bytes dans un caractère multibyte */
#define MB_CUR_MAX 1

/* Taille maximum d'une variable d'environnement */
#define ENV_MAX 256

/* Définir __NORETURN si pas déjà défini */
#ifndef __NORETURN
#ifdef __GNUC__
#define __NORETURN __attribute__((noreturn))
#else
#define __NORETURN
#endif
#endif



/* ========================================
 * Contrôle de programme
 * ======================================== */

/* Terminer le programme */
void exit(int status) __NORETURN;
void _exit(int status) __NORETURN;
void abort(void) __NORETURN;

/* Enregistrer des fonctions de nettoyage */
int atexit(void (*function)(void));

/* ========================================
 * Conversion de chaînes en nombres
 * ======================================== */

/* Conversion vers entier */
int atoi(const char* str);
long atol(const char* str);
long long atoll(const char* str);

/* Conversion avancée avec détection d'erreur */
long strtol(const char* str, char** endptr, int base);
unsigned long strtoul(const char* str, char** endptr, int base);
long long strtoll(const char* str, char** endptr, int base);
unsigned long long strtoull(const char* str, char** endptr, int base);

/* Conversion vers flottant */
double atof(const char* str);
double strtod(const char* str, char** endptr);
float strtof(const char* str, char** endptr);

/* ========================================
 * Conversion de nombres en chaînes
 * ======================================== */

/* Conversion entier vers chaîne */
char* itoa(int value, char* buffer, int base);
char* ltoa(long value, char* buffer, int base);
char* utoa(unsigned int value, char* buffer, int base);

/* ========================================
 * Génération de nombres aléatoires
 * ======================================== */

int rand(void);
void srand(unsigned int seed);

/* ========================================
 * Recherche et tri
 * ======================================== */

/* Recherche binaire */
void* bsearch(const void* key, const void* base, size_t nmemb, 
              size_t size, int (*compar)(const void*, const void*));

/* Tri rapide */
void qsort(void* base, size_t nmemb, size_t size,
           int (*compar)(const void*, const void*));

/* ========================================
 * Valeur absolue
 * ======================================== */

int abs(int x);
long labs(long x);
long long llabs(long long x);

/* Division avec reste */
typedef struct { int quot, rem; } div_t;
typedef struct { long quot, rem; } ldiv_t;
typedef struct { long long quot, rem; } lldiv_t;

div_t div(int numer, int denom);
ldiv_t ldiv(long numer, long denom);
lldiv_t lldiv(long long numer, long long denom);

/* ========================================
 * Variables d'environnement
 * ======================================== */

char* getenv(const char* name);
int setenv(const char* name, const char* value, int overwrite);
int unsetenv(const char* name);

/* ========================================
 * Utilitaires système
 * ======================================== */

int system(const char* command);


#endif /* _STDLIB_H */