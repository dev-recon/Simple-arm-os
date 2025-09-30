#ifndef _STDIO_H
#define _STDIO_H

#include <stddef.h>
#include <stdarg.h>

/* ========================================
 * Standard I/O Header - User Space
 * Entrées/sorties, formatage, fichiers
 * ======================================== */

/* ========================================
 * Types et structures
 * ======================================== */

/* Type pour les positions dans les fichiers */
typedef long fpos_t;
typedef int  off_t;

/* Structure de fichier (opaque pour l'utilisateur) */
typedef struct _FILE {
    int fd;           /* File descriptor */
    int flags;        /* État du fichier */
    char* buffer;     /* Buffer d'I/O */
    size_t bufsize;   /* Taille du buffer */
    size_t bufpos;    /* Position dans le buffer */
    int error;        /* Flag d'erreur */
    int eof;          /* Flag end-of-file */
} FILE;

/* ========================================
 * Constantes
 * ======================================== */

/* File descriptors standard */
#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

/* Taille du buffer par défaut */
#define BUFSIZ 1024

/* Codes d'erreur EOF */
#define EOF (-1)

/* Modes de buffering */
#define _IOFBF 0    /* Full buffering */
#define _IOLBF 1    /* Line buffering */
#define _IONBF 2    /* No buffering */

/* Nombre maximum de fichiers ouverts */
#define FOPEN_MAX 16

/* Longueur maximum d'un nom de fichier */
#define FILENAME_MAX 256

/* Taille du nom de fichier temporaire */
#define L_tmpnam 256

/* Nombre maximum de fichiers temporaires */
#define TMP_MAX 1024

/* ========================================
 * Variables globales
 * ======================================== */

/* Fichiers standard */
extern FILE* stdin;
extern FILE* stdout;
extern FILE* stderr;

/* ========================================
 * Fonctions de formatage
 * ======================================== */

/* Sortie formatée */
int printf(const char* format, ...);
int fprintf(FILE* stream, const char* format, ...);
int sprintf(char* str, const char* format, ...);
int snprintf(char* str, size_t size, const char* format, ...);

/* Versions avec va_list */
int vprintf(const char* format, va_list args);
int vfprintf(FILE* stream, const char* format, va_list args);
int vsprintf(char* str, const char* format, va_list args);
int vsnprintf(char* str, size_t size, const char* format, va_list args);

/* Entrée formatée */
int scanf(const char* format, ...);
int fscanf(FILE* stream, const char* format, ...);
int sscanf(const char* str, const char* format, ...);

/* ========================================
 * I/O par caractère
 * ======================================== */

/* Sortie caractère */
int putchar(int c);
int putc(int c, FILE* stream);
int fputc(int c, FILE* stream);

/* Entrée caractère */
int getchar(void);
int getc(FILE* stream);
int fgetc(FILE* stream);
int ungetc(int c, FILE* stream);

/* ========================================
 * I/O par ligne
 * ======================================== */

/* Sortie chaîne */
int puts(const char* str);
int fputs(const char* str, FILE* stream);

/* Entrée chaîne */
char* gets(char* str);  /* Deprecated - unsafe */
char* fgets(char* str, int size, FILE* stream);

/* ========================================
 * I/O binaire
 * ======================================== */

size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream);
size_t fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream);

/* ========================================
 * Gestion de fichiers
 * ======================================== */

/* Ouverture/fermeture */
FILE* fopen(const char* pathname, const char* mode);
FILE* freopen(const char* pathname, const char* mode, FILE* stream);
int fclose(FILE* stream);

/* Flush */
int fflush(FILE* stream);

char* getcwd(char *buf, size_t size);

/* ========================================
 * Positionnement dans les fichiers
 * ======================================== */

int fseek(FILE* stream, long offset, int whence);
long ftell(FILE* stream);
void rewind(FILE* stream);

int fgetpos(FILE* stream, fpos_t* pos);
int fsetpos(FILE* stream, const fpos_t* pos);


/* ========================================
 * Gestion d'erreurs
 * ======================================== */

void clearerr(FILE* stream);
int feof(FILE* stream);
int ferror(FILE* stream);
void perror(const char* str);

/* ========================================
 * Buffering
 * ======================================== */

int setvbuf(FILE* stream, char* buffer, int mode, size_t size);
void setbuf(FILE* stream, char* buffer);

/* ========================================
 * Fichiers temporaires
 * ======================================== */

FILE* tmpfile(void);
char* tmpnam(char* str);

/* ========================================
 * Suppression de fichiers
 * ======================================== */

int remove(const char* pathname);
int rename(const char* oldpath, const char* newpath);

/* ========================================
 * Gestion mémoire
 * ======================================== */

/* Allocation/libération mémoire */
void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t count, size_t size);
void *realloc(void *ptr, size_t size);

/* Allocation alignée */
void* aligned_alloc(size_t alignment, size_t size);

#endif /* _STDIO_H */