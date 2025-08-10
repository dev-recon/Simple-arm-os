#ifndef _STDDEF_H
#define _STDDEF_H

/* ========================================
 * Standard Definitions Header - User Space
 * Pour programmes utilisateur ARM 32-bit
 * ======================================== */

/* NULL pointer constant */
#ifndef NULL
#define NULL ((void*)0)
#endif

/* Boolean type (C89/C90 compatible) */
#ifndef __cplusplus
#ifndef bool
typedef enum {
    false = 0,
    true = 1
} bool;
#endif
#endif

/* ========================================
 * Types de base pour userspace
 * ======================================== */

/* Size type - pour malloc, strlen, etc. */
typedef unsigned int size_t;

/* Signed size type - pour différences, retours d'erreur */
typedef int ssize_t;

/* Type pour différences de pointeurs */
typedef int ptrdiff_t;

/* Wide character */
typedef unsigned int wchar_t;
typedef unsigned short wint_t;

/* Integer types capable de stocker des pointeurs */
typedef unsigned int uintptr_t;
typedef int intptr_t;

/* ========================================
 * Macros essentielles
 * ======================================== */

/* Offset d'un membre dans une structure */
#define offsetof(type, member) \
    ((size_t)((char*)&((type*)0)->member - (char*)0))

/* Taille d'un tableau statique */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* ========================================
 * Limites pour ARM 32-bit userspace
 * ======================================== */

#define SIZE_MAX    0xFFFFFFFFU
#define SSIZE_MAX   0x7FFFFFFF
#define SSIZE_MIN   (-SSIZE_MAX - 1)

#define PTRDIFF_MAX 0x7FFFFFFF
#define PTRDIFF_MIN (-PTRDIFF_MAX - 1)

#define UINTPTR_MAX 0xFFFFFFFFU
#define INTPTR_MAX  0x7FFFFFFF
#define INTPTR_MIN  (-INTPTR_MAX - 1)

/* ========================================
 * Attributs de compilation (si GCC)
 * ======================================== */

#ifdef __GNUC__
  #define __UNUSED    __attribute__((unused))
  #define __PACKED    __attribute__((packed))
  #define __ALIGNED(n) __attribute__((aligned(n)))
  #define __PURE      __attribute__((pure))
  #define __CONST     __attribute__((const))
  #define __NORETURN  __attribute__((noreturn))
  #define __INLINE    inline __attribute__((always_inline))
#else
  #define __UNUSED
  #define __PACKED
  #define __ALIGNED(n)
  #define __PURE
  #define __CONST
  #define __NORETURN
  #define __INLINE    inline
#endif

/* ========================================
 * Macros utilitaires pour userspace
 * ======================================== */

/* Min/Max */
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

/* Alignement */
#define ALIGN_UP(value, align) \
    (((value) + (align) - 1) & ~((align) - 1))

#define ALIGN_DOWN(value, align) \
    ((value) & ~((align) - 1))

#define IS_ALIGNED(value, align) \
    (((value) & ((align) - 1)) == 0)

/* ========================================
 * Constantes pour programmes utilisateur
 * ======================================== */

/* Alignement par défaut */
#define USERSPACE_ALIGNMENT 4

/* Limites typiques */
#define USER_PATH_MAX   256
#define USER_NAME_MAX   64
#define USER_LINE_MAX   1024

/* ========================================
 * Types pour la compatibilité
 * ======================================== */

/* Type pour les codes d'erreur */
typedef int error_t;

/* Type pour les handles/descripteurs */
typedef int handle_t;

/* Type générique pour les IDs */
typedef unsigned int id_t;

#endif /* _STDDEF_H */