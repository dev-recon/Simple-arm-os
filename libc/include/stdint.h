#ifndef _STDINT_H
#define _STDINT_H

/* ========================================
 * Standard Definitions Header - User Space
 * Pour programmes utilisateur ARM 32-bit
 * ======================================== */

/* Types entiers exacts */
typedef signed char        int8_t;
typedef unsigned char      uint8_t;
typedef short              int16_t;
typedef unsigned short     uint16_t;
typedef int                int32_t;
typedef unsigned int       uint32_t;
typedef long long          int64_t;
typedef unsigned long long uint64_t;

/* Types entiers rapides (au moins N bits) */
typedef int8_t             int_fast8_t;
typedef uint8_t            uint_fast8_t;
typedef int16_t            int_fast16_t;
typedef uint16_t           uint_fast16_t;
typedef int32_t            int_fast32_t;
typedef uint32_t           uint_fast32_t;
typedef int64_t            int_fast64_t;
typedef uint64_t           uint_fast64_t;

/* Types entiers les plus petits (au moins N bits) */
typedef int8_t             int_least8_t;
typedef uint8_t            uint_least8_t;
typedef int16_t            int_least16_t;
typedef uint16_t           uint_least16_t;
typedef int32_t            int_least32_t;
typedef uint32_t           uint_least32_t;
typedef int64_t            int_least64_t;
typedef uint64_t           uint_least64_t;

/* Types pour pointeurs (ARMv7 = 32-bit) */
typedef int32_t            intptr_t;     /* Utilisé dans sbrk() */
typedef uint32_t           uintptr_t;

/* Type entier maximum */
typedef int64_t            intmax_t;
typedef uint64_t           uintmax_t;

/* Limites des types exacts */
#define INT8_MIN           (-128)
#define INT8_MAX           (127)
#define UINT8_MAX          (255U)

#define INT16_MIN          (-32768)
#define INT16_MAX          (32767)
#define UINT16_MAX         (65535U)

#define INT32_MIN          (-2147483648)
#define INT32_MAX          (2147483647)
#define UINT32_MAX         (4294967295U)

#define INT64_MIN          (-9223372036854775808LL)
#define INT64_MAX          (9223372036854775807LL)
#define UINT64_MAX         (18446744073709551615ULL)

/* Limites des types pointeurs */
//#define INTPTR_MIN         INT32_MIN
//#define INTPTR_MAX         INT32_MAX
//#define UINTPTR_MAX        UINT32_MAX

/* Limites des types maximum */
#define INTMAX_MIN         INT64_MIN
#define INTMAX_MAX         INT64_MAX
#define UINTMAX_MAX        UINT64_MAX

/* Macros pour les constantes */
#define INT8_C(c)          c
#define INT16_C(c)         c
#define INT32_C(c)         c
#define INT64_C(c)         c ## LL

#define UINT8_C(c)         c ## U
#define UINT16_C(c)        c ## U
#define UINT32_C(c)        c ## U
#define UINT64_C(c)        c ## ULL

#define INTMAX_C(c)        c ## LL
#define UINTMAX_C(c)       c ## ULL

#endif /* _STDINT_H */