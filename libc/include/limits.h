/* userspace/libc/include/limits.h */
#ifndef _LIMITS_H
#define _LIMITS_H

/* Limites des caractères */
#define CHAR_BIT    8
#define SCHAR_MIN   (-128)
#define SCHAR_MAX   127
#define UCHAR_MAX   255

#ifdef __CHAR_UNSIGNED__
#define CHAR_MIN    0
#define CHAR_MAX    UCHAR_MAX
#else
#define CHAR_MIN    SCHAR_MIN
#define CHAR_MAX    SCHAR_MAX
#endif

/* Limites des short */
#define SHRT_MIN    (-32768)
#define SHRT_MAX    32767
#define USHRT_MAX   65535

/* Limites des int (32-bit ARM) */
#define INT_MIN     (-2147483647 - 1)
#define INT_MAX     2147483647
#define UINT_MAX    4294967295U

/* Limites des long (32-bit sur ARM32) */
#define LONG_MIN    (-2147483647L - 1L)
#define LONG_MAX    2147483647L
#define ULONG_MAX   4294967295UL

/* Limites des long long (64-bit) */
#define LLONG_MIN   (-9223372036854775807LL - 1LL)
#define LLONG_MAX   9223372036854775807LL
#define ULLONG_MAX  18446744073709551615ULL

/* Nombre de bits dans un pointeur */
#define PTR_BIT     32

/* Taille maximale d'un chemin */
#ifndef PATH_MAX
#define PATH_MAX    4096
#endif

/* Nombre maximal de fichiers ouverts */
#ifndef OPEN_MAX
#define OPEN_MAX    256
#endif

/* Taille maximale d'un nom de fichier */
#ifndef NAME_MAX
#define NAME_MAX    255
#endif

/* Autres limites POSIX */
#define ARG_MAX     131072
#define CHILD_MAX   999
#define LINK_MAX    127
#define MAX_CANON   255
#define MAX_INPUT   255
#define PIPE_BUF    4096

/* MB (multibyte) */
#define MB_LEN_MAX  4

#endif /* _LIMITS_H */