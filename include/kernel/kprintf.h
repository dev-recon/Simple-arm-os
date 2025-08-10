/* include/kernel/kprintf.h - Header pour kprintf kernel */
#ifndef _KERNEL_KPRINTF_H
#define _KERNEL_KPRINTF_H

#include <kernel/types.h>
#include <kernel/stdarg.h>

/*
 * Fonction printf pour le kernel
 * Support des formats : %d %i %u %x %X %p %s %c %%
 * Support des flags : - 0 + (espace)
 * Support de la largeur : %10d %-10s
 * Support de la precision : %.10s
 * Support du modificateur : %ld
 */
/* Fonctions principales */
int kprintf(const char *format, ...);
int kvprintf(const char *format, va_list args);
void set_debug(int enable);
int get_debug(void);
void kprintf_test(void);

/*
 * Fonctions de convenance avec prefixes
 */
int kdebug(const char *format, ...);   /* [DEBUG] ... */
int kinfo(const char *format, ...);    /* [INFO] ... */
int kerror(const char *format, ...);   /* [ERROR] ... */
int kwarn(const char *format, ...);    /* [WARN] ... */

/*
 * Macros utiles pour debug
 */
#define KPRINTF_HERE() kprintf("HERE: %s:%d in %s()\n", __FILE__, __LINE__, __func__)

#define KPRINTF_VAR_INT(var) kprintf(#var " = %d\n", var)
#define KPRINTF_VAR_HEX(var) kprintf(#var " = 0x%x\n", var)
#define KPRINTF_VAR_PTR(var) kprintf(#var " = %p\n", var)
#define KPRINTF_VAR_STR(var) kprintf(#var " = \"%s\"\n", var)

/* Macros de debug */
#define KDEBUG(fmt, ...) do { \
    int DEBUG=1; \
    if (DEBUG) { \
        kprintf("[DEBUG] %s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    } \
} while(0)

#define KINFO(fmt, ...) kprintf("[INFO] " fmt, ##__VA_ARGS__)
#define KWARN(fmt, ...) kprintf("[WARN] " fmt, ##__VA_ARGS__)
#define KERROR(fmt, ...) kprintf("[ERROR] " fmt, ##__VA_ARGS__)

/* Macro pour afficher un dump hex de memoire */
#define KPRINTF_HEX_DUMP(ptr, size) do { \
    uint8_t *_p = (uint8_t*)(ptr); \
    kprintf("Hex dump of %p (%d bytes):\n", ptr, size); \
    for (int _i = 0; _i < (size); _i++) { \
        if (_i % 16 == 0) kprintf("%08x: ", (uint32_t)(_p + _i)); \
        kprintf("%02x ", _p[_i]); \
        if (_i % 16 == 15) kprintf("\n"); \
    } \
    if ((size) % 16 != 0) kprintf("\n"); \
} while(0)

/*
 * Macros conditionnelles pour debug (activees/desactivees a la compilation)
 */
#ifdef DEBUG_KERNEL
    #define KDEBUG_PRINTF(fmt, ...) kdebug(fmt, ##__VA_ARGS__)
    #define KDEBUG_HERE() KPRINTF_HERE()
    #define KDEBUG_VAR_INT(var) KPRINTF_VAR_INT(var)
    #define KDEBUG_VAR_HEX(var) KPRINTF_VAR_HEX(var)
#else
    #define KDEBUG_PRINTF(fmt, ...) do {} while(0)
    #define KDEBUG_HERE() do {} while(0)
    #define KDEBUG_VAR_INT(var) do {} while(0)
    #define KDEBUG_VAR_HEX(var) do {} while(0)
#endif

#endif /* _KERNEL_KPRINTF_H */