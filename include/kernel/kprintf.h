/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/kprintf.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

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
int kprintf(const char *format, ...) __attribute__((format(printf, 1, 2)));
int kvprintf(const char *format, va_list args);
size_t kmsg_read(char* out, size_t max);
void set_debug(int enable);
int get_debug(void);
void kprintf_test(void);
void kboot_statusf(const char* status, const char* format, ...) __attribute__((format(printf, 2, 3)));

/* Niveaux de log runtime. Le boot normal garde WARN/ERROR + KBOOT. */
#define KLOG_ERROR 0
#define KLOG_WARN  1
#define KLOG_INFO  2
#define KLOG_DEBUG 3

extern int DEBUG;
extern int kernel_log_level;

#define KBOOT_COLOR_RESET "\033[0m"
#define KBOOT_COLOR_OK    "\033[1;32m"
#define KBOOT_COLOR_WARN  "\033[1;33m"
#define KBOOT_COLOR_FAIL  "\033[1;31m"
#define KBOOT_COLOR_INFO  "\033[1;36m"

#define KBOOT_STATUS_OK   KBOOT_COLOR_OK   "[ OK ]"   KBOOT_COLOR_RESET
#define KBOOT_STATUS_WARN KBOOT_COLOR_WARN "[WARN]"   KBOOT_COLOR_RESET
#define KBOOT_STATUS_FAIL KBOOT_COLOR_FAIL "[FAIL]"   KBOOT_COLOR_RESET
#define KBOOT_STATUS_INFO KBOOT_COLOR_INFO "[INFO]"   KBOOT_COLOR_RESET

#define KBOOT(fmt, ...) kprintf(fmt, ##__VA_ARGS__)
#define KBOOT_OK(label)   kprintf("%-56s " KBOOT_STATUS_OK "\n", label)
#define KBOOT_WARN(label) kprintf("%-56s " KBOOT_STATUS_WARN "\n", label)
#define KBOOT_FAIL(label) kprintf("%-56s " KBOOT_STATUS_FAIL "\n", label)
#define KBOOT_OKF(fmt, ...)   kboot_statusf(KBOOT_STATUS_OK, fmt, ##__VA_ARGS__)
#define KBOOT_WARNF(fmt, ...) kboot_statusf(KBOOT_STATUS_WARN, fmt, ##__VA_ARGS__)
#define KBOOT_FAILF(fmt, ...) kboot_statusf(KBOOT_STATUS_FAIL, fmt, ##__VA_ARGS__)

/*
 * Fonctions de convenance avec prefixes
 */
int kdebug(const char *format, ...) __attribute__((format(printf, 1, 2)));  /* [DEBUG] ... */
int kinfo(const char *format, ...) __attribute__((format(printf, 1, 2)));    /* [INFO] ... */
int kerror(const char *format, ...) __attribute__((format(printf, 1, 2)));;   /* [ERROR] ... */
int kwarn(const char *format, ...) __attribute__((format(printf, 1, 2)));    /* [WARN] ... */

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
    if (DEBUG || kernel_log_level >= KLOG_DEBUG) { \
        kprintf("[DEBUG] %s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    } \
} while(0)

#define KINFO(fmt, ...) do { \
    if (kernel_log_level >= KLOG_INFO) { \
        kprintf("[INFO] " fmt, ##__VA_ARGS__); \
    } \
} while(0)
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
