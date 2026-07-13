/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/lib/kprintf.c
 * Layer: Kernel / support library
 *
 * Responsibilities:
 * - Provide freestanding helpers unavailable from libc.
 * - Keep formatting, string, math, and debug helpers deterministic.
 *
 * Notes:
 * - Must remain safe before userland and full runtime services exist.
 */

#include <kernel/types.h>
#include <kernel/uart.h>
#include <kernel/tty.h>
#include <kernel/stdarg.h>
#include <kernel/kprintf.h>
#include <kernel/spinlock.h>
#include <kernel/arch_cpu.h>


/* Console transport supplied by the active platform. */
extern void putchar_kernel(char c);

/*
 * Logging is available before the TTY subsystem and on architecture ports
 * that have not connected a persistent TTY yet.  A linked TTY driver provides
 * strong versions of these hooks once console serialization is available.
 */
__attribute__((weak)) bool tty_console_output_lock(unsigned long *flags)
{
    if (flags)
        *flags = 0;
    return false;
}

__attribute__((weak)) void tty_console_output_unlock(unsigned long flags)
{
    (void)flags;
}

/* Variable globale de debug */
int DEBUG = 0;
int kernel_log_level = KLOG_WARN;

#define KMSG_BUF_SIZE 8192
static char kmsg_buf[KMSG_BUF_SIZE];
static uint32_t kmsg_head = 0;
static uint32_t kmsg_count = 0;
static DEFINE_SPINLOCK(kmsg_lock);
static DEFINE_SPINLOCK(kprintf_lock);

static void kmsg_putc(char c)
{
    unsigned long flags;

    spin_lock_irqsave(&kmsg_lock, &flags);
    /*
     * kmsg is used precisely when the kernel is reporting faults.  If prior
     * corruption or an SMP race damages the indices, never let diagnostics
     * turn into a second kernel abort while writing the ring buffer.
     */
    if (kmsg_head >= KMSG_BUF_SIZE || kmsg_count > KMSG_BUF_SIZE) {
        kmsg_head = 0;
        kmsg_count = 0;
    }
    kmsg_buf[kmsg_head] = c;
    kmsg_head = (kmsg_head + 1) % KMSG_BUF_SIZE;
    if (kmsg_count < KMSG_BUF_SIZE)
        kmsg_count++;
    spin_unlock_irqrestore(&kmsg_lock, flags);
}

size_t kmsg_read(char* out, size_t max)
{
    unsigned long flags;
    uint32_t start;
    size_t n;

    if (!out || max == 0)
        return 0;

    spin_lock_irqsave(&kmsg_lock, &flags);
    if (kmsg_head >= KMSG_BUF_SIZE || kmsg_count > KMSG_BUF_SIZE) {
        kmsg_head = 0;
        kmsg_count = 0;
    }
    n = kmsg_count;
    if (n > max)
        n = max;

    start = (kmsg_head + KMSG_BUF_SIZE - kmsg_count) % KMSG_BUF_SIZE;
    for (size_t i = 0; i < n; i++)
        out[i] = kmsg_buf[(start + i) % KMSG_BUF_SIZE];
    spin_unlock_irqrestore(&kmsg_lock, flags);

    return n;
}

static void kprintf_emit_char(char c)
{
    if (arch_mmu_enabled())
        kmsg_putc(c);
    putchar_kernel(c);
}

#define putchar_kernel(c) kprintf_emit_char(c)

static void kprintf_emit_string(const char *s)
{
    if (!s)
        s = "(null)";
    while (*s)
        putchar_kernel(*s++);
}

static int kprintf_vlocked(const char *format, va_list args)
{
    char safe_buffer[1024];
    unsigned int buf_pos = 0;
    const char* p = format;

    if (!format) {
        kprintf_emit_string("(null format)");
        return 0;
    }

    while (*p && buf_pos < (sizeof(safe_buffer) - 1)) {
        /* Keep logs printable even when a corrupted string reaches kprintf. */
        safe_buffer[buf_pos++] = ((unsigned char)*p > 127) ? '?' : *p;
        p++;
    }

    safe_buffer[buf_pos] = '\0';
    return kvprintf(safe_buffer, args);
}

/* Fonctions utilitaires internes */
static int itoa_local(long val, char *str) {
    if (val == 0) {
        str[0] = '0';
        str[1] = '\0';
        return 1;
    }
    
    int i = 0;
    int negative = 0;
    
    if (val < 0) {
        negative = 1;
        val = -val;
    }
    
    while (val > 0) {
        str[i++] = '0' + (val % 10);
        val /= 10;
    }
    
    if (negative) {
        str[i++] = '-';
    }
    
    str[i] = '\0';
    
    /* Inverser la chaine */
    for (int j = 0; j < i / 2; j++) {
        char temp = str[j];
        str[j] = str[i - 1 - j];
        str[i - 1 - j] = temp;
    }
    
    return i;
}

static int utoa_local(unsigned long val, char *str, int base) {
    if (val == 0) {
        str[0] = '0';
        str[1] = '\0';
        return 1;
    }
    
    char digits[] = "0123456789abcdef";
    int i = 0;
    
    while (val > 0) {
        str[i++] = digits[val % base];
        val /= base;
    }
    
    str[i] = '\0';
    
    /* Inverser la chaine */
    for (int j = 0; j < i / 2; j++) {
        char temp = str[j];
        str[j] = str[i - 1 - j];
        str[i - 1 - j] = temp;
    }
    
    return i;
}

static int ptoa_local(void *ptr, char *str) {
    unsigned long addr = (unsigned long)ptr;
    str[0] = '0';
    str[1] = 'x';
    int len = utoa_local(addr, str + 2, 16);
    return len + 2;
}

/* Fonction pour gerer les largeurs de champ */
static void print_padding(char pad_char, int width) {
    for (int i = 0; i < width; i++) {
        putchar_kernel(pad_char);
    }
}

/* Fonction principale kvprintf */
int kvprintf(const char *format, va_list args) {
    if (!format) return -1;
    
    const char *fmt = format;
    int count = 0;
    
    while (*fmt) {
        if (*fmt == '%' && *(fmt + 1)) {
            fmt++;
            
            /* Gestion des flags */
            int left_align = 0;
            int zero_pad = 0;
            //int show_sign = 0;
            //int space_prefix = 0;
            
            while (*fmt == '-' || *fmt == '0' || *fmt == '+' || *fmt == ' ') {
                if (*fmt == '-') left_align = 1;
                else if (*fmt == '0') zero_pad = 1;
                //else if (*fmt == '+') show_sign = 1;
                //else if (*fmt == ' ') space_prefix = 1;
                fmt++;
            }
            
            /* Gestion de la largeur */
            int width = 0;
            while (*fmt >= '0' && *fmt <= '9') {
                width = width * 10 + (*fmt - '0');
                fmt++;
            }
            
            /* Gestion de la precision */
            int precision = -1;
            if (*fmt == '.') {
                fmt++;
                precision = 0;
                while (*fmt >= '0' && *fmt <= '9') {
                    precision = precision * 10 + (*fmt - '0');
                    fmt++;
                }
            }
            
            /* Gestion des modificateurs de longueur */
            int is_long = 0;
            int is_long_long = 0;
            
            if (*fmt == 'l') {
                is_long = 1;
                fmt++;
                if (*fmt == 'l') {
                    is_long_long = 1;
                    fmt++;
                }
            } else if (*fmt == 'z') {
                is_long = 1; /* size_t = unsigned long sur ARM64 */
                fmt++;
            }
            
            /* Traitement du specificateur */
            switch (*fmt) {
                case 'd':
                case 'i': {
                    long val;
                    if (is_long || is_long_long) {
                        val = va_arg(args, long);
                    } else {
                        val = va_arg(args, int);
                    }
                    
                    char temp[32];
                    int len = itoa_local(val, temp);
                    
                    if (!left_align && width > len) {
                        print_padding(zero_pad ? '0' : ' ', width - len);
                        count += width - len;
                    }
                    
                    for (int i = 0; i < len; i++) {
                        putchar_kernel(temp[i]);
                        count++;
                    }
                    
                    if (left_align && width > len) {
                        print_padding(' ', width - len);
                        count += width - len;
                    }
                    break;
                }
                
                case 'u': {
                    unsigned long val;
                    if (is_long || is_long_long) {
                        val = va_arg(args, unsigned long);
                    } else {
                        val = va_arg(args, unsigned int);
                    }
                    
                    char temp[32];
                    int len = utoa_local(val, temp, 10);
                    
                    if (!left_align && width > len) {
                        print_padding(zero_pad ? '0' : ' ', width - len);
                        count += width - len;
                    }
                    
                    for (int i = 0; i < len; i++) {
                        putchar_kernel(temp[i]);
                        count++;
                    }
                    
                    if (left_align && width > len) {
                        print_padding(' ', width - len);
                        count += width - len;
                    }
                    break;
                }
                
                case 'x':
                case 'X': {
                    unsigned long val;
                    if (is_long || is_long_long) {
                        val = va_arg(args, unsigned long);
                    } else {
                        val = va_arg(args, unsigned int);
                    }
                    
                    char temp[32];
                    int len = utoa_local(val, temp, 16);
                    
                    /* Convertir en majuscules si X */
                    if (*fmt == 'X') {
                        for (int i = 0; i < len; i++) {
                            if (temp[i] >= 'a' && temp[i] <= 'f') {
                                temp[i] = temp[i] - 'a' + 'A';
                            }
                        }
                    }
                    
                    if (!left_align && width > len) {
                        print_padding(zero_pad ? '0' : ' ', width - len);
                        count += width - len;
                    }
                    
                    for (int i = 0; i < len; i++) {
                        putchar_kernel(temp[i]);
                        count++;
                    }
                    
                    if (left_align && width > len) {
                        print_padding(' ', width - len);
                        count += width - len;
                    }
                    break;
                }
                
                case 'c': {
                    char c = (char)va_arg(args, int);
                    
                    if (!left_align && width > 1) {
                        print_padding(' ', width - 1);
                        count += width - 1;
                    }
                    
                    putchar_kernel(c);
                    count++;
                    
                    if (left_align && width > 1) {
                        print_padding(' ', width - 1);
                        count += width - 1;
                    }
                    break;
                }
                
                case 's': {
                    char *s = va_arg(args, char*);
                    if (!s) s = "(null)";
                    
                    int str_len = 0;
                    char *temp = s;
                    while (*temp++) str_len++; /* strlen */
                    
                    if (precision >= 0 && str_len > precision) {
                        str_len = precision;
                    }
                    
                    if (!left_align && width > str_len) {
                        print_padding(' ', width - str_len);
                        count += width - str_len;
                    }
                    
                    for (int i = 0; i < str_len; i++) {
                        putchar_kernel(s[i]);
                        count++;
                    }
                    
                    if (left_align && width > str_len) {
                        print_padding(' ', width - str_len);
                        count += width - str_len;
                    }
                    break;
                }
                
                case 'p': {
                    void *ptr = va_arg(args, void*);
                    char temp[32];
                    int len = ptoa_local(ptr, temp);
                    
                    for (int i = 0; i < len; i++) {
                        putchar_kernel(temp[i]);
                        count++;
                    }
                    break;
                }
                
                case '%': {
                    putchar_kernel('%');
                    count++;
                    break;
                }
                
                default:
                    putchar_kernel('%');
                    putchar_kernel(*fmt);
                    count += 2;
                    break;
            }
        } else {
            putchar_kernel(*fmt);
            count++;
        }
        fmt++;
    }
    
    return count;
}

/* Fonction principale kprintf */
int kprintf(const char *format, ...) {
    va_list args;
    unsigned long flags;
    unsigned long console_flags = 0;
    bool console_locked;
    int result;

    va_start(args, format);

    if (!arch_mmu_enabled()) {
        result = kprintf_vlocked(format, args);
        va_end(args);
        return result;
    }

    console_locked = tty_console_output_lock(&console_flags);
    spin_lock_irqsave(&kprintf_lock, &flags);
    result = kprintf_vlocked(format, args);
    spin_unlock_irqrestore(&kprintf_lock, flags);
    if (console_locked)
        tty_console_output_unlock(console_flags);

    va_end(args);
    return result;
}

void kboot_statusf(const char* status, const char* format, ...)
{
    va_list args;
    int label_len;
    bool early_console;

    if (!status || !format)
        return;

    unsigned long flags;
    unsigned long console_flags = 0;
    bool console_locked = false;

    early_console = !arch_mmu_enabled();
    if (!early_console) {
        console_locked = tty_console_output_lock(&console_flags);
        spin_lock_irqsave(&kprintf_lock, &flags);
    }

    va_start(args, format);
    label_len = kprintf_vlocked(format, args);
    va_end(args);

    while (label_len < 56) {
        putchar_kernel(' ');
        label_len++;
    }

    putchar_kernel(' ');
    kprintf_emit_string(status);
    putchar_kernel('\n');

    if (!early_console)
        spin_unlock_irqrestore(&kprintf_lock, flags);
    if (console_locked)
        tty_console_output_unlock(console_flags);
}

/* Fonctions de gestion du debug */
void set_debug(int enable) {
    DEBUG = enable;
}

int get_debug(void) {
    return DEBUG;
}

/* Fonction de test pour kprintf */
void kprintf_test(void) {
    kprintf("=== TEST KPRINTF eTENDU ===\n");
    
    /* Test des formats de base */
    kprintf("Entier: %d\n", 42);
    kprintf("Entier negatif: %d\n", -42);
    kprintf("Unsigned: %u\n", 3000000000U);
    kprintf("Hex minuscule: %x\n", 255);
    kprintf("Hex majuscule: %X\n", 255);
    kprintf("Caractere: %c\n", 'A');
    kprintf("String: %s\n", "Hello, kernel!");
    kprintf("Pointeur: %p\n", (void*)0x40080000);
    
    /* Test des formats longs */
    kprintf("Long: %ld\n", 1234567890L);
    kprintf("Long unsigned: %lu\n", 4000000000UL);
    kprintf("Long hex: %x\n", 0xDEADBEEF);
    
    /* Test des largeurs */
    kprintf("Largeur 10: '%10d'\n", 42);
    kprintf("Largeur 10 aligne gauche: '%-10d'\n", 42);
    kprintf("Padding zero: '%08d'\n", 42);
    kprintf("String largeur: '%15s'\n", "test");
    
    /* Test du debug */
    set_debug(1);
    KDEBUG("Message de debug test\n");
    KINFO("Message d'info\n");
    KWARN("Message d'avertissement\n");
    KERROR("Message d'erreur\n");
    set_debug(0);
    
    kprintf("=== FIN TEST KPRINTF ===\n");
}
