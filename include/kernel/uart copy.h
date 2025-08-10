/* include/kernel/uart.h */
#ifndef _KERNEL_UART_H
#define _KERNEL_UART_H

#include <kernel/types.h>


/* Declarations forward des fonctions UART */

/* Fonctions de base */
void uart_init(void);
void uart_putc(char c);
void uart_puts(const char* str);
int uart_getc(void);
void uart_flush(void);

/* Fonctions d'affichage formate */
void uart_put_hex(uint32_t value);
void uart_put_dec(uint32_t value);
void uart_put_bin(uint32_t value, int bits);

/* Fonction printf simplifiee */
void uart_printf(const char* format, ...);

/* Fonctions de diagnostic */
bool uart_test_loopback(void);
void uart_dump_registers(void);
void putchar_kernel(char c);

/* Macros utiles pour le debug */
#define UART_DEBUG(msg) do { \
    uart_puts("[DEBUG] " msg "\n"); \
} while(0)

#define UART_INFO(msg) do { \
    uart_puts("[INFO] " msg "\n"); \
} while(0)

#define UART_ERROR(msg) do { \
    uart_puts("[ERROR] " msg "\n"); \
} while(0)

#define UART_HEXDUMP(name, value) do { \
    uart_puts(name ": 0x"); \
    uart_put_hex(value); \
    uart_puts("\n"); \
} while(0)

#endif /* UART_H */