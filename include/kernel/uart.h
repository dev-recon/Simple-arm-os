#ifndef UART_H
#define UART_H

#include <kernel/task.h>

// Adresse base de l'UART pour QEMU virt machine
#define UART_BASE_ADDR   0x09000000

// Registres UART (PL011)
#define UART_DR         (UART_BASE_ADDR + 0x00)  // Data Register
#define UART_FR         (UART_BASE_ADDR + 0x18)  // Flag Register
#define UART_IBRD       (UART_BASE_ADDR + 0x24)  // Integer Baud Rate
#define UART_FBRD       (UART_BASE_ADDR + 0x28)  // Fractional Baud Rate
#define UART_LCRH       (UART_BASE_ADDR + 0x2C)  // Line Control
#define UART_CR         (UART_BASE_ADDR + 0x30)  // Control Register

// Bits du registre Flag (FR)
#define UART_FR_TXFF    (1 << 5)  // Transmit FIFO Full
#define UART_FR_RXFE    (1 << 4)  // Receive FIFO Empty

// Fonctions publiques
void uart_init(void);
void uart_use_kernel_mmio_alias(void);
void uart_putc(char c);
bool uart_try_putc(char c);
bool uart_tx_ready(void);
void uart_puts(const char* str);
int uart_getc(void);
bool uart_has_data(void);
void uart_set_tx_irq_enabled(bool enabled);
void uart_put_hex(unsigned long value);
void uart_put_dec(int num);
void uart_irq_handler(void);

file_t* create_uart_console_file(const char* name, int flags);

#endif // UART_H
