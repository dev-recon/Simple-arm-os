/* kernel/drivers/uart.c */
#include <kernel/types.h>
#include <kernel/kernel.h>
#include <kernel/uart.h>

// src/kernel/uart.c - Implementation du driver UART

// Fonctions d'acces aux registres
static inline void mmio_write(unsigned long addr, unsigned int value) {
    *(volatile unsigned int*)addr = value;
}

static inline unsigned int mmio_read(unsigned long addr) {
    return *(volatile unsigned int*)addr;
}

// Initialiser l'UART
void uart_init(void) {
    // Desactiver l'UART
    mmio_write(UART_CR, 0);
    
    // Configurer le baud rate (38400 baud avec 24MHz clock)
    mmio_write(UART_IBRD, 39);
    mmio_write(UART_FBRD, 16);
    
    // Configurer le format: 8N1 (8 bits, no parity, 1 stop bit)
    mmio_write(UART_LCRH, (1 << 4) | (1 << 5) | (1 << 6));
    
    // Activer l'UART, TX et RX
    mmio_write(UART_CR, (1 << 0) | (1 << 8) | (1 << 9));
}

void putchar_kernel(char c) {
    uart_putc(c) ;
}  



// Envoyer un caractere
void uart_putc(char c) {
    // Attendre que le FIFO de transmission ne soit pas plein
    while (mmio_read(UART_FR) & UART_FR_TXFF) {
        // Attendre
    }
    
    if (c == '\n'){
         mmio_write(UART_DR, '\r');
    }
    
        // ecrire le caractere
        mmio_write(UART_DR, c);
    

}

// Envoyer une chaine de caracteres
void uart_puts(const char* str) {
    while (*str) {
        if (*str == '\n') {
            uart_putc('\r');  // Ajouter CR avant LF
        }
        uart_putc(*str++);
    }
}

// Recevoir un caractere
char uart_getc(void) {
    // Attendre qu'un caractere soit disponible
    while (mmio_read(UART_FR) & UART_FR_RXFE) {
        // Attendre
    }
    
    // Lire le caractere
    return (char)mmio_read(UART_DR);
}

// Afficher un nombre en hexadecimal
void uart_put_hex(unsigned long value) {
    uart_puts("0x");
    
    for (int i = 60; i >= 0; i -= 4) {
        int digit = (value >> i) & 0xF;
        if (digit < 10) {
            uart_putc('0' + digit);
        } else {
            uart_putc('A' + digit - 10);
        }
    }
}

// Afficher un nombre decimal
void uart_put_number(int num) {
    if (num == 0) {
        uart_putc('0');
        return;
    }
    
    if (num < 0) {
        uart_putc('-');
        num = -num;
    }
    
    char buffer[12];  // Suffisant pour un int 32-bit
    int pos = 0;
    
    while (num > 0) {
        buffer[pos++] = '0' + (num % 10);
        num /= 10;
    }
    
    // Afficher dans l'ordre inverse
    for (int i = pos - 1; i >= 0; i--) {
        uart_putc(buffer[i]);
    }
}