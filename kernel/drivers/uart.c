/* kernel/drivers/uart.c */
#include <kernel/types.h>
#include <kernel/kernel.h>
#include <kernel/spinlock.h>
#include <kernel/vfs.h>
#include <kernel/userspace.h>

/* Registres PL011 UART */
#define UART_DR         (*(volatile uint32_t*)(UART0_BASE + 0x00))  /* Data */
#define UART_RSR        (*(volatile uint32_t*)(UART0_BASE + 0x04))  /* Receive Status */
#define UART_FR         (*(volatile uint32_t*)(UART0_BASE + 0x18))  /* Flag */
#define UART_ILPR       (*(volatile uint32_t*)(UART0_BASE + 0x20))  /* IrDA Low-power */
#define UART_IBRD       (*(volatile uint32_t*)(UART0_BASE + 0x24))  /* Integer Baud Rate */
#define UART_FBRD       (*(volatile uint32_t*)(UART0_BASE + 0x28))  /* Fractional Baud Rate */
#define UART_LCRH       (*(volatile uint32_t*)(UART0_BASE + 0x2C))  /* Line Control */
#define UART_CR         (*(volatile uint32_t*)(UART0_BASE + 0x30))  /* Control */
#define UART_IFLS       (*(volatile uint32_t*)(UART0_BASE + 0x34))  /* Interrupt FIFO Level */
#define UART_IMSC       (*(volatile uint32_t*)(UART0_BASE + 0x38))  /* Interrupt Mask */
#define UART_RIS        (*(volatile uint32_t*)(UART0_BASE + 0x3C))  /* Raw Interrupt Status */
#define UART_MIS        (*(volatile uint32_t*)(UART0_BASE + 0x40))  /* Masked Interrupt Status */
#define UART_ICR        (*(volatile uint32_t*)(UART0_BASE + 0x44))  /* Interrupt Clear */

/* Bits de controle UART_FR (Flag Register) */
#define UART_FR_TXFE    (1 << 7)  /* Transmit FIFO empty */
#define UART_FR_RXFF    (1 << 6)  /* Receive FIFO full */
#define UART_FR_TXFF    (1 << 5)  /* Transmit FIFO full */
#define UART_FR_RXFE    (1 << 4)  /* Receive FIFO empty */
#define UART_FR_BUSY    (1 << 3)  /* UART busy */

/* Bits de controle UART_CR (Control Register) */
#define UART_CR_CTSEN   (1 << 15) /* CTS hardware flow control enable */
#define UART_CR_RTSEN   (1 << 14) /* RTS hardware flow control enable */
#define UART_CR_RTS     (1 << 11) /* Request to send */
#define UART_CR_RXE     (1 << 9)  /* Receive enable */
#define UART_CR_TXE     (1 << 8)  /* Transmit enable */
#define UART_CR_LBE     (1 << 7)  /* Loopback enable */
#define UART_CR_UARTEN  (1 << 0)  /* UART enable */

/* Bits de controle UART_LCRH (Line Control Register) */
#define UART_LCRH_SPS   (1 << 7)  /* Stick parity select */
#define UART_LCRH_WLEN_8 (3 << 5) /* Word length 8 bits */
#define UART_LCRH_WLEN_7 (2 << 5) /* Word length 7 bits */
#define UART_LCRH_WLEN_6 (1 << 5) /* Word length 6 bits */
#define UART_LCRH_WLEN_5 (0 << 5) /* Word length 5 bits */
#define UART_LCRH_FEN   (1 << 4)  /* FIFO enable */
#define UART_LCRH_STP2  (1 << 3)  /* Two stop bits select */
#define UART_LCRH_EPS   (1 << 2)  /* Even parity select */
#define UART_LCRH_PEN   (1 << 1)  /* Parity enable */
#define UART_LCRH_BRK   (1 << 0)  /* Send break */

/* Variable globale */
DEFINE_SPINLOCK(uart_lock);

/*
 * Initialisation de l'UART PL011
 */
void uart_init(void)
{
    /* Desactiver l'UART */
    UART_CR = 0;
    
    /* Vider les FIFOs */
    while (!(UART_FR & UART_FR_RXFE)) {
        (void)UART_DR;
    }
    
    /* Configuration baud rate pour machine virt QEMU */
    /* QEMU machine virt utilise une horloge differente */
    /* Pour 115200 bps sur machine virt : */
    UART_IBRD = 26;   /* Partie entiere */
    UART_FBRD = 3;    /* Partie fractionnaire */
    
    /* Alternative plus s-re : desactiver completement le baud rate */
    /* QEMU peut ignorer ces registres */
    
    /* Configurer le format de ligne */
    UART_LCRH = UART_LCRH_WLEN_8 | UART_LCRH_FEN;
    
    /* Effacer toutes les interruptions */
    UART_ICR = 0x7FF;
    UART_IMSC = 0;
    
    /* Activer UART, TX et RX */
    UART_CR = UART_CR_UARTEN | UART_CR_TXE | UART_CR_RXE;

}

/*
 * Envoyer un caractere
 */
void uart_putc(char c)
{
    unsigned long flags;
    spin_lock_irqsave(&uart_lock, &flags);

    int timeout = 100000;
    
    /* Attendre que le FIFO TX ne soit pas plein avec timeout */
    while ((UART_FR & UART_FR_TXFF) && timeout > 0) {
        timeout--;
        for (volatile int i = 0; i < 10; i++);
    }
    
    if (timeout > 0) {
        UART_DR = c;
    }
    spin_unlock_irqrestore(&uart_lock, flags);
}

/*
 * Envoyer une chaine de caracteres
 */
void uart_puts(const char* str)
{

    while (*str) {
        /* Convertir LF en CRLF pour compatibilite terminal */
        if (*str == '\n') {
            uart_putc('\r');
        }
        uart_putc(*str++);
    }

}

/*
 * Recevoir un caractere (non-bloquant)
 */
int uart_getc(void)
{
    /* Verifier si des donnees sont disponibles */
    if (UART_FR & UART_FR_RXFE) {
        return -1;  /* Pas de donnees */
    }
    
    /* Lire le caractere */
    return UART_DR & 0xFF;
}

/*
 * Afficher un nombre en hexadecimal
 */
void uart_put_hex(uint32_t value)
{

    const char hex_chars[] = "0123456789ABCDEF";
    char buffer[9];
    int i;
    
    buffer[8] = '\0';
    
    for (i = 7; i >= 0; i--) {
        buffer[i] = hex_chars[value & 0xF];
        value >>= 4;
    }
    
    uart_puts(buffer);
}

/*
 * Afficher un nombre en decimal
 */
void uart_put_dec(uint32_t value)
{

    char buffer[11];  /* Assez pour 2^32 */
    int i = 0;
    
    if (value == 0) {
        uart_putc('0');
        return;
    }
    
    /* Convertir en chaine (ordre inverse) */
    while (value > 0) {
        buffer[i++] = '0' + (value % 10);
        value /= 10;
    }
    
    /* Afficher dans le bon ordre */
    while (i > 0) {
        uart_putc(buffer[--i]);
    }
}

/*
 * Afficher un nombre binaire (utile pour les registres)
 */
void uart_put_bin(uint32_t value, int bits)
{

    int i;
    
    uart_puts("0b");
    
    for (i = bits - 1; i >= 0; i--) {
        uart_putc((value & (1 << i)) ? '1' : '0');
        
        /* Ajouter un espace tous les 4 bits pour lisibilite */
        if (i > 0 && (i % 4) == 0) {
            uart_putc(' ');
        }
    }
}

/*
 * Fonction printf simplifiee pour debug
 */
void uart_printf(const char* format, ...)
{

    /* Implementation basique pour %d, %x, %s */
    const char* p = format;
    
    /* Note: Implementation simplifiee sans va_list pour eviter 
     * les dependances sur stdarg.h dans un kernel minimal */
    
    while (*p) {
        if (*p == '%' && *(p + 1)) {
            p++;  /* Passer le '%' */
            switch (*p) {
                case '%':
                    uart_putc('%');
                    break;
                case 'c':
                    uart_putc('?');  /* Placeholder */
                    break;
                case 's':
                    uart_puts("(str)");  /* Placeholder */
                    break;
                case 'd':
                    uart_puts("(dec)");  /* Placeholder */
                    break;
                case 'x':
                    uart_puts("(hex)");  /* Placeholder */
                    break;
                default:
                    uart_putc(*p);
                    break;
            }
        } else {
            uart_putc(*p);
        }
        p++;
    }
}

/*
 * Test de boucle-back UART (diagnostic)
 */
bool uart_test_loopback(void)
{
    const char test_char = 'A';
    char received;
    
    /* Activer le mode loopback */
    UART_CR |= UART_CR_LBE;
    
    /* Envoyer un caractere */
    uart_putc(test_char);
    
    /* Attendre un peu */
    for (volatile int i = 0; i < 1000; i++);
    
    /* Essayer de le recevoir */
    received = uart_getc();
    
    /* Desactiver le loopback */
    UART_CR &= ~UART_CR_LBE;
    
    return (received == test_char);
}

/*
 * Afficher l'etat des registres UART (debug)
 */
void uart_dump_registers(void)
{
    uart_puts("\n=== etat UART PL011 ===\n");
    
    uart_puts("FR (Flag):     0x");
    uart_put_hex(UART_FR);
    uart_puts(" = ");
    uart_put_bin(UART_FR, 8);
    uart_puts("\n");
    
    uart_puts("CR (Control):  0x");
    uart_put_hex(UART_CR);
    uart_puts(" = ");
    uart_put_bin(UART_CR, 16);
    uart_puts("\n");
    
    uart_puts("LCRH (Line):   0x");
    uart_put_hex(UART_LCRH);
    uart_puts(" = ");
    uart_put_bin(UART_LCRH, 8);
    uart_puts("\n");
    
    uart_puts("IBRD (Baud):   ");
    uart_put_dec(UART_IBRD);
    uart_puts("\n");
    
    uart_puts("FBRD (Frac):   ");
    uart_put_dec(UART_FBRD);
    uart_puts("\n");
    
    uart_puts("========================\n\n");
}

void putchar_kernel(char c) {
    uart_putc(c) ;
}

void uart_flush(void)
{
    int timeout = 100000;
    
    /* Utiliser directement UART_FR qui est deja defini */
    while (!(UART_FR & UART_FR_TXFE) && timeout > 0) {
        timeout--;
        for (volatile int i = 0; i < 10; i++);
    }
    
    /* Pause finale pour etre s-r */
    for (volatile int i = 0; i < 1000; i++);
}

// Pour QEMU machine virt qui utilise PL011
bool uart_has_data(void) {
    // PL011 Flag Register à offset 0x18
    uint32_t uart_flags = GET32(UART0_BASE + 0x18);
    
    // Bit 4 (RXFE) = 1 si RX FIFO vide, 0 si données disponibles
    bool rx_fifo_empty = (uart_flags & (1 << 4)) != 0;
    
    return !rx_fifo_empty;  // Retourner true si données disponibles
}


static ssize_t uart_console_write(file_t* file, const void* buf, size_t count) {
    (void) file;
    const char* data = (const char*)buf;
    size_t written = 0;
    
    // Vérifier adresse utilisateur
    //if (!is_valid_user_range(buf, count)) {
    //    return -EFAULT;
    //}
    
    // Écrire via UART caractère par caractère
    for (size_t i = 0; i < count; i++) {
        char c = data[i];
        
        // Utiliser votre fonction UART existante
        uart_putc(c);  // ou uart_write_char(c), selon votre API
        written++;
    }
    
    return written;
}

static ssize_t uart_console_read(file_t* file, void* buf, size_t count) {
    (void) file;

    // Pour stdin via UART (si implémenté)
    char* data = (char*)buf;
    size_t read_count = 0;
    
    if (!is_valid_user_range(buf, count)) {
        return -EFAULT;
    }
    
    for (size_t i = 0; i < count; i++) {
        // Utiliser votre fonction UART de lecture
        if (uart_has_data()) {  // Vérifier si données disponibles
            data[i] = uart_getc();  // ou uart_read_char()
            read_count++;
            
            // Arrêter sur newline pour stdin
            if (data[i] == '\n') {
                read_count++;
                break;
            }
        } else {
            // Pas de données : retourner ce qu'on a lu
            break;
        }
    }
    
    return read_count;
}

// File operations pour console UART
file_operations_t uart_console_fops = {
    .read = uart_console_read,
    .write = uart_console_write,
    .open = NULL,
    .close = NULL,      // Pas de close sur UART
    .lseek = NULL,       // Pas de seek sur UART
    .readdir = NULL
};


// Créer un fichier console UART
file_t* create_uart_console_file(const char* name, int flags) {
    file_t* file = kmalloc(sizeof(file_t));
    if (!file) return NULL;
    
    memset(file, 0, sizeof(file_t));
    
    file->f_op = &uart_console_fops;    // Pointer vers UART operations
    file->flags = flags;
    file->pos = 0;
    file->inode = NULL;                 // Fichier virtuel
    
    // Debug name
    if (name) {
        strncpy(file->name, name, sizeof(file->name) - 1);
    }
    
    return file;
}