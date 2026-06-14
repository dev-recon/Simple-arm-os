/* kernel/drivers/tty.c */
#include <kernel/tty.h>
#include <kernel/uart.h>
#include <kernel/task.h>
#include <kernel/string.h>
#include <kernel/process.h>

struct tty_struct tty0;

void tty_init(void) {
    memset(&tty0, 0, sizeof(tty0));
    
    /* Configuration par défaut : echo + mode ligne */
    tty0.c_lflag = ECHO | ICANON;
    
    init_spinlock(&tty0.lock);
}

/* Appelé par l'IRQ UART (ou polling) */
void tty_input_char(char c) {
    unsigned long flags;
    spin_lock_irqsave(&tty0.lock, &flags);
    
    /* Echo si activé */
    if (tty0.c_lflag & ECHO) {
        uart_putc(c);
    }
    
    /* Gestion backspace */
    if (c == '\b' || c == 127) {
        if (tty0.input_head != tty0.input_tail) {
            tty0.input_head = (tty0.input_head - 1) % TTY_INPUT_BUF_SIZE;
            if (tty0.c_lflag & ECHO) {
                uart_puts("\b \b");  /* Effacer le caractère à l'écran */
            }
        }
        spin_unlock_irqrestore(&tty0.lock, flags);
        return;
    }
    
    /* Ajouter au buffer */
    uint32_t next_head = (tty0.input_head + 1) % TTY_INPUT_BUF_SIZE;
    if (next_head != tty0.input_tail) {
        tty0.input_buf[tty0.input_head] = c;
        tty0.input_head = next_head;
        
        /* Réveiller le lecteur si mode ligne et '\n' reçu */
        if ((tty0.c_lflag & ICANON) && (c == '\n' || c == '\r')) {
            if (tty0.read_wait) {
                task_t* reader = tty0.read_wait;
                reader->state = TASK_READY;
                if (reader->process)
                    reader->process->state = (proc_state_t)PROC_READY;
                tty0.read_wait = NULL;
            }
        }
    }
    
    spin_unlock_irqrestore(&tty0.lock, flags);
}

ssize_t tty_read(char *buf, size_t count) {
    size_t read = 0;
    unsigned long flags;
    
    while (read < count) {
        spin_lock_irqsave(&tty0.lock, &flags);
        
        /* Buffer vide ? */
        if (tty0.input_head == tty0.input_tail) {
            if (read > 0) {
                spin_unlock_irqrestore(&tty0.lock, flags);
                break;  /* Données déjà lues */
            }
            
            /* Bloquer en attendant des données */
            tty0.read_wait = current_task;
            current_task->state = TASK_BLOCKED;
            spin_unlock_irqrestore(&tty0.lock, flags);
            
            yield();
            
            continue;
        }
        
        /* Lire un caractère */
        char c = tty0.input_buf[tty0.input_tail];
        tty0.input_tail = (tty0.input_tail + 1) % TTY_INPUT_BUF_SIZE;
        
        spin_unlock_irqrestore(&tty0.lock, flags);
        
        buf[read++] = c;
        
        /* En mode ligne, s'arrêter au '\n' */
        if ((tty0.c_lflag & ICANON) && (c == '\n' || c == '\r')) {
            break;
        }
    }
    
    return read;
}

ssize_t tty_write(const char *buf, size_t count) {
    for (size_t i = 0; i < count; i++) {
        uart_putc(buf[i]);
    }
    return count;
}
