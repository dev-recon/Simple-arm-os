/* kernel/drivers/tty.c */
#include <kernel/tty.h>
#include <kernel/uart.h>
#include <kernel/task.h>
#include <kernel/string.h>
#include <kernel/process.h>
#include <kernel/vfs.h>
#include <kernel/signal.h>

struct tty_struct tty0;

void tty_init(void) {
    memset(&tty0, 0, sizeof(tty0));
    
    /* mash echoe deja les caracteres lus ; le TTY garde le buffering ligne. */
    tty0.c_lflag = ICANON | ISIG;
    tty0.foreground_pgid = 0;
    
    init_spinlock(&tty0.lock);
}

static int tty_signal_process_group(pid_t pgid, int sig)
{
    task_t* task;
    int delivered = 0;
    int count = 0;

    if (pgid <= 0 || !task_list_head)
        return 0;

    task = task_list_head;
    do {
        if (task->type == TASK_TYPE_PROCESS && task->process &&
            task->process->pgid == pgid &&
            task->state != TASK_ZOMBIE &&
            task->state != TASK_TERMINATED) {
            if (send_signal(task, sig) == 0)
                delivered++;
        }

        task = task->next;
        count++;
    } while (task && task != task_list_head && count < MAX_TASKS);

    return delivered;
}

int tty_set_foreground_pgid(pid_t pgid)
{
    unsigned long flags;

    if (pgid < 0)
        return -EINVAL;

    spin_lock_irqsave(&tty0.lock, &flags);
    tty0.foreground_pgid = pgid;
    spin_unlock_irqrestore(&tty0.lock, flags);
    return 0;
}

pid_t tty_get_foreground_pgid(void)
{
    unsigned long flags;
    pid_t pgid;

    spin_lock_irqsave(&tty0.lock, &flags);
    pgid = tty0.foreground_pgid;
    spin_unlock_irqrestore(&tty0.lock, flags);
    return pgid;
}

/* Appelé par l'IRQ UART (ou polling) */
void tty_input_char(char c) {
    task_t* reader = NULL;
    pid_t signal_pgid = 0;
    int signal_num = 0;
    unsigned long flags;
    spin_lock_irqsave(&tty0.lock, &flags);

    if ((tty0.c_lflag & ISIG) && c == 0x03) {
        signal_pgid = tty0.foreground_pgid;
        signal_num = SIGINT;
        spin_unlock_irqrestore(&tty0.lock, flags);
        uart_puts("^C\n");
        tty_signal_process_group(signal_pgid, signal_num);
        return;
    }
    
    /* In raw/no-echo mode, pass editing keys to userland. mash owns line editing. */
    if ((tty0.c_lflag & ECHO) && (c == '\b' || c == 127)) {
        if (tty0.input_head != tty0.input_tail) {
            tty0.input_head = (tty0.input_head - 1) % TTY_INPUT_BUF_SIZE;
            uart_puts("\b \b");
        }
        spin_unlock_irqrestore(&tty0.lock, flags);
        return;
    }

    /* Echo si activé */
    if (tty0.c_lflag & ECHO) {
        uart_putc(c);
    }
    
    /* Ajouter au buffer */
    uint32_t next_head = (tty0.input_head + 1) % TTY_INPUT_BUF_SIZE;
    if (next_head != tty0.input_tail) {
        tty0.input_buf[tty0.input_head] = c;
        tty0.input_head = next_head;
        
        /* read(0, &c, 1) doit être réveillé dès qu'un caractère arrive. */
        if (tty0.read_wait) {
            reader = tty0.read_wait;
            tty0.read_wait = NULL;
        }
    }
    
    spin_unlock_irqrestore(&tty0.lock, flags);

    if (reader) {
        reader->wakeup_time = 0;
        if (reader->process)
            reader->process->state = (proc_state_t)PROC_READY;
        add_to_ready_queue(reader);
    }
}

ssize_t tty_read(char *buf, size_t count) {
    size_t read = 0;
    unsigned long flags;
    
    while (read < count) {
        while (uart_has_data()) {
            int c = uart_getc();
            if (c < 0) break;
            tty_input_char((char)c);
        }

        spin_lock_irqsave(&tty0.lock, &flags);
        
        /* Buffer vide ? */
        if (tty0.input_head == tty0.input_tail) {
            if (read > 0 || !current_task) {
                spin_unlock_irqrestore(&tty0.lock, flags);
                break;
            }

            tty0.read_wait = current_task;
            current_task->state = TASK_INTERRUPTIBLE;
            if (current_task->process)
                current_task->process->state = (proc_state_t)PROC_INTERRUPTIBLE;
            spin_unlock_irqrestore(&tty0.lock, flags);

            schedule();
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
        if (buf[i] == '\n') {
            uart_putc('\r');
        }
        uart_putc(buf[i]);
    }
    return count;
}

static ssize_t tty_file_read(file_t* file, void* buf, size_t count) {
    (void)file;
    return tty_read((char*)buf, count);
}

static ssize_t tty_file_write(file_t* file, const void* buf, size_t count) {
    (void)file;
    return tty_write((const char*)buf, count);
}

static file_operations_t tty_file_ops = {
    .read = tty_file_read,
    .write = tty_file_write,
    .open = NULL,
    .close = NULL,
    .lseek = NULL,
    .readdir = NULL
};

file_t* create_tty_console_file(const char* name, int flags) {
    file_t* file = create_file();
    if (!file) return NULL;

    file->f_op = &tty_file_ops;
    file->flags = flags;
    file->pos = 0;
    file->inode = NULL;

    if (name) {
        strncpy(file->name, name, sizeof(file->name) - 1);
        file->name[sizeof(file->name) - 1] = '\0';
    }

    return file;
}
