/* kernel/drivers/tty.c */
#include <kernel/tty.h>
#include <kernel/uart.h>
#include <kernel/task.h>
#include <kernel/string.h>
#include <kernel/process.h>
#include <kernel/vfs.h>
#include <kernel/signal.h>
#include <kernel/timer.h>

struct tty_struct tty0;

static uint32_t tty_output_next(uint32_t pos)
{
    return (pos + 1) % TTY_OUTPUT_BUF_SIZE;
}

static uint32_t tty_input_prev(uint32_t pos)
{
    return pos == 0 ? TTY_INPUT_BUF_SIZE - 1 : pos - 1;
}

static bool tty_output_empty_locked(void)
{
    return tty0.output_head == tty0.output_tail;
}

static bool tty_output_full_locked(void)
{
    return tty_output_next(tty0.output_head) == tty0.output_tail;
}

static void tty_init_termios(struct termios *tio)
{
    memset(tio, 0, sizeof(*tio));
    tio->c_iflag = ICRNL | IXON;
    tio->c_oflag = OPOST | ONLCR;
    tio->c_cflag = CS8 | CREAD | HUPCL;
    /* mash owns line echo/editing today; keep ECHO disabled by default. */
    tio->c_lflag = ICANON | ISIG | ECHOE | ECHOK | ECHOCTL | ECHOKE;
    tio->c_cc[VINTR] = 0x03;   /* Ctrl-C */
    tio->c_cc[VQUIT] = 0x1C;   /* Ctrl-\ */
    tio->c_cc[VERASE] = 0x7F;  /* DEL */
    tio->c_cc[VKILL] = 0x15;   /* Ctrl-U */
    tio->c_cc[VEOF] = 0x04;    /* Ctrl-D */
    tio->c_cc[VTIME] = 0;
    tio->c_cc[VMIN] = 1;
    tio->c_cc[VSTART] = 0x11;  /* Ctrl-Q */
    tio->c_cc[VSTOP] = 0x13;   /* Ctrl-S */
    tio->c_cc[VSUSP] = 0x1A;   /* Ctrl-Z */
    tio->c_cc[VEOL] = 0;
    tio->c_cc[VEOL2] = 0;
    tio->c_ispeed = 115200;
    tio->c_ospeed = 115200;
}

void tty_init(void) {
    memset(&tty0, 0, sizeof(tty0));
    
    tty_init_termios(&tty0.termios);
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

int tty_get_termios(struct termios *tio)
{
    unsigned long flags;

    if (!tio)
        return -EINVAL;

    memset(tio, 0, sizeof(*tio));

    spin_lock_irqsave(&tty0.lock, &flags);
    *tio = tty0.termios;
    spin_unlock_irqrestore(&tty0.lock, flags);

    return 0;
}

int tty_set_termios(const struct termios *tio, int flush_input)
{
    unsigned long flags;
    struct termios next;

    if (!tio)
        return -EINVAL;

    next = *tio;
    next.c_iflag &= (INLCR | IGNCR | ICRNL | IXON | IXOFF);
    next.c_oflag &= (OPOST | ONLCR | OCRNL | ONOCR | ONLRET);
    next.c_lflag &= (ECHO | ICANON | ISIG | IEXTEN |
                     ECHOE | ECHOK | ECHOCTL | ECHOKE);
    next.c_cflag &= (CS8 | CREAD | HUPCL);

    spin_lock_irqsave(&tty0.lock, &flags);
    tty0.termios = next;
    if (flush_input) {
        tty0.input_head = 0;
        tty0.input_tail = 0;
    }
    spin_unlock_irqrestore(&tty0.lock, flags);

    return 0;
}

int tty_flush(int queue_selector)
{
    unsigned long flags;

    if (queue_selector != TCIFLUSH &&
        queue_selector != TCOFLUSH &&
        queue_selector != TCIOFLUSH)
        return -EINVAL;

    if (queue_selector == TCIFLUSH || queue_selector == TCIOFLUSH) {
        spin_lock_irqsave(&tty0.lock, &flags);
        tty0.input_head = 0;
        tty0.input_tail = 0;
        tty0.eof_pending = false;
        tty0.read_wait = NULL;
        spin_unlock_irqrestore(&tty0.lock, flags);
    }

    if (queue_selector == TCOFLUSH || queue_selector == TCIOFLUSH) {
        spin_lock_irqsave(&tty0.lock, &flags);
        tty0.output_head = 0;
        tty0.output_tail = 0;
        spin_unlock_irqrestore(&tty0.lock, flags);
        uart_set_tx_irq_enabled(false);
    }

    return 0;
}

pid_t tty_get_read_wait_pid(void)
{
    unsigned long flags;
    task_t* waiter;
    pid_t pid = 0;

    spin_lock_irqsave(&tty0.lock, &flags);
    waiter = tty0.read_wait;
    if (waiter && waiter->process)
        pid = waiter->process->pid;
    spin_unlock_irqrestore(&tty0.lock, flags);
    return pid;
}

int tty_get_read_wait_state(void)
{
    unsigned long flags;
    task_t* waiter;
    int state = -1;

    spin_lock_irqsave(&tty0.lock, &flags);
    waiter = tty0.read_wait;
    if (waiter)
        state = (int)waiter->state;
    spin_unlock_irqrestore(&tty0.lock, flags);
    return state;
}

void tty_get_tx_stats(uint32_t *enqueued, uint32_t *drained,
                      uint32_t *full_waits, uint32_t *drain_calls)
{
    unsigned long flags;

    spin_lock_irqsave(&tty0.lock, &flags);
    if (enqueued)
        *enqueued = tty0.output_enqueued;
    if (drained)
        *drained = tty0.output_drained;
    if (full_waits)
        *full_waits = tty0.output_full_waits;
    if (drain_calls)
        *drain_calls = tty0.output_drain_calls;
    spin_unlock_irqrestore(&tty0.lock, flags);
}

bool tty_has_pending_output(void)
{
    unsigned long flags;
    bool pending;

    spin_lock_irqsave(&tty0.lock, &flags);
    pending = !tty_output_empty_locked();
    spin_unlock_irqrestore(&tty0.lock, flags);

    return pending;
}

/* Appelé par l'IRQ UART (ou polling) */
void tty_input_char(char c) {
    task_t* reader = NULL;
    pid_t signal_pgid = 0;
    int signal_num = 0;
    struct termios tio;
    bool canonical_echo;
    bool should_wake = true;
    unsigned long flags;
    spin_lock_irqsave(&tty0.lock, &flags);
    tio = tty0.termios;
    canonical_echo = (tio.c_lflag & ICANON) && (tio.c_lflag & ECHO);

    if (c == '\r') {
        if (tio.c_iflag & IGNCR) {
            spin_unlock_irqrestore(&tty0.lock, flags);
            return;
        }
        if (tio.c_iflag & ICRNL)
            c = '\n';
    } else if (c == '\n' && (tio.c_iflag & INLCR)) {
        c = '\r';
    }

    if ((tio.c_lflag & ISIG) && c == tio.c_cc[VINTR]) {
        int delivered;
        signal_pgid = tty0.foreground_pgid;
        signal_num = SIGINT;
        tty0.ctrl_c_seen++;
        tty0.last_signal_pgid = signal_pgid;
        tty0.last_signal = signal_num;
        spin_unlock_irqrestore(&tty0.lock, flags);
        uart_puts("^C\n");
        delivered = tty_signal_process_group(signal_pgid, signal_num);
        spin_lock_irqsave(&tty0.lock, &flags);
        tty0.last_signal_delivered = delivered;
        if (delivered > 0)
            tty0.sigint_delivered += delivered;
        else
            tty0.sigint_missed++;
        spin_unlock_irqrestore(&tty0.lock, flags);
        return;
    }

    if ((tio.c_lflag & ISIG) && c == tio.c_cc[VSUSP]) {
        int delivered;
        signal_pgid = tty0.foreground_pgid;
        signal_num = SIGTSTP;
        tty0.ctrl_z_seen++;
        tty0.last_signal_pgid = signal_pgid;
        tty0.last_signal = signal_num;
        spin_unlock_irqrestore(&tty0.lock, flags);
        uart_puts("^Z\n");
        delivered = tty_signal_process_group(signal_pgid, signal_num);
        spin_lock_irqsave(&tty0.lock, &flags);
        tty0.last_signal_delivered = delivered;
        if (delivered > 0)
            tty0.sigtstp_delivered += delivered;
        else
            tty0.sigtstp_missed++;
        spin_unlock_irqrestore(&tty0.lock, flags);
        return;
    }
    
    if (canonical_echo && c == tio.c_cc[VEOF]) {
        tty0.eof_pending = true;
        if (tty0.read_wait && tty0.read_wait->state == TASK_INTERRUPTIBLE) {
            reader = tty0.read_wait;
            tty0.read_wait = NULL;
        }
        spin_unlock_irqrestore(&tty0.lock, flags);

        if (reader) {
            reader->wakeup_time = 0;
            if (reader->process)
                reader->process->state = (proc_state_t)PROC_READY;
            add_to_ready_queue(reader);
        }
        return;
    }

    /* In canonical echo mode, the kernel owns basic line editing. mash keeps
     * ECHO disabled and still receives raw editing keys for its own editor. */
    if (canonical_echo && (c == '\b' || c == tio.c_cc[VERASE])) {
        if (tty0.input_head != tty0.input_tail) {
            uint32_t prev = tty_input_prev(tty0.input_head);
            if (tty0.input_buf[prev] != '\n' && tty0.input_buf[prev] != '\r') {
                tty0.input_head = prev;
                uart_puts("\b \b");
            }
        }
        spin_unlock_irqrestore(&tty0.lock, flags);
        return;
    }

    if (canonical_echo && c == tio.c_cc[VKILL]) {
        while (tty0.input_head != tty0.input_tail) {
            uint32_t prev = tty_input_prev(tty0.input_head);
            if (tty0.input_buf[prev] == '\n' || tty0.input_buf[prev] == '\r')
                break;
            tty0.input_head = prev;
            uart_puts("\b \b");
        }
        spin_unlock_irqrestore(&tty0.lock, flags);
        return;
    }

    /* Echo si activé */
    if (tio.c_lflag & ECHO) {
        uart_putc(c);
    }
    
    /* Ajouter au buffer */
    uint32_t next_head = (tty0.input_head + 1) % TTY_INPUT_BUF_SIZE;
    if (next_head != tty0.input_tail) {
        tty0.input_buf[tty0.input_head] = c;
        tty0.input_head = next_head;
        tty0.input_chars++;
        if (canonical_echo)
            should_wake = (c == '\n' || c == '\r');
        
        /* read(0, &c, 1) doit être réveillé dès qu'un caractère arrive.
         * Ne pas conserver un waiter mort ou qui n'attend plus le TTY: après
         * un signal, il doit revenir en userland via -EINTR plutôt que voler
         * le prochain caractère du shell. */
        if (should_wake && tty0.read_wait) {
            if (tty0.read_wait->state == TASK_INTERRUPTIBLE) {
                reader = tty0.read_wait;
                tty0.read_wait = NULL;
            } else if (tty0.read_wait->state == TASK_ZOMBIE ||
                       tty0.read_wait->state == TASK_TERMINATED ||
                       tty0.read_wait->state == TASK_READY ||
                       tty0.read_wait->state == TASK_RUNNING) {
                kernel_lifecycle_stats.tty_stale_waiters++;
                tty0.read_wait = NULL;
            }
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
            struct termios tio = tty0.termios;
            bool noncanon_no_min = !(tio.c_lflag & ICANON) && tio.c_cc[VMIN] == 0;
            uint32_t timeout_ticks = (uint32_t)tio.c_cc[VTIME] * (TIMER_FREQ / 10);
            uint32_t deadline = 0;

            if (tty0.eof_pending) {
                tty0.eof_pending = false;
                spin_unlock_irqrestore(&tty0.lock, flags);
                break;
            }

            if (read > 0 || !current_task) {
                spin_unlock_irqrestore(&tty0.lock, flags);
                break;
            }

            if (noncanon_no_min && timeout_ticks == 0) {
                spin_unlock_irqrestore(&tty0.lock, flags);
                break;
            }

            tty0.read_wait = current_task;
            task_set_interruptible(current_task);
            if (noncanon_no_min) {
                deadline = get_system_ticks() + timeout_ticks;
                current_task->wakeup_time = deadline;
            }
            spin_unlock_irqrestore(&tty0.lock, flags);

            schedule();
            spin_lock_irqsave(&tty0.lock, &flags);
            if (tty0.read_wait == current_task)
                tty0.read_wait = NULL;
            spin_unlock_irqrestore(&tty0.lock, flags);

            if (has_pending_signals(current_task))
                return read > 0 ? (ssize_t)read : (ssize_t)-EINTR;
            if (noncanon_no_min && get_system_ticks() >= deadline) {
                current_task->wakeup_time = 0;
                break;
            }
            current_task->wakeup_time = 0;
            continue;
        }
        
        /* Lire un caractère */
        char c = tty0.input_buf[tty0.input_tail];
        struct termios tio = tty0.termios;
        tty0.input_tail = (tty0.input_tail + 1) % TTY_INPUT_BUF_SIZE;
        
        spin_unlock_irqrestore(&tty0.lock, flags);
        
        buf[read++] = c;

        if (!(tio.c_lflag & ICANON)) {
            break;
        }
        
        /* En mode ligne, s'arrêter au '\n' */
        if (c == '\n' || c == '\r') {
            break;
        }
    }
    
    return read;
}

ssize_t tty_write(const char *buf, size_t count) {
    uint32_t oflag;
    unsigned long flags;
    size_t written = 0;

    spin_lock_irqsave(&tty0.lock, &flags);
    oflag = tty0.termios.c_oflag;
    spin_unlock_irqrestore(&tty0.lock, flags);

    for (size_t i = 0; i < count; i++) {
        if ((oflag & OPOST) && (oflag & ONLCR) && buf[i] == '\n') {
            while (1) {
                spin_lock_irqsave(&tty0.lock, &flags);
                if (!tty_output_full_locked()) {
                    tty0.output_buf[tty0.output_head] = '\r';
                    tty0.output_head = tty_output_next(tty0.output_head);
                    tty0.output_enqueued++;
                    spin_unlock_irqrestore(&tty0.lock, flags);
                    uart_set_tx_irq_enabled(true);
                    tty_drain_output();
                    break;
                }
                tty0.output_full_waits++;
                spin_unlock_irqrestore(&tty0.lock, flags);
                tty_drain_output();
                if (current_task && has_pending_signals(current_task))
                    return written > 0 ? (ssize_t)written : (ssize_t)-EINTR;
                if (current_task)
                    yield();
                else {
                    uart_putc('\r');
                    break;
                }
            }
        }

        while (1) {
            spin_lock_irqsave(&tty0.lock, &flags);
            if (!tty_output_full_locked()) {
                tty0.output_buf[tty0.output_head] = buf[i];
                tty0.output_head = tty_output_next(tty0.output_head);
                tty0.output_enqueued++;
                spin_unlock_irqrestore(&tty0.lock, flags);
                uart_set_tx_irq_enabled(true);
                tty_drain_output();
                break;
            }
            tty0.output_full_waits++;
            spin_unlock_irqrestore(&tty0.lock, flags);
            tty_drain_output();
            if (current_task && has_pending_signals(current_task))
                return written > 0 ? (ssize_t)written : (ssize_t)-EINTR;
            if (current_task)
                yield();
            else {
                uart_putc(buf[i]);
                break;
            }
        }
        written++;
    }
    return (ssize_t)written;
}

void tty_drain_output(void)
{
    unsigned long flags;

    spin_lock_irqsave(&tty0.lock, &flags);
    tty0.output_drain_calls++;
    spin_unlock_irqrestore(&tty0.lock, flags);

    while (1) {
        char c;
        bool sent;

        spin_lock_irqsave(&tty0.lock, &flags);
        if (tty_output_empty_locked()) {
            spin_unlock_irqrestore(&tty0.lock, flags);
            uart_set_tx_irq_enabled(false);
            return;
        }

        c = tty0.output_buf[tty0.output_tail];
        sent = uart_try_putc(c);
        if (sent) {
            tty0.output_tail = tty_output_next(tty0.output_tail);
            tty0.output_drained++;
        }
        spin_unlock_irqrestore(&tty0.lock, flags);

        if (!sent) {
            uart_set_tx_irq_enabled(true);
            return;
        }
    }
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
