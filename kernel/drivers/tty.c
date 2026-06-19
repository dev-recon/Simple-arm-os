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

#define TTY_TX_DRAIN_BUDGET 64

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
    tio->c_cc[VWERASE] = 0x17; /* Ctrl-W */
    tio->c_cc[VEOL] = 0;
    tio->c_cc[VEOL2] = 0;
    tio->c_ispeed = 115200;
    tio->c_ospeed = 115200;
}

void tty_init(void) {
    memset(&tty0, 0, sizeof(tty0));
    
    tty_init_termios(&tty0.termios);
    tty0.foreground_pgid = 0;
    tty0.winsize_rows = 24;
    tty0.winsize_cols = 80;
    tty0.winsize_xpixel = 0;
    tty0.winsize_ypixel = 0;
    
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
    task_t *reader = NULL;

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
        tty0.eof_pending = false;
        if (tty0.read_wait && tty0.read_wait->state == TASK_INTERRUPTIBLE) {
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

    return 0;
}

int tty_flush(int queue_selector)
{
    unsigned long flags;
    task_t *reader = NULL;

    if (queue_selector != TCIFLUSH &&
        queue_selector != TCOFLUSH &&
        queue_selector != TCIOFLUSH)
        return -EINVAL;

    if (queue_selector == TCIFLUSH || queue_selector == TCIOFLUSH) {
        spin_lock_irqsave(&tty0.lock, &flags);
        tty0.input_head = 0;
        tty0.input_tail = 0;
        tty0.eof_pending = false;
        if (tty0.read_wait && tty0.read_wait->state == TASK_INTERRUPTIBLE)
            reader = tty0.read_wait;
        tty0.read_wait = NULL;
        spin_unlock_irqrestore(&tty0.lock, flags);

        if (reader) {
            reader->wakeup_time = 0;
            if (reader->process)
                reader->process->state = (proc_state_t)PROC_READY;
            add_to_ready_queue(reader);
        }
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

void tty_get_winsize(uint16_t *rows, uint16_t *cols,
                     uint16_t *xpixel, uint16_t *ypixel)
{
    unsigned long flags;

    spin_lock_irqsave(&tty0.lock, &flags);
    if (rows)
        *rows = tty0.winsize_rows;
    if (cols)
        *cols = tty0.winsize_cols;
    if (xpixel)
        *xpixel = tty0.winsize_xpixel;
    if (ypixel)
        *ypixel = tty0.winsize_ypixel;
    spin_unlock_irqrestore(&tty0.lock, flags);
}

int tty_set_winsize(uint16_t rows, uint16_t cols,
                    uint16_t xpixel, uint16_t ypixel)
{
    unsigned long flags;
    pid_t pgid = 0;
    bool changed;

    if (rows == 0 || cols == 0)
        return -EINVAL;

    spin_lock_irqsave(&tty0.lock, &flags);
    changed = tty0.winsize_rows != rows ||
              tty0.winsize_cols != cols ||
              tty0.winsize_xpixel != xpixel ||
              tty0.winsize_ypixel != ypixel;
    tty0.winsize_rows = rows;
    tty0.winsize_cols = cols;
    tty0.winsize_xpixel = xpixel;
    tty0.winsize_ypixel = ypixel;
    if (changed)
        pgid = tty0.foreground_pgid;
    spin_unlock_irqrestore(&tty0.lock, flags);

    if (changed && pgid > 0)
        tty_signal_process_group(pgid, SIGWINCH);

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

void tty_get_input_stats(uint32_t *depth, uint32_t *capacity,
                         uint32_t *eof_pending, uint32_t *iflag,
                         uint32_t *oflag, uint32_t *lflag,
                         uint32_t *vmin, uint32_t *vtime,
                         uint32_t *char_wakeups,
                         uint32_t *line_wakeups,
                         uint32_t *eof_wakeups)
{
    unsigned long flags;
    uint32_t head;
    uint32_t tail;
    struct termios tio;

    spin_lock_irqsave(&tty0.lock, &flags);
    head = tty0.input_head;
    tail = tty0.input_tail;
    tio = tty0.termios;

    if (depth)
        *depth = head >= tail ? head - tail : TTY_INPUT_BUF_SIZE - tail + head;
    if (capacity)
        *capacity = TTY_INPUT_BUF_SIZE - 1;
    if (eof_pending)
        *eof_pending = tty0.eof_pending ? 1 : 0;
    if (iflag)
        *iflag = tio.c_iflag;
    if (oflag)
        *oflag = tio.c_oflag;
    if (lflag)
        *lflag = tio.c_lflag;
    if (vmin)
        *vmin = tio.c_cc[VMIN];
    if (vtime)
        *vtime = tio.c_cc[VTIME];
    if (char_wakeups)
        *char_wakeups = tty0.char_wakeups;
    if (line_wakeups)
        *line_wakeups = tty0.line_wakeups;
    if (eof_wakeups)
        *eof_wakeups = tty0.eof_wakeups;
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

static void tty_wake_reader(task_t *reader)
{
    if (!reader)
        return;

    reader->wakeup_time = 0;
    if (reader->process)
        reader->process->state = (proc_state_t)PROC_READY;
    add_to_ready_queue(reader);
}

static bool tty_normalize_input_char(const struct termios *tio, char *c)
{
    if (*c == '\r') {
        if (tio->c_iflag & IGNCR)
            return false;
        if (tio->c_iflag & ICRNL)
            *c = '\n';
    } else if (*c == '\n' && (tio->c_iflag & INLCR)) {
        *c = '\r';
    }

    return true;
}

static bool tty_handle_signal_char_locked(const struct termios *tio, char c,
                                          unsigned long *flags)
{
    int sig;
    int delivered;
    pid_t pgid;
    const char *echo;

    if (!(tio->c_lflag & ISIG))
        return false;

    if (c == tio->c_cc[VINTR]) {
        sig = SIGINT;
        echo = "^C\n";
        tty0.ctrl_c_seen++;
    } else if (c == tio->c_cc[VSUSP]) {
        sig = SIGTSTP;
        echo = "^Z\n";
        tty0.ctrl_z_seen++;
    } else {
        return false;
    }

    pgid = tty0.foreground_pgid;
    tty0.last_signal_pgid = pgid;
    tty0.last_signal = sig;

    spin_unlock_irqrestore(&tty0.lock, *flags);
    uart_puts(echo);
    delivered = tty_signal_process_group(pgid, sig);
    spin_lock_irqsave(&tty0.lock, flags);

    tty0.last_signal_delivered = delivered;
    if (sig == SIGINT) {
        if (delivered > 0)
            tty0.sigint_delivered += delivered;
        else
            tty0.sigint_missed++;
    } else {
        if (delivered > 0)
            tty0.sigtstp_delivered += delivered;
        else
            tty0.sigtstp_missed++;
    }

    return true;
}

static task_t *tty_take_interruptible_reader_locked(void)
{
    task_t *reader = NULL;

    if (tty0.read_wait && tty0.read_wait->state == TASK_INTERRUPTIBLE) {
        reader = tty0.read_wait;
        tty0.read_wait = NULL;
    }

    return reader;
}

static bool tty_handle_eof_locked(const struct termios *tio, char c,
                                  task_t **reader)
{
    if (!((tio->c_lflag & ICANON) && (tio->c_lflag & ECHO)) ||
        c != tio->c_cc[VEOF])
        return false;

    tty0.eof_pending = true;
    *reader = tty_take_interruptible_reader_locked();
    if (*reader)
        tty0.eof_wakeups++;

    return true;
}

static bool tty_handle_canonical_edit_locked(const struct termios *tio, char c)
{
    bool canonical_echo = (tio->c_lflag & ICANON) && (tio->c_lflag & ECHO);

    if (!canonical_echo)
        return false;

    /* In canonical echo mode, the kernel owns basic line editing. mash keeps
     * ECHO disabled and still receives raw editing keys for its own editor. */
    if (c == '\b' || c == tio->c_cc[VERASE]) {
        if (tty0.input_head != tty0.input_tail) {
            uint32_t prev = tty_input_prev(tty0.input_head);
            if (tty0.input_buf[prev] != '\n' && tty0.input_buf[prev] != '\r') {
                tty0.input_head = prev;
                uart_puts("\b \b");
            }
        }
        return true;
    }

    if (c == tio->c_cc[VKILL]) {
        while (tty0.input_head != tty0.input_tail) {
            uint32_t prev = tty_input_prev(tty0.input_head);
            if (tty0.input_buf[prev] == '\n' || tty0.input_buf[prev] == '\r')
                break;
            tty0.input_head = prev;
            uart_puts("\b \b");
        }
        return true;
    }

    if (c == tio->c_cc[VWERASE]) {
        while (tty0.input_head != tty0.input_tail) {
            uint32_t prev = tty_input_prev(tty0.input_head);
            char pc = tty0.input_buf[prev];
            if (pc == '\n' || pc == '\r' || pc != ' ')
                break;
            tty0.input_head = prev;
            uart_puts("\b \b");
        }
        while (tty0.input_head != tty0.input_tail) {
            uint32_t prev = tty_input_prev(tty0.input_head);
            char pc = tty0.input_buf[prev];
            if (pc == '\n' || pc == '\r' || pc == ' ')
                break;
            tty0.input_head = prev;
            uart_puts("\b \b");
        }
        return true;
    }

    return false;
}

static task_t *tty_enqueue_input_char_locked(const struct termios *tio, char c)
{
    uint32_t next_head;
    bool canonical_echo = (tio->c_lflag & ICANON) && (tio->c_lflag & ECHO);
    bool should_wake = true;
    task_t *reader = NULL;

    if (tio->c_lflag & ECHO)
        uart_putc(c);

    next_head = (tty0.input_head + 1) % TTY_INPUT_BUF_SIZE;
    if (next_head == tty0.input_tail)
        return NULL;

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
            if (canonical_echo)
                tty0.line_wakeups++;
            else
                tty0.char_wakeups++;
        } else if (tty0.read_wait->state == TASK_ZOMBIE ||
                   tty0.read_wait->state == TASK_TERMINATED ||
                   tty0.read_wait->state == TASK_READY ||
                   tty0.read_wait->state == TASK_RUNNING) {
            kernel_lifecycle_stats.tty_stale_waiters++;
            tty0.read_wait = NULL;
        }
    }

    return reader;
}

/* Appelé par l'IRQ UART (ou polling) */
void tty_input_char(char c) {
    task_t* reader = NULL;
    struct termios tio;
    unsigned long flags;

    spin_lock_irqsave(&tty0.lock, &flags);
    tio = tty0.termios;

    if (!tty_normalize_input_char(&tio, &c)) {
        spin_unlock_irqrestore(&tty0.lock, flags);
        return;
    }

    if (tty_handle_signal_char_locked(&tio, c, &flags)) {
        spin_unlock_irqrestore(&tty0.lock, flags);
        return;
    }

    if (tty_handle_eof_locked(&tio, c, &reader)) {
        spin_unlock_irqrestore(&tty0.lock, flags);
        tty_wake_reader(reader);
        return;
    }

    if (tty_handle_canonical_edit_locked(&tio, c)) {
        spin_unlock_irqrestore(&tty0.lock, flags);
        return;
    }

    reader = tty_enqueue_input_char_locked(&tio, c);
    spin_unlock_irqrestore(&tty0.lock, flags);
    tty_wake_reader(reader);
}

ssize_t tty_read(char *buf, size_t count) {
    size_t read = 0;
    bool interbyte_timer_active = false;
    uint32_t interbyte_deadline = 0;
    unsigned long flags;

    if (count == 0)
        return 0;
    
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
            bool canon = (tio.c_lflag & ICANON) != 0;
            uint32_t vmin = tio.c_cc[VMIN];
            uint32_t timeout_ticks = (uint32_t)tio.c_cc[VTIME] * (TIMER_FREQ / 10);
            uint32_t deadline = 0;

            if (tty0.eof_pending) {
                tty0.eof_pending = false;
                spin_unlock_irqrestore(&tty0.lock, flags);
                break;
            }

            if (read > 0) {
                if (canon || vmin == 0 || read >= vmin ||
                    (interbyte_timer_active && get_system_ticks() >= interbyte_deadline)) {
                    spin_unlock_irqrestore(&tty0.lock, flags);
                    break;
                }
            }

            if (!current_task) {
                spin_unlock_irqrestore(&tty0.lock, flags);
                break;
            }

            if (!canon && vmin == 0 && timeout_ticks == 0) {
                spin_unlock_irqrestore(&tty0.lock, flags);
                break;
            }

            if (tty0.read_wait && tty0.read_wait != current_task) {
                if (tty0.read_wait->state != TASK_INTERRUPTIBLE) {
                    tty0.read_wait = NULL;
                    kernel_lifecycle_stats.tty_stale_waiters++;
                } else {
                    spin_unlock_irqrestore(&tty0.lock, flags);
                    yield();
                    continue;
                }
            }

            tty0.read_wait = current_task;
            task_set_interruptible(current_task);

            if (!canon && timeout_ticks > 0) {
                if (vmin == 0 && read == 0) {
                    deadline = get_system_ticks() + timeout_ticks;
                } else if (read > 0) {
                    if (!interbyte_timer_active) {
                        interbyte_timer_active = true;
                        interbyte_deadline = get_system_ticks() + timeout_ticks;
                    }
                    deadline = interbyte_deadline;
                }
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
            if (!canon && timeout_ticks > 0 && deadline && get_system_ticks() >= deadline) {
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
            uint32_t vmin = tio.c_cc[VMIN];
            uint32_t timeout_ticks = (uint32_t)tio.c_cc[VTIME] * (TIMER_FREQ / 10);

            if (vmin > 0 && read >= vmin)
                break;

            if (timeout_ticks > 0) {
                interbyte_timer_active = true;
                interbyte_deadline = get_system_ticks() + timeout_ticks;
            }

            continue;
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

static void tty_drain_output_limited(uint32_t budget)
{
    unsigned long flags;
    uint32_t drained = 0;

    spin_lock_irqsave(&tty0.lock, &flags);
    tty0.output_drain_calls++;
    spin_unlock_irqrestore(&tty0.lock, flags);

    while (drained < budget) {
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
            drained++;
        }
        spin_unlock_irqrestore(&tty0.lock, flags);

        if (!sent) {
            uart_set_tx_irq_enabled(true);
            return;
        }
    }

    spin_lock_irqsave(&tty0.lock, &flags);
    if (tty_output_empty_locked()) {
        spin_unlock_irqrestore(&tty0.lock, flags);
        uart_set_tx_irq_enabled(false);
    } else {
        spin_unlock_irqrestore(&tty0.lock, flags);
        uart_set_tx_irq_enabled(true);
    }
}

void tty_drain_output(void)
{
    tty_drain_output_limited(TTY_TX_DRAIN_BUDGET);
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
    file->type = FILE_TYPE_TTY;
    file->pos = 0;
    file->inode = NULL;

    if (name) {
        strncpy(file->name, name, sizeof(file->name) - 1);
        file->name[sizeof(file->name) - 1] = '\0';
    }

    return file;
}
