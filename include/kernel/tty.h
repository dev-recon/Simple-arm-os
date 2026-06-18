/* kernel/drivers/tty.h */
#ifndef _TTY_H
#define _TTY_H

#include <kernel/types.h>
#include <kernel/spinlock.h>
#include <kernel/task.h>

#define TTY_INPUT_BUF_SIZE  512
#define TTY_OUTPUT_BUF_SIZE 512

#define TTY_STTY_SET_FOREGROUND_PGID 1
#define TTY_GTTY_GET_FOREGROUND_PGID 1

#define NCCS 32

#define VMIN  16
#define VTIME 17

typedef uint32_t tcflag_t;
typedef uint8_t cc_t;
typedef uint32_t speed_t;

struct termios {
    tcflag_t c_iflag;
    tcflag_t c_oflag;
    tcflag_t c_cflag;
    tcflag_t c_lflag;
    cc_t c_line;
    cc_t c_cc[NCCS];
    speed_t c_ispeed;
    speed_t c_ospeed;
};

struct tty_struct {
    /* Buffers circulaires */
    char input_buf[TTY_INPUT_BUF_SIZE];
    uint32_t input_head;
    uint32_t input_tail;
    
    /* Flags */
    uint32_t c_lflag;  /* Local flags */
    pid_t foreground_pgid;
    
    /* Wait queue pour read bloquant */
    task_t *read_wait;

    /* Diagnostic counters for long-idle / foreground signal issues. */
    uint32_t input_chars;
    uint32_t ctrl_c_seen;
    uint32_t ctrl_z_seen;
    uint32_t sigint_delivered;
    uint32_t sigint_missed;
    uint32_t sigtstp_delivered;
    uint32_t sigtstp_missed;
    pid_t last_signal_pgid;
    int last_signal;
    int last_signal_delivered;
    
    spinlock_t lock;
};

/* Flags pour c_lflag */
#define ECHO    0x0001
#define ICANON  0x0002  /* Mode ligne (buffering jusqu'à \n) */
#define ISIG    0x0004  /* Generer SIGINT/SIGTSTP depuis les caracteres de controle */
#define IEXTEN  0x0008

extern struct tty_struct tty0;

void tty_init(void);
void tty_input_char(char c);
ssize_t tty_read(char *buf, size_t count);
ssize_t tty_write(const char *buf, size_t count);
int tty_get_termios(struct termios *tio);
int tty_set_termios(const struct termios *tio, int flush_input);
int tty_set_foreground_pgid(pid_t pgid);
pid_t tty_get_foreground_pgid(void);
pid_t tty_get_read_wait_pid(void);
int tty_get_read_wait_state(void);
file_t* create_tty_console_file(const char* name, int flags);

#endif
