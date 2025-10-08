/* kernel/drivers/tty.h */
#ifndef _TTY_H
#define _TTY_H

#include <kernel/types.h>
#include <kernel/spinlock.h>
#include <kernel/task.h>

#define TTY_INPUT_BUF_SIZE  512
#define TTY_OUTPUT_BUF_SIZE 512

struct tty_struct {
    /* Buffers circulaires */
    char input_buf[TTY_INPUT_BUF_SIZE];
    uint32_t input_head;
    uint32_t input_tail;
    
    /* Flags */
    uint32_t c_lflag;  /* Local flags */
    
    /* Wait queue pour read bloquant */
    task_t *read_wait;
    
    spinlock_t lock;
};

/* Flags pour c_lflag */
#define ECHO    0x0001
#define ICANON  0x0002  /* Mode ligne (buffering jusqu'à \n) */

extern struct tty_struct tty0;

void tty_init(void);
void tty_input_char(char c);
ssize_t tty_read(char *buf, size_t count);
ssize_t tty_write(const char *buf, size_t count);

#endif