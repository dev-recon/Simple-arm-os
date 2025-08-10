#ifndef _KERNEL_KEYBOARD_H
#define _KERNEL_KEYBOARD_H

#include <kernel/types.h>
#include <kernel/task.h>

/* PL050 Keyboard */
#define KBD_BASE        0x09060000
#define KBD_DATA        (KBD_BASE + 0x00)
#define KBD_STAT        (KBD_BASE + 0x04)
#define KBD_CTRL        (KBD_BASE + 0x08)
#define KBD_CLKDIV      (KBD_BASE + 0x0C)
#define KBD_IRQ         (KBD_BASE + 0x10)

typedef struct {
    bool shift_pressed;
    bool ctrl_pressed;
    bool alt_pressed;
    bool caps_lock;
    bool fn_pressed;        /* Pour Mac */
    bool cmd_pressed;       /* Touche Cmd Mac */
    bool opt_pressed;       /* Touche Option Mac */
    
    char buffer[256];
    uint32_t head;
    uint32_t tail;
    
    task_t * waiters;
} keyboard_state_t;

/* Keyboard functions */
void init_keyboard(void);
void keyboard_irq_handler(void);
void handle_scancode(uint8_t scancode);
char convert_to_ascii_mac_fr(uint8_t scancode);
void add_to_keyboard_buffer(char c);
char keyboard_getchar(void);
void keyboard_irq_handler(void);

#endif