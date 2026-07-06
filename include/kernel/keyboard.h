/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/keyboard.h
 * Layer: Kernel / terminal and character devices
 *
 * Responsibilities:
 * - Drive UART/framebuffer console backends and TTY line discipline.
 * - Preserve canonical/raw terminal semantics and job-control signals.
 *
 * Notes:
 * - tty0/UART must remain a reliable fallback path.
 */

#ifndef _KERNEL_KEYBOARD_H
#define _KERNEL_KEYBOARD_H

#include <kernel/arch_platform.h>
#include <kernel/types.h>
#include <kernel/task.h>

/* Legacy PL050 keyboard fallback selected by the current platform. */
#define KBD_BASE        VIRT_PL050_KBD_BASE
#define KBD_DATA        (KBD_BASE + 0x00u)
#define KBD_STAT        (KBD_BASE + 0x04u)
#define KBD_CTRL        (KBD_BASE + 0x08u)
#define KBD_CLKDIV      (KBD_BASE + 0x0Cu)
#define KBD_IRQ         (KBD_BASE + 0x10u)

typedef struct {
    bool shift_pressed;
    bool ctrl_pressed;
    bool alt_pressed;
    bool caps_lock;
    bool fn_pressed;        /* Mac Fn key */
    bool cmd_pressed;       /* Mac Command key */
    bool opt_pressed;       /* Mac Option key */
    
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
