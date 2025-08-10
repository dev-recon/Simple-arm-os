#include <kernel/keyboard.h>
#include <kernel/task.h>
#include <kernel/interrupt.h>
#include <kernel/kernel.h>
#include <kernel/string.h>
#include <kernel/uart.h>
#include <kernel/signal.h>
#include <kernel/kernel.h>
#include <kernel/process.h>

/* Forward declarations de toutes les fonctions statiques */
static void add_to_wait_queue(task_t** queue, task_t* proc);
static void remove_from_wait_queue(task_t** queue, task_t* proc);
static void wake_up_wait_queue(task_t** queue);

/* Scancode to ASCII mapping for Mac FR (AZERTY) - version ASCII pure */
static char scancode_to_ascii_mac_fr[55] = {
    0,   27,  '&', 'e', '"', '\'', '(', '-', 'e', '_', 'c', 'a', ')', '=', '\b',
    '\t', 'a', 'z', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '^', '$', '\n',
    0,   'q', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'u', '`',
    0,   '<', 'w', 'x', 'c', 'v', 'b', 'n', ',', ';', ':', '!', 0
    /* Supprime le dernier '*' */
};

static char scancode_to_ascii_shift_mac_fr[55] = {
    0,   27,  '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'd', '+', '\b',
    '\t', 'A', 'Z', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '^', '*', '\n',
    0,   'Q', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'M', '%', 'L',
    0,   '>', 'W', 'X', 'C', 'V', 'B', 'N', '?', '.', '/', 'S', 0
    /* Supprime le dernier '*' */
};

static char scancode_to_ascii_option_mac_fr[55] = {
    0,   27,  0, '~', '#', '{', '[', '|', '`', '\\', '^', '@', ']', '}', '\b',
    '\t', 'a', 'A', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', 'E', '<', '\n',
    0,   'O', 'I', 'd', 'f', 'c', 'I', 'I', 'I', 'O', 'm', 'U', 0,
    0,   '<', ',', '~', 'c', 'v', 'i', 'n', '.', '>', '/', 'p', 0
    /* Supprime le dernier '*' */
};

static keyboard_state_t kbd_state = {0};

void init_keyboard(void)
{
    volatile uint32_t* kbd = (volatile uint32_t*)KBD_BASE;
    
    /* Reset keyboard */
    kbd[KBD_CTRL/4] = 0;
    
    /* Configure clock divisor */
    kbd[KBD_CLKDIV/4] = 8;
    
    /* Enable keyboard with interrupts */
    kbd[KBD_CTRL/4] = (1 << 2) | (1 << 4);
    
    /* Enable keyboard IRQ */
    enable_irq(IRQ_KEYBOARD);
    
    kbd_state.head = 0;
    kbd_state.tail = 0;
    kbd_state.waiters = NULL;
    
    uart_puts("Keyboard initialized (Mac FR layout - ASCII)\n");
}

void keyboard_irq_handler(void)
{
    volatile uint32_t* kbd = (volatile uint32_t*)KBD_BASE;
    uint8_t scancode;
    
    /* Check if data available */
    if (!(kbd[KBD_STAT/4] & (1 << 4))) {
        return;
    }
    
    scancode = kbd[KBD_DATA/4] & 0xFF;
    handle_scancode(scancode);
}

void handle_scancode(uint8_t scancode)
{
    bool key_released = (scancode & 0x80) != 0;
    uint8_t key = scancode & 0x7F;
    char ascii;
    
    if (key_released) {
        /* Key released */
        switch (key) {
            case 0x2A: case 0x36: /* Shift */
                kbd_state.shift_pressed = false;
                break;
            case 0x1D: /* Ctrl */
                kbd_state.ctrl_pressed = false;
                break;
            case 0x38: /* Alt/Option */
                kbd_state.opt_pressed = false;
                break;
            case 0x5B: case 0x5C: /* Cmd (Windows keys on PC) */
                kbd_state.cmd_pressed = false;
                break;
            case 0x3A: /* Fn (some layouts) */
                kbd_state.fn_pressed = false;
                break;
        }
        return;
    }
    
    /* Key pressed */
    switch (key) {
        case 0x2A: case 0x36: /* Shift */
            kbd_state.shift_pressed = true;
            break;
        case 0x1D: /* Ctrl */
            kbd_state.ctrl_pressed = true;
            break;
        case 0x38: /* Alt/Option */
            kbd_state.opt_pressed = true;
            break;
        case 0x5B: case 0x5C: /* Cmd */
            kbd_state.cmd_pressed = true;
            break;
        case 0x3A: /* Caps Lock */
            kbd_state.caps_lock = !kbd_state.caps_lock;
            break;
        case 0x57: case 0x58: /* Fn */
            kbd_state.fn_pressed = true;
            break;
        default:
            /* Convert to ASCII */
            ascii = convert_to_ascii_mac_fr(key);
            if (ascii) {
                add_to_keyboard_buffer(ascii);
            }
            break;
    }
}

char convert_to_ascii_mac_fr(uint8_t scancode)
{
    char ascii;
    bool use_shift;
    
    if (scancode >= 55) return 0; /* Limite aux 54 premiers scancodes */
    
    use_shift = kbd_state.shift_pressed;
    
    /* Caps Lock affects letters */
    if (kbd_state.caps_lock && scancode >= 0x10 && scancode <= 0x32) {
        use_shift = !use_shift;
    }
    
    /* Option key combinations (accents, special chars) */
    if (kbd_state.opt_pressed) {
        ascii = scancode_to_ascii_option_mac_fr[scancode];
        if (ascii) return ascii;
    }
    
    /* Regular character mapping */
    ascii = use_shift ? scancode_to_ascii_shift_mac_fr[scancode] : 
                       scancode_to_ascii_mac_fr[scancode];
    
    /* Ctrl combinations */
    if (kbd_state.ctrl_pressed && ascii >= 'a' && ascii <= 'z') {
        ascii = ascii - 'a' + 1;
    } else if (kbd_state.ctrl_pressed && ascii >= 'A' && ascii <= 'Z') {
        ascii = ascii - 'A' + 1;
    }
    
    return ascii;
}

void add_to_keyboard_buffer(char c)
{
    uint32_t next_head = (kbd_state.head + 1) % 256;
    
    if (next_head != kbd_state.tail) {
        kbd_state.buffer[kbd_state.head] = c;
        kbd_state.head = next_head;
        
        /* Wake up waiting processes */
        wake_up_wait_queue(&kbd_state.waiters);
    }
}

char keyboard_getchar(void)
{
    char c;
    
    /* Wait for character */
    while (kbd_state.head == kbd_state.tail) {
        add_to_wait_queue(&kbd_state.waiters, current_task);
        current_task->state = TASK_BLOCKED;
        schedule();
        
        /* Check for signals */
        if (has_pending_signals(current_task)) {
            remove_from_wait_queue(&kbd_state.waiters, current_task);
            return -1;
        }
    }
    
    /* Get character */
    c = kbd_state.buffer[kbd_state.tail];
    kbd_state.tail = (kbd_state.tail + 1) % 256;
    
    return c;
}

/* Wait queue helper functions */
static void add_to_wait_queue(task_t** queue, task_t* proc)
{
    proc->next = *queue;
    *queue = proc;
}

static void remove_from_wait_queue(task_t** queue, task_t* proc)
{
    task_t* current;
    
    if (*queue == proc) {
        *queue = proc->next;
    } else {
        current = *queue;
        while (current && current->next != proc) {
            current = current->next;
        }
        if (current) {
            current->next = proc->next;
        }
    }
}

static void wake_up_wait_queue(task_t** queue)
{
    task_t* proc = *queue;
    task_t* next;
    
    while (proc) {
        next = proc->next;
        if (proc->state == TASK_BLOCKED) {
            proc->state = TASK_READY;
            add_to_ready_queue(proc);
        }
        proc = next;
    }
    *queue = NULL;
}