/* kernel/lib/debug_print.c - Version debug sans conflit */
#include <kernel/types.h>
#include <kernel/uart.h>
#include <kernel/kprintf.h>

/* Fonction simple qui fonctionne a coup s-r */
void debug_print_hex(const char* prefix, uint32_t value)
{
    KDEBUG("%s0x%x\n", prefix, value);
}

void debug_print_dec(const char* prefix, uint32_t value)
{
    KDEBUG("%s%d\n", prefix, value);
}

/* Version kprintf simple qui marche */
void simple_kprintf(const char* msg)
{
    KDEBUG("[SIMPLE] %s\n", msg);
}
