#ifndef DEBUG_PRINT_H
#define DEBUG_PRINT_H

#include <kernel/types.h>

void debug_print_hex(const char* prefix, uint32_t value);
void debug_print_dec(const char* prefix, uint32_t value);
void simple_kprintf(const char* msg);

#endif
