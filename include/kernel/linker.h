/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/linker.h
 * Layer: Kernel / linker script interface
 *
 * Responsibilities:
 * - Declare symbols exported by the active kernel linker script.
 * - Provide typed helpers for kernel section, stack, heap, and free-RAM bounds.
 *
 * Notes:
 * - This header is intentionally architecture-neutral. Each architecture may use
 *   its own linker script, but the C kernel sees the same symbol contract.
 */

#ifndef _KERNEL_LINKER_H
#define _KERNEL_LINKER_H

#include <kernel/types.h>

/* Kernel image bounds exported by the linker script. */
extern uint32_t __start;
extern uint32_t __end;
extern uint32_t __kernel_start;
extern uint32_t __kernel_end;
extern uint32_t __kernel_size;
extern uint32_t __kernel_phys_start;
extern uint32_t __kernel_phys_end;

/* Kernel sections. */
extern uint32_t __text_start;
extern uint32_t __text_end;
extern uint32_t __rodata_start;
extern uint32_t __rodata_end;
extern uint32_t __data_start;
extern uint32_t __data_end;
extern uint32_t __bss_start;
extern uint32_t __bss_end;

/* Kernel stack, heap, and free-RAM boundaries. */
extern uint32_t __stack_bottom;
extern uint32_t __stack_top;
extern uint32_t stack_bottom;
extern uint32_t stack_top;
extern uint32_t __heap_start;
extern uint32_t __heap_end;
extern uint32_t __heap_size;
extern uint32_t __ram_start;
extern uint32_t __ram_end;
extern uint32_t __ram_size;
extern uint32_t __free_memory_start;

extern uint32_t __stack_svc_top;

#define KERNEL_START            ((vaddr_t)(uintptr_t)&__start)
#define KERNEL_END              ((vaddr_t)(uintptr_t)&__end)
#define KERNEL_SIZE             ((size_t)(uintptr_t)&__kernel_size)
#define KERNEL_BASE             KERNEL_START

#define KERNEL_PHYSICAL_START   \
    ((paddr_t)(uintptr_t)&__kernel_phys_start)
#define KERNEL_PHYSICAL_END     \
    ((paddr_t)(uintptr_t)&__kernel_phys_end)
#define KERNEL_PHYSICAL_SIZE    \
    ((size_t)(KERNEL_PHYSICAL_END - KERNEL_PHYSICAL_START))

#define KERNEL_TEXT_START       ((vaddr_t)(uintptr_t)&__text_start)
#define KERNEL_TEXT_END         ((vaddr_t)(uintptr_t)&__text_end)
#define KERNEL_DATA_START       ((vaddr_t)(uintptr_t)&__data_start)
#define KERNEL_DATA_END         ((vaddr_t)(uintptr_t)&__data_end)
#define KERNEL_BSS_START        ((vaddr_t)(uintptr_t)&__bss_start)
#define KERNEL_BSS_END          ((vaddr_t)(uintptr_t)&__bss_end)

#define KERNEL_STACK_BOTTOM     ((vaddr_t)(uintptr_t)&__stack_bottom)
#define KERNEL_STACK_TOP        ((vaddr_t)(uintptr_t)&__stack_top)
#define KERNEL_STACK_SIZE       (KERNEL_STACK_TOP - KERNEL_STACK_BOTTOM)

#define KERNEL_HEAP_START       ((vaddr_t)(uintptr_t)&__heap_start)
#define KERNEL_HEAP_END         ((vaddr_t)(uintptr_t)&__heap_end)
#define KERNEL_HEAP_SIZE        ((size_t)(uintptr_t)&__heap_size)

#define PHYSICAL_RAM_START      ((paddr_t)(uintptr_t)&__ram_start)
#define PHYSICAL_RAM_END        ((paddr_t)(uintptr_t)&__ram_end)
#define PHYSICAL_RAM_SIZE       ((size_t)(uintptr_t)&__ram_size)
#define FREE_MEMORY_START       ((paddr_t)(uintptr_t)&__free_memory_start)

#define KERNEL_SVC_STACK_TOP    ((vaddr_t)(uintptr_t)&__stack_svc_top)

/* Compatibility aliases used by older allocator and boot code. */
#define HEAP_START              KERNEL_HEAP_START
#define HEAP_END                KERNEL_HEAP_END
#define HEAP_SIZE               KERNEL_HEAP_SIZE
#define RAM_START               PHYSICAL_RAM_START
#define RAM_END                 PHYSICAL_RAM_END
#define RAM_SIZE                PHYSICAL_RAM_SIZE

#endif /* _KERNEL_LINKER_H */
