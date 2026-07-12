/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 * SPDX-License-Identifier: Apache-2.0
 *
 * AArch64 milestone 1 PL011 console for QEMU virt.
 */

#include <asm/early_console.h>
#include <asm/irq.h>
#include <asm/mmu.h>
#include <kernel/early_page_allocator.h>
#include <kernel/fdt.h>

#define PL011_BASE 0x09000000UL
#define PL011_DR   0x000
#define PL011_FR   0x018
#define PL011_FR_TXFF (1u << 5)

#define EARLY_ALLOC_MAX_RAM      0x40000000ULL
#define EARLY_ALLOC_MAX_PAGES    (EARLY_ALLOC_MAX_RAM / PAGE_SIZE)
#define EARLY_ALLOC_BITMAP_BYTES ((EARLY_ALLOC_MAX_PAGES + 7u) / 8u)

extern uint8_t __kernel_end[];

static early_page_allocator_t early_allocator;
static uint8_t early_allocator_bitmap[EARLY_ALLOC_BITMAP_BYTES]
    __attribute__((aligned(ARCH_CACHE_LINE_SIZE)));

static inline void mmio_write32(unsigned long address, uint32_t value)
{
    *(volatile uint32_t *)address = value;
}

static inline uint32_t mmio_read32(unsigned long address)
{
    return *(volatile uint32_t *)address;
}

void arm64_early_putc(char c)
{
    if (c == '\n')
        arm64_early_putc('\r');

    while (mmio_read32(PL011_BASE + PL011_FR) & PL011_FR_TXFF)
        __asm__ volatile("yield");

    mmio_write32(PL011_BASE + PL011_DR, (uint32_t)c);
}

void arm64_early_puts(const char *text)
{
    while (*text)
        arm64_early_putc(*text++);
}

void arm64_early_puthex64(arm64_early_u64 value)
{
    static const char digits[] = "0123456789ABCDEF";

    arm64_early_puts("0x");
    for (int shift = 60; shift >= 0; shift -= 4)
        arm64_early_putc(digits[(value >> shift) & 0xfu]);
}

static uint64_t current_el(void)
{
    uint64_t value;

    __asm__ volatile("mrs %0, CurrentEL" : "=r"(value));
    return (value >> 2) & 3u;
}

static int test_early_page_allocator(uint64_t dtb_address)
{
    static const uint64_t first_magic = 0x41524D4F53504147ULL;
    static const uint64_t last_magic = 0x45414C4C4F434F4BULL;
    fdt_memory_layout_t layout;
    fdt_memory_range_t *ram = NULL;
    paddr_t one_page;
    paddr_t three_pages;
    paddr_t recycled_page;
    paddr_t kernel_end = (paddr_t)(uintptr_t)__kernel_end;
    paddr_t ram_end;
    uint32_t initial_free;
    uint32_t reserved_before;
    uint32_t index;

    if (!fdt_read_memory_layout((void *)(uintptr_t)dtb_address, &layout))
        return -1;

    for (index = 0; index < layout.memory_count; index++) {
        paddr_t candidate_end = layout.memory[index].start +
                                layout.memory[index].size;
        if (kernel_end >= layout.memory[index].start &&
            kernel_end < candidate_end) {
            ram = &layout.memory[index];
            break;
        }
    }
    if (!ram || ram->size > EARLY_ALLOC_MAX_RAM)
        return -1;

    ram_end = ram->start + ram->size;

    if (early_page_allocator_init(&early_allocator,
                                  kernel_end,
                                  ram_end,
                                  early_allocator_bitmap,
                                  sizeof(early_allocator_bitmap)) != 0)
        return -1;

    reserved_before = early_allocator.free_pages;
    for (index = 0; index < layout.reserved_count; index++) {
        paddr_t reserved_end = layout.reserved[index].start +
                               layout.reserved[index].size;
        if (early_page_reserve(&early_allocator,
                               layout.reserved[index].start,
                               reserved_end) != 0)
            return -1;
    }
    if (layout.dtb_size == 0 || early_allocator.free_pages >= reserved_before)
        return -1;

    if (early_page_reserve(&early_allocator,
                           early_allocator.base,
                           early_allocator.base + PAGE_SIZE) != 0)
        return -1;

    initial_free = early_allocator.free_pages;
    if (early_page_alloc_pages(&early_allocator, 1, &one_page) != 0 ||
        early_page_alloc_pages(&early_allocator, 3, &three_pages) != 0)
        return -1;
    if ((one_page & PAGE_OFFSET_MASK) != 0 ||
        (three_pages & PAGE_OFFSET_MASK) != 0 ||
        one_page == three_pages ||
        one_page != early_allocator.base + PAGE_SIZE)
        return -1;

    *(volatile uint64_t *)(uintptr_t)one_page = first_magic;
    *(volatile uint64_t *)(uintptr_t)three_pages = first_magic;
    *(volatile uint64_t *)(uintptr_t)(three_pages + (3 * PAGE_SIZE) - 8) = last_magic;
    if (*(volatile uint64_t *)(uintptr_t)one_page != first_magic ||
        *(volatile uint64_t *)(uintptr_t)three_pages != first_magic ||
        *(volatile uint64_t *)(uintptr_t)(three_pages + (3 * PAGE_SIZE) - 8) != last_magic)
        return -1;

    if (early_page_free_pages(&early_allocator, one_page, 1) != 0 ||
        early_page_alloc_pages(&early_allocator, 1, &recycled_page) != 0 ||
        recycled_page != one_page)
        return -1;

    arm64_early_puts("Early pages: base=");
    arm64_early_puthex64(early_allocator.base);
    arm64_early_puts(" end=");
    arm64_early_puthex64(early_allocator.end);
    arm64_early_puts(" total=");
    arm64_early_puthex64(early_allocator.total_pages);
    arm64_early_puts(" free=");
    arm64_early_puthex64(early_allocator.free_pages);
    arm64_early_puts("\n");
    arm64_early_puts("FDT RAM: base=");
    arm64_early_puthex64(ram->start);
    arm64_early_puts(" size=");
    arm64_early_puthex64(ram->size);
    arm64_early_puts(" DTB size=");
    arm64_early_puthex64(layout.dtb_size);
    arm64_early_puts(" reserved ranges=");
    arm64_early_puthex64(layout.reserved_count);
    arm64_early_puts("\n");
    arm64_early_puts("ARM64_FDT_MEMORY_OK\n");

    if (early_page_free_pages(&early_allocator, recycled_page, 1) != 0 ||
        early_page_free_pages(&early_allocator, three_pages, 3) != 0 ||
        early_allocator.free_pages != initial_free)
        return -1;

    return 0;
}

void arm64_early_main(uint64_t dtb_address)
{
    arm64_mmu_u64 par_uart;
    arm64_mmu_u64 par_kernel;
    arm64_mmu_u64 par_unmapped;

    arm64_early_puts("\nArmOS ARM64 bring-up\n");
    arm64_early_puts("Architecture: AArch64\n");
    arm64_early_puts("Current EL: EL");
    arm64_early_putc((char)('0' + current_el()));
    arm64_early_puts("\nDTB: ");
    arm64_early_puthex64(dtb_address);
    arm64_early_puts("\nARM64_BOOT_OK\n");

    arm64_early_puts("Testing EL1 synchronous vector with BRK #0x64\n");
    __asm__ volatile("brk #0x64");
    arm64_early_puts("ARM64_EXCEPTION_RETURN_OK\n");

    arm64_early_puts("Enabling ARMv8 4K identity MMU\n");
    if (arm64_mmu_enable_identity_map() != 0) {
        arm64_early_puts("ARM64_MMU_FAILED\n");
        return;
    }

    arm64_early_puts("SCTLR_EL1: ");
    arm64_early_puthex64(arm64_mmu_read_sctlr());
    arm64_early_puts("\nTCR_EL1: ");
    arm64_early_puthex64(arm64_mmu_read_tcr());
    arm64_early_puts("\nTTBR0_EL1: ");
    arm64_early_puthex64(arm64_mmu_read_ttbr0());
    arm64_early_puts("\n");

    par_uart = arm64_mmu_translate_read(PL011_BASE);
    par_kernel = arm64_mmu_translate_read(0x40080000ULL);
    par_unmapped = arm64_mmu_translate_read(0x80000000ULL);

    arm64_early_puts("PAR UART: ");
    arm64_early_puthex64(par_uart);
    arm64_early_puts(" kernel: ");
    arm64_early_puthex64(par_kernel);
    arm64_early_puts(" unmapped: ");
    arm64_early_puthex64(par_unmapped);
    arm64_early_puts("\n");

    if ((par_uart & 1u) == 0 &&
        (par_kernel & 1u) == 0 &&
        (par_unmapped & 1u) != 0) {
        arm64_early_puts("ARM64_MMU_OK\n");
        arm64_early_puts("Testing synchronous vector with MMU enabled\n");
        __asm__ volatile("brk #0x64");
        arm64_early_puts("ARM64_MMU_EXCEPTION_OK\n");
        arm64_early_puts("Testing GICv2 physical timer PPI 30\n");
        if (arm64_timer_irq_smoke_test() != 0)
            arm64_early_puts("ARM64_TIMER_IRQ_FAILED\n");
        else if (test_early_page_allocator(dtb_address) != 0)
            arm64_early_puts("ARM64_PHYS_ALLOC_FAILED\n");
        else
            arm64_early_puts("ARM64_PHYS_ALLOC_OK\n");
    } else {
        arm64_early_puts("ARM64_MMU_TRANSLATION_FAILED\n");
    }
}
