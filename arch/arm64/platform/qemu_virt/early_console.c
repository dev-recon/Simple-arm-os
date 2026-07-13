/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/platform/qemu_virt/early_console.c
 * Layer: ARM64 / QEMU virt bring-up
 *
 * Responsibilities:
 * - Drive the early PL011 console and sequence AArch64 boot milestones.
 * - Validate MMU, exceptions, timer IRQs, user VMs and context switching.
 * - Run the EL0 syscall ABI payload and report stable serial markers.
 *
 * Notes:
 * - This file intentionally hosts bounded bring-up probes before generic
 *   kernel subsystems are enabled for ARM64.
 */

#include <asm/early_console.h>
#include <asm/exception.h>
#include <asm/irq.h>
#include <asm/mmu.h>
#include <asm/task.h>
#include <asm/task_context.h>
#include <asm/user_vm.h>
#include <kernel/early_page_allocator.h>
#include <kernel/fdt.h>
#include <kernel/task.h>
#include <uapi/armos/syscall.h>

#define PL011_BASE 0x09000000UL
#define PL011_DR   0x000
#define PL011_FR   0x018
#define PL011_FR_TXFF (1u << 5)

#define EARLY_ALLOC_MAX_RAM      0x40000000ULL
#define EARLY_ALLOC_MAX_PAGES    (EARLY_ALLOC_MAX_RAM / PAGE_SIZE)
#define EARLY_ALLOC_BITMAP_BYTES ((EARLY_ALLOC_MAX_PAGES + 7u) / 8u)
#define PAR_PA_MASK              0x0000FFFFFFFFF000ULL
#define TTBR_TABLE_MASK          0x0000FFFFFFFFF000ULL
#define TTBR_ASID_SHIFT          48u
#define USER_CODE_VA             0x0000000000400000ULL
#define USER_DATA_VA             0x0000000000401000ULL
#define USER_STACK_VA            0x0000000000402000ULL
#define PROBE_USER_STACK_TOP     0x0000000000403000ULL
#define USER_WRITE_RESULT_OFFSET 0x100u
#define USER_EFAULT_RESULT_OFFSET 0x108u
#define USER_ENOSYS_RESULT_OFFSET 0x110u
#define USER_EXIT_PC_OFFSET        0x118u
#define USER_VM_MAGIC_OFFSET     0x200u
#define USER_TEST_MAGIC          0x5553455254544252ULL
#define USER_WRITE_LENGTH        23u
#define USER_EXIT_STATUS         42u
#define USER_EFAULT_RESULT       0xFFFFFFFFFFFFFFF2ULL
#define USER_ENOSYS_RESULT       0xFFFFFFFFFFFFFFDAULL
#define USER_X19_SENTINEL         0x1919191919191919ULL
#define USER_X20_SENTINEL         0x2020202020202020ULL
#define USER_X29_SENTINEL         0x2929292929292929ULL
#define USER_X30_SENTINEL         0x3030303030303030ULL
#define TASK_X22_SENTINEL         0x2222222222222222ULL
#define TASK_X23_SENTINEL         0x2323232323232323ULL
#define TASK_PROBE_STACK_PAGES    1u

static const char arm64_user_message[] = "ARM64 syscall write OK\n";
_Static_assert(sizeof(arm64_user_message) - 1 == USER_WRITE_LENGTH,
               "EL0 write payload length must match its assembly constant");

extern uint8_t arm64_vectors[];
extern uint8_t arm64_el0_payload_start[];
extern uint8_t arm64_el0_payload_end[];

extern void arm64_enter_high_alias(uint64_t entry,
                                   uint64_t stack,
                                   uint64_t vectors,
                                   uint64_t context)
    __attribute__((noreturn));
extern void arm64_enter_el0(const arm64_user_context_t *registers)
    __attribute__((noreturn));

typedef struct {
    paddr_t boot_l1;
    arm64_user_vm_t user_vm;
    arm64_user_vm_t empty_vm;
    arm64_task_context_t user_task;
    arm64_task_context_t bootstrap_task;
    task_t probe_task;
    volatile uint64_t task_probe_phase;
    volatile uint64_t task_probe_ttbr0;
} arm64_high_context_t;

static early_page_allocator_t early_allocator;
static uint8_t early_allocator_bitmap[EARLY_ALLOC_BITMAP_BYTES]
    __attribute__((aligned(ARCH_CACHE_LINE_SIZE)));
static arm64_high_context_t high_context;

static void arm64_high_main(arm64_high_context_t *context)
    __attribute__((noreturn));
static void arm64_el0_return(uint64_t result)
    __attribute__((noreturn));

static void prepare_user_registers(arm64_user_context_t *registers)
{
    unsigned int index;

    for (index = 0; index < 31; index++)
        registers->x[index] = 0;
    registers->x[19] = USER_X19_SENTINEL;
    registers->x[20] = USER_X20_SENTINEL;
    registers->x[29] = USER_X29_SENTINEL;
    registers->x[30] = USER_X30_SENTINEL;
    registers->sp = PROBE_USER_STACK_TOP;
    registers->pc = USER_CODE_VA;
    registers->pstate = ARM64_USER_PSTATE_EL0T_MASKED;
}

static void clear_task_context(arm64_task_context_t *task)
{
    uint64_t *words = (uint64_t *)task;
    unsigned int index;

    for (index = 0; index < sizeof(*task) / sizeof(*words); index++)
        words[index] = 0;
}

static early_page_allocator_t *high_early_allocator(void)
{
    early_page_allocator_t *allocator = &early_allocator;

    if ((uint64_t)(uintptr_t)allocator->bitmap < ARM64_KERNEL_VA_BASE) {
        allocator->bitmap = (uint8_t *)(uintptr_t)
            arm64_mmu_kernel_address(
                (uint64_t)(uintptr_t)allocator->bitmap);
    }
    return allocator;
}

static int task_probe_metadata_valid(const task_t *task)
{
    vaddr_t stack_base;
    vaddr_t stack_top;
    paddr_t stack_physical;

    if (!task)
        return 0;
    stack_base = (vaddr_t)(uintptr_t)task->stack_base;
    stack_top = (vaddr_t)(uintptr_t)task->stack_top;
    stack_physical = (paddr_t)(uintptr_t)task->stack_phys_base;

    return task->magic == TASK_MAGIC_ALIVE &&
           task->task_id == 1 &&
           task->state == TASK_BLOCKED &&
           task->priority == TASK_DEFAULT_PRIORITY &&
           task->type == TASK_TYPE_KERNEL &&
           task->running_cpu == TASK_CPU_NONE &&
           task->last_cpu == TASK_CPU_NONE &&
           task->name[0] == 'c' &&
           task->stack_size == TASK_PROBE_STACK_PAGES * PAGE_SIZE &&
           stack_base >= ARM64_KERNEL_VA_BASE &&
           stack_top == stack_base + task->stack_size &&
           task->context.kernel.sp == stack_top &&
           (stack_physical & PAGE_OFFSET_MASK) == 0;
}

static int prepare_task_probe(arm64_high_context_t *context,
                              const arm64_user_vm_t *user_vm)
{
    arm64_task_context_t *bootstrap = &context->bootstrap_task;
    arm64_task_context_t *probe;

    clear_task_context(bootstrap);
    context->task_probe_phase = 0;
    context->task_probe_ttbr0 = 0;

    if (arm64_task_init(
            &context->probe_task,
            high_early_allocator(),
            user_vm,
            (vaddr_t)(uintptr_t)arm64_task_context_probe_entry,
            "context-probe",
            1,
            TASK_PROBE_STACK_PAGES) != 0)
        return -1;
    probe = &context->probe_task.context;
    if (!task_probe_metadata_valid(&context->probe_task) ||
        arm64_task_destroy(&context->probe_task,
                           high_early_allocator(), probe) != -2) {
        arm64_task_destroy(&context->probe_task,
                           high_early_allocator(), bootstrap);
        return -2;
    }
    probe->kernel.x[0] = (uint64_t)(uintptr_t)probe;
    probe->kernel.x[1] = (uint64_t)(uintptr_t)bootstrap;
    probe->kernel.x[2] =
        (uint64_t)(uintptr_t)&context->task_probe_phase;
    probe->kernel.x[3] = TASK_X22_SENTINEL;
    probe->kernel.x[4] = TASK_X23_SENTINEL;
    probe->kernel.x[5] =
        (uint64_t)(uintptr_t)&context->task_probe_ttbr0;
    if (probe->kernel.pc < ARM64_KERNEL_VA_BASE ||
        probe->kernel.sp < ARM64_KERNEL_VA_BASE) {
        arm64_task_destroy(&context->probe_task,
                           high_early_allocator(), bootstrap);
        return -3;
    }

    return 0;
}

static int arm64_task_context_smoke_test(arm64_high_context_t *context)
{
    arm64_task_context_t *bootstrap = &context->bootstrap_task;
    arm64_task_context_t *probe;
    early_page_allocator_t *allocator = high_early_allocator();
    uint64_t free_before = allocator->free_pages;
    int result = 0;

    if (prepare_task_probe(context, NULL) != 0)
        return -1;
    probe = &context->probe_task.context;

    if (arm64_task_context_switch_address_space(bootstrap, probe) != 0)
        result = -2;
    if (result == 0 &&
        (context->task_probe_phase != 1 ||
        probe->kernel.x[3] != TASK_X22_SENTINEL ||
        probe->kernel.x[4] != TASK_X23_SENTINEL ||
        bootstrap->kernel.pc < ARM64_KERNEL_VA_BASE ||
        bootstrap->kernel.sp < ARM64_KERNEL_VA_BASE))
        result = -3;

    if (result == 0) {
        context->task_probe_phase = 2;
        if (arm64_task_context_switch_address_space(bootstrap, probe) != 0)
            result = -4;
        if (result == 0 &&
            (context->task_probe_phase != 3 ||
            probe->kernel.x[3] != TASK_X22_SENTINEL ||
            probe->kernel.x[4] != TASK_X23_SENTINEL))
            result = -5;
    }

    if (arm64_task_destroy(&context->probe_task, allocator, bootstrap) != 0)
        return -6;
    if (context->probe_task.magic != TASK_MAGIC_DEAD)
        return -7;
    if (allocator->free_pages != free_before)
        return -8;
    return result;
}

static int arm64_task_address_space_smoke_test(
    arm64_high_context_t *context,
    uint64_t user_ttbr,
    uint64_t empty_ttbr)
{
    arm64_task_context_t *bootstrap = &context->bootstrap_task;
    arm64_task_context_t *probe;
    uint64_t flush_before;
    uint64_t preserve_before;
    early_page_allocator_t *allocator = high_early_allocator();
    uint64_t free_before = allocator->free_pages;
    int result = 0;

    if (prepare_task_probe(context, &context->empty_vm) != 0)
        return -1;
    probe = &context->probe_task.context;

    bootstrap->user_vm = &context->user_vm;
    bootstrap->ttbr0 = context->user_vm.l1;
    bootstrap->asid = context->user_vm.asid;
    probe->ttbr0 = context->user_vm.l1;
    probe->asid = context->empty_vm.asid;
    if (arm64_task_context_switch_address_space(bootstrap, probe) == 0 ||
        context->task_probe_phase != 0)
        result = -2;

    probe->ttbr0 = context->empty_vm.l1;
    flush_before = arm64_user_vm_tlb_flush_count();
    preserve_before = arm64_user_vm_tlb_preserve_count();

    if (result == 0) {
        if (arm64_mmu_read_ttbr0() != user_ttbr ||
            arm64_task_context_switch_address_space(bootstrap, probe) != 0)
            result = -3;
        if (result == 0 &&
            (context->task_probe_phase != 1 ||
            context->task_probe_ttbr0 != empty_ttbr ||
            arm64_mmu_read_ttbr0() != user_ttbr))
            result = -4;
    }

    if (result == 0) {
        context->task_probe_phase = 2;
        if (arm64_task_context_switch_address_space(bootstrap, probe) != 0)
            result = -5;
        if (result == 0 &&
            (context->task_probe_phase != 3 ||
            context->task_probe_ttbr0 != empty_ttbr ||
            arm64_mmu_read_ttbr0() != user_ttbr ||
            (arm64_mmu_translate_user_read(USER_DATA_VA) & 1u) != 0))
            result = -6;
        if (result == 0 &&
            (arm64_user_vm_tlb_flush_count() != flush_before ||
             arm64_user_vm_tlb_preserve_count() != preserve_before + 4))
            result = -7;
    }

    if (arm64_task_destroy(&context->probe_task, allocator, bootstrap) != 0)
        return -8;
    if (context->probe_task.magic != TASK_MAGIC_DEAD)
        return -9;
    if (allocator->free_pages != free_before)
        return -10;
    return result;
}

static inline void mmio_write32(unsigned long address, uint32_t value)
{
    address = (unsigned long)arm64_mmu_kernel_address(address);
    *(volatile uint32_t *)address = value;
}

static inline uint32_t mmio_read32(unsigned long address)
{
    address = (unsigned long)arm64_mmu_kernel_address(address);
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
    paddr_t kernel_end = (paddr_t)(uintptr_t)&__kernel_end;
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

static int test_dynamic_page_table(void)
{
    static const uint64_t page_magic = 0x4C33504147454F4BULL;
    paddr_t table_pages;
    paddr_t l1_page;
    paddr_t l2_page;
    paddr_t l3_page;
    paddr_t test_page;
    paddr_t ttbr1_page;
    paddr_t user_code_page;
    paddr_t user_data_page;
    paddr_t user_stack_page;
    paddr_t lifecycle_page;
    arm64_mmu_u64 old_ttbr;
    arm64_mmu_u64 new_ttbr;
    arm64_mmu_u64 high_text;
    arm64_mmu_u64 high_rodata;
    arm64_mmu_u64 high_data;
    arm64_mmu_u64 par_uart;
    arm64_mmu_u64 par_kernel;
    arm64_mmu_u64 par_unmapped;
    arm64_user_vm_t lifecycle_vm;
    uint64_t payload_size;
    uint64_t offset;
    uint32_t lifecycle_free_pages;
    unsigned int recycled_asid;

    if (early_page_alloc_pages(&early_allocator, 3, &table_pages) != 0 ||
        early_page_alloc_pages(&early_allocator, 1, &test_page) != 0)
        return -1;

    l1_page = table_pages;
    l2_page = table_pages + PAGE_SIZE;
    l3_page = table_pages + 2 * PAGE_SIZE;
    if (test_page >= 0x40200000ULL)
        return -1;

    *(volatile uint64_t *)(uintptr_t)test_page = page_magic;

    old_ttbr = arm64_mmu_read_ttbr0();
    if (arm64_mmu_prepare_identity_tables(l1_page, l2_page, l3_page) != 0 ||
        arm64_mmu_protect_kernel_image(
            l3_page,
            (arm64_mmu_u64)(uintptr_t)&__text_start,
            (arm64_mmu_u64)(uintptr_t)&__text_end,
            (arm64_mmu_u64)(uintptr_t)&__rodata_start,
            (arm64_mmu_u64)(uintptr_t)&__rodata_end) != 0 ||
        arm64_mmu_switch_ttbr0(l1_page) != 0)
        return -1;
    new_ttbr = arm64_mmu_read_ttbr0();

    if ((new_ttbr & PAGE_MASK) != l1_page ||
        (old_ttbr & PAGE_MASK) == l1_page)
        return -1;

    par_uart = arm64_mmu_translate_read(PL011_BASE);
    par_kernel = arm64_mmu_translate_read(0x40080000ULL);
    par_unmapped = arm64_mmu_translate_read(0x80000000ULL);
    if ((par_uart & 1u) != 0 ||
        (par_kernel & 1u) != 0 ||
        (par_unmapped & 1u) == 0)
        return -1;

    arm64_early_puts("TTBR0 allocated: old=");
    arm64_early_puthex64(old_ttbr);
    arm64_early_puts(" new=");
    arm64_early_puthex64(new_ttbr);
    arm64_early_puts(" L2=");
    arm64_early_puthex64(l2_page);
    arm64_early_puts(" L3=");
    arm64_early_puthex64(l3_page);
    arm64_early_puts("\n");

    if (arm64_mmu_update_identity_page(l3_page, test_page, 0) != 0 ||
        (arm64_mmu_translate_read(test_page) & 1u) == 0 ||
        arm64_mmu_update_identity_page(l3_page, test_page, 1) != 0 ||
        (arm64_mmu_translate_read(test_page) & 1u) != 0 ||
        *(volatile uint64_t *)(uintptr_t)test_page != page_magic)
        return -1;
    arm64_early_puts("ARM64_L3_PAGE_TLBI_OK\n");

    if (early_page_alloc_pages(&early_allocator, 1, &ttbr1_page) != 0 ||
        arm64_mmu_install_ttbr1(ttbr1_page, l2_page) != 0)
        return -1;

    high_text = ARM64_KERNEL_VA_BASE +
                (arm64_mmu_u64)(uintptr_t)&__text_start;
    high_rodata = ARM64_KERNEL_VA_BASE +
                  (arm64_mmu_u64)(uintptr_t)&__rodata_start;
    high_data = ARM64_KERNEL_VA_BASE +
                (arm64_mmu_u64)(uintptr_t)&early_allocator;

    if ((arm64_mmu_read_ttbr1() & PAGE_MASK) != ttbr1_page ||
        (arm64_mmu_translate_read(high_text) & 1u) != 0 ||
        (arm64_mmu_translate_read(high_text) & PAR_PA_MASK) !=
            ((arm64_mmu_u64)(uintptr_t)&__text_start & PAR_PA_MASK) ||
        (arm64_mmu_translate_write(high_text) & 1u) == 0 ||
        (arm64_mmu_translate_user_read(high_text) & 1u) == 0 ||
        (arm64_mmu_translate_read(high_rodata) & 1u) != 0 ||
        (arm64_mmu_translate_write(high_rodata) & 1u) == 0 ||
        (arm64_mmu_translate_user_read(high_rodata) & 1u) == 0 ||
        (arm64_mmu_translate_read(high_data) & 1u) != 0 ||
        (arm64_mmu_translate_write(high_data) & 1u) != 0 ||
        (arm64_mmu_translate_user_read(high_data) & 1u) == 0 ||
        *(volatile uint64_t *)(uintptr_t)high_text !=
            *(volatile uint64_t *)(uintptr_t)&__text_start ||
        *(volatile uint64_t *)(uintptr_t)high_rodata !=
            *(volatile uint64_t *)(uintptr_t)&__rodata_start ||
        *(volatile uint64_t *)(uintptr_t)high_data !=
            *(volatile uint64_t *)(uintptr_t)&early_allocator)
        return -1;

    arm64_early_puts("TTBR1 kernel alias: table=");
    arm64_early_puthex64(arm64_mmu_read_ttbr1());
    arm64_early_puts(" text=");
    arm64_early_puthex64(high_text);
    arm64_early_puts(" TCR=");
    arm64_early_puthex64(arm64_mmu_read_tcr());
    arm64_early_puts("\nARM64_TTBR1_PERMISSIONS_OK\n");

    lifecycle_free_pages = early_allocator.free_pages;
    if (arm64_user_vm_init(&lifecycle_vm, &early_allocator) != 0 ||
        arm64_user_vm_map_new_page(
            &lifecycle_vm,
            &early_allocator,
            0x0000000000600000ULL,
            ARM64_USER_PAGE_READ | ARM64_USER_PAGE_WRITE,
            &lifecycle_page) != 0 ||
        early_allocator.free_pages != lifecycle_free_pages - 4 ||
        arm64_user_vm_map_new_page(
            &lifecycle_vm,
            &early_allocator,
            0x0000000000601000ULL,
            ARM64_USER_PAGE_READ | ARM64_USER_PAGE_WRITE |
                ARM64_USER_PAGE_EXEC,
            &lifecycle_page) == 0 ||
        early_allocator.free_pages != lifecycle_free_pages - 4)
        return -1;
    recycled_asid = lifecycle_vm.asid;
    if (arm64_user_vm_destroy(&lifecycle_vm, &early_allocator) != 0 ||
        early_allocator.free_pages != lifecycle_free_pages ||
        arm64_user_vm_init(&high_context.user_vm, &early_allocator) != 0 ||
        high_context.user_vm.asid != recycled_asid ||
        arm64_user_vm_init(&high_context.empty_vm, &early_allocator) != 0 ||
        high_context.empty_vm.asid == high_context.user_vm.asid)
        return -1;
    arm64_early_puts("ARM64_USER_VM_LIFECYCLE_OK\n");

    if (arm64_user_vm_map_new_page(
            &high_context.user_vm,
            &early_allocator,
            USER_CODE_VA,
            ARM64_USER_PAGE_READ | ARM64_USER_PAGE_EXEC,
            &user_code_page) != 0 ||
        arm64_user_vm_map_new_page(
            &high_context.user_vm,
            &early_allocator,
            USER_DATA_VA,
            ARM64_USER_PAGE_READ | ARM64_USER_PAGE_WRITE,
            &user_data_page) != 0 ||
        arm64_user_vm_map_new_page(
            &high_context.user_vm,
            &early_allocator,
            USER_STACK_VA,
            ARM64_USER_PAGE_READ | ARM64_USER_PAGE_WRITE,
            &user_stack_page) != 0)
        return -1;

    payload_size = (uint64_t)(uintptr_t)arm64_el0_payload_end -
                   (uint64_t)(uintptr_t)arm64_el0_payload_start;
    if (payload_size == 0 || payload_size > PAGE_SIZE)
        return -1;
    for (offset = 0; offset < payload_size; offset++)
        *(volatile uint8_t *)(uintptr_t)(user_code_page + offset) =
            arm64_el0_payload_start[offset];
    arm64_mmu_sync_code(user_code_page, payload_size);

    for (offset = 0; offset < USER_WRITE_LENGTH; offset++)
        *(volatile uint8_t *)(uintptr_t)(user_data_page + offset) =
            (uint8_t)arm64_user_message[offset];
    *(volatile uint64_t *)(uintptr_t)(user_data_page + USER_VM_MAGIC_OFFSET) =
        USER_TEST_MAGIC;
    high_context.boot_l1 = l1_page;
    (void)user_stack_page;

    if (early_page_free_pages(&early_allocator, test_page, 1) != 0)
        return -1;

    arm64_early_puts("ARM64_DYNAMIC_PGTABLE_OK\n");
    arm64_enter_high_alias(
        ARM64_KERNEL_VA_BASE +
            (arm64_mmu_u64)(uintptr_t)arm64_high_main,
        ARM64_KERNEL_VA_BASE +
            (arm64_mmu_u64)(uintptr_t)&__stack_top,
        ARM64_KERNEL_VA_BASE +
            (arm64_mmu_u64)(uintptr_t)arm64_vectors,
        ARM64_KERNEL_VA_BASE +
            (arm64_mmu_u64)(uintptr_t)&high_context);
}

static void arm64_high_main(arm64_high_context_t *context)
{
    arm64_mmu_u64 pc;
    arm64_mmu_u64 sp;
    arm64_mmu_u64 vbar;
    arm64_mmu_u64 high_text;
    arm64_mmu_u64 high_uart;
    arm64_mmu_u64 high_user_page;
    arm64_mmu_u64 par_low_kernel;
    arm64_mmu_u64 par_high_kernel;
    arm64_mmu_u64 user_ttbr;
    arm64_mmu_u64 empty_ttbr;
    paddr_t user_data_page;

    __asm__ volatile("adr %0, ." : "=r"(pc));
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    __asm__ volatile("mrs %0, vbar_el1" : "=r"(vbar));
    high_text = (arm64_mmu_u64)(uintptr_t)&__text_start;
    high_uart = arm64_mmu_kernel_address(PL011_BASE);
    if (arm64_user_vm_lookup(&context->user_vm, USER_DATA_VA,
                             &user_data_page, NULL) != 0) {
        arm64_early_puts("ARM64_USER_VM_LOOKUP_FAILED\n");
        goto halt;
    }
    high_user_page = ARM64_KERNEL_VA_BASE + user_data_page;

    arm64_early_puts("High kernel: PC=");
    arm64_early_puthex64(pc);
    arm64_early_puts(" SP=");
    arm64_early_puthex64(sp);
    arm64_early_puts(" VBAR=");
    arm64_early_puthex64(vbar);
    arm64_early_puts("\n");

    if (pc < ARM64_KERNEL_VA_BASE || sp < ARM64_KERNEL_VA_BASE ||
        vbar != (arm64_mmu_u64)(uintptr_t)arm64_vectors ||
        high_text < ARM64_KERNEL_VA_BASE) {
        arm64_early_puts("ARM64_TTBR1_EXECUTION_FAILED\n");
        goto halt;
    }
    arm64_early_puts("ARM64_TTBR1_EXECUTION_OK\n");

    if ((arm64_mmu_translate_read(high_uart) & 1u) != 0 ||
        (arm64_mmu_translate_user_read(high_uart) & 1u) == 0) {
        arm64_early_puts("ARM64_HIGH_MMIO_FAILED\n");
        goto halt;
    }
    arm64_early_puts("ARM64_HIGH_MMIO_OK\n");

    if (arm64_mmu_retire_low_map(context->boot_l1) != 0) {
        arm64_early_puts("ARM64_LOW_MAP_RETIRE_FAILED\n");
        goto halt;
    }

    par_low_kernel = arm64_mmu_translate_read(0x40080000ULL);
    par_high_kernel = arm64_mmu_translate_read(high_text);
    if ((par_low_kernel & 1u) == 0 ||
        (par_high_kernel & 1u) != 0 ||
        (arm64_mmu_translate_read(PL011_BASE) & 1u) == 0 ||
        (arm64_mmu_translate_read(high_uart) & 1u) != 0) {
        arm64_early_puts("ARM64_LOW_MAP_RETIRE_VERIFY_FAILED\n");
        goto halt;
    }
    arm64_early_puts("ARM64_LOW_MAP_RETIRED_OK\n");

    if (arm64_task_context_smoke_test(context) != 0) {
        arm64_early_puts("ARM64_TASK_CONTEXT_SWITCH_FAILED\n");
        goto halt;
    }
    arm64_early_puts("ARM64_TASK_CONTEXT_SWITCH_OK\n");
    arm64_early_puts("ARM64_TASK_STACK_LIFECYCLE_OK\n");
    arm64_early_puts("ARM64_GENERIC_TASK_LIFECYCLE_OK\n");

    if (arm64_user_vm_activate(&context->user_vm) != 0) {
        arm64_early_puts("ARM64_USER_TTBR0_SWITCH_FAILED\n");
        goto halt;
    }
    user_ttbr = arm64_mmu_read_ttbr0();
    if ((user_ttbr & TTBR_TABLE_MASK) != context->user_vm.l1 ||
        ((user_ttbr >> TTBR_ASID_SHIFT) & 0xffu) !=
            context->user_vm.asid ||
        (arm64_mmu_translate_user_read(USER_CODE_VA) & 1u) != 0 ||
        (arm64_mmu_translate_user_write(USER_CODE_VA) & 1u) == 0 ||
        (arm64_mmu_translate_user_read(USER_DATA_VA) & 1u) != 0 ||
        (arm64_mmu_translate_user_write(USER_DATA_VA) & 1u) != 0 ||
        (arm64_mmu_translate_user_read(USER_STACK_VA) & 1u) != 0 ||
        (arm64_mmu_translate_user_write(USER_STACK_VA) & 1u) != 0 ||
        (arm64_mmu_translate_read(USER_DATA_VA) & 1u) != 0 ||
        *(volatile uint64_t *)(uintptr_t)(USER_DATA_VA +
                                         USER_VM_MAGIC_OFFSET) !=
            USER_TEST_MAGIC ||
        *(volatile uint64_t *)(uintptr_t)(high_user_page +
                                         USER_VM_MAGIC_OFFSET) !=
            USER_TEST_MAGIC ||
        (arm64_mmu_translate_read(0x40080000ULL) & 1u) == 0 ||
        (arm64_mmu_translate_read(PL011_BASE) & 1u) == 0 ||
        (arm64_mmu_translate_read(high_text) & 1u) != 0 ||
        (arm64_mmu_translate_read(high_uart) & 1u) != 0) {
        arm64_early_puts("ARM64_USER_TTBR0_VERIFY_FAILED\n");
        goto halt;
    }

    if (arm64_user_vm_activate(&context->empty_vm) != 0) {
        arm64_early_puts("ARM64_EMPTY_TTBR0_SWITCH_FAILED\n");
        goto halt;
    }
    empty_ttbr = arm64_mmu_read_ttbr0();
    if ((empty_ttbr & TTBR_TABLE_MASK) != context->empty_vm.l1 ||
        ((empty_ttbr >> TTBR_ASID_SHIFT) & 0xffu) !=
            context->empty_vm.asid ||
        (arm64_mmu_translate_user_read(USER_DATA_VA) & 1u) == 0 ||
        (arm64_mmu_translate_read(high_text) & 1u) != 0 ||
        (arm64_mmu_translate_read(high_uart) & 1u) != 0 ||
        arm64_user_vm_activate(&context->user_vm) != 0 ||
        (arm64_mmu_translate_user_read(USER_DATA_VA) & 1u) != 0 ||
        *(volatile uint64_t *)(uintptr_t)(USER_DATA_VA +
                                         USER_VM_MAGIC_OFFSET) !=
            USER_TEST_MAGIC) {
        arm64_early_puts("ARM64_TTBR0_ISOLATION_FAILED\n");
        goto halt;
    }

    arm64_early_puts("User TTBR0: mapped=");
    arm64_early_puthex64(user_ttbr);
    arm64_early_puts(" empty=");
    arm64_early_puthex64(empty_ttbr);
    arm64_early_puts(" VA=");
    arm64_early_puthex64(USER_DATA_VA);
    arm64_early_puts(" PA=");
    arm64_early_puthex64(user_data_page);
    arm64_early_puts("\nARM64_USER_TTBR0_ASID_OK\n");

    if (arm64_task_address_space_smoke_test(context, user_ttbr,
                                            empty_ttbr) != 0) {
        arm64_early_puts("ARM64_TASK_TTBR0_SWITCH_FAILED\n");
        goto halt;
    }
    arm64_early_puts("ARM64_TASK_TTBR0_SWITCH_OK\n");
    arm64_early_puts("ASID residency: flush=");
    arm64_early_puthex64(arm64_user_vm_tlb_flush_count());
    arm64_early_puts(" preserve=");
    arm64_early_puthex64(arm64_user_vm_tlb_preserve_count());
    arm64_early_puts("\nARM64_TASK_TLB_RESIDENCY_OK\n");

    arm64_early_puts("Testing high VBAR synchronous vector\n");
    __asm__ volatile("brk #0x64");
    clear_task_context(&context->user_task);
    context->user_task.user_vm = &context->user_vm;
    context->user_task.ttbr0 = context->user_vm.l1;
    context->user_task.asid = context->user_vm.asid;
    context->user_task.flags = ARM64_TASK_FLAG_RETURNS_TO_USER;
    prepare_user_registers(&context->user_task.user);
    arm64_exception_set_el0_context(
        &context->user_vm,
        &context->user_task.user,
        (arm64_exception_u64)(uintptr_t)arm64_el0_return);
    arm64_early_puts("Entering EL0 at ");
    arm64_early_puthex64(USER_CODE_VA);
    arm64_early_puts(" stack=");
    arm64_early_puthex64(PROBE_USER_STACK_TOP);
    arm64_early_puts("\n");
    arm64_enter_el0(&context->user_task.user);

halt:
    for (;;)
        __asm__ volatile("wfe");
}

static void arm64_el0_return(uint64_t result)
{
    if (current_el() != 1 || result != USER_EXIT_STATUS ||
        *(volatile uint64_t *)(uintptr_t)(USER_DATA_VA +
                                         USER_WRITE_RESULT_OFFSET) !=
            USER_WRITE_LENGTH ||
        *(volatile uint64_t *)(uintptr_t)(USER_DATA_VA +
                                         USER_EFAULT_RESULT_OFFSET) !=
            USER_EFAULT_RESULT ||
        *(volatile uint64_t *)(uintptr_t)(USER_DATA_VA +
                                         USER_ENOSYS_RESULT_OFFSET) !=
            USER_ENOSYS_RESULT ||
        high_context.user_task.user_vm != &high_context.user_vm ||
        high_context.user_task.ttbr0 != high_context.user_vm.l1 ||
        high_context.user_task.asid != high_context.user_vm.asid ||
        high_context.user_task.flags != ARM64_TASK_FLAG_RETURNS_TO_USER ||
        high_context.user_task.user.x[0] != USER_EXIT_STATUS ||
        high_context.user_task.user.x[8] != ARMOS_NR_EXIT ||
        high_context.user_task.user.x[19] != USER_X19_SENTINEL ||
        high_context.user_task.user.x[20] != USER_X20_SENTINEL ||
        high_context.user_task.user.x[29] != USER_X29_SENTINEL ||
        high_context.user_task.user.x[30] != USER_X30_SENTINEL ||
        high_context.user_task.user.sp != PROBE_USER_STACK_TOP ||
        high_context.user_task.user.pc !=
            *(volatile uint64_t *)(uintptr_t)(USER_DATA_VA +
                                              USER_EXIT_PC_OFFSET) ||
        high_context.user_task.user.pstate !=
            ARM64_USER_PSTATE_EL0T_MASKED ||
        arm64_exception_el0_exit_status() != USER_EXIT_STATUS ||
        arm64_exception_el0_syscall_count() != 4) {
        arm64_early_puts("ARM64_EL0_SYSCALL_ABI_FAILED\n");
        goto halt;
    }

    arm64_early_puts("EL0 exit status: ");
    arm64_early_puthex64(result);
    arm64_early_puts(" syscall count: ");
    arm64_early_puthex64(arm64_exception_el0_syscall_count());
    arm64_early_puts("\nARM64_EL0_SYSCALL_ABI_OK\n");
    arm64_early_puts("ARM64_EL0_CONTEXT_OK\n");

    arm64_early_puts("Testing timer IRQ after EL0 return\n");
    if (arm64_timer_irq_smoke_test() != 0) {
        arm64_early_puts("ARM64_POST_EL0_TIMER_IRQ_FAILED\n");
        goto halt;
    }
    arm64_early_puts("ARM64_HIGH_KERNEL_OK\n");

halt:
    for (;;)
        __asm__ volatile("wfe");
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
        else {
            arm64_early_puts("ARM64_PHYS_ALLOC_OK\n");
            if (test_dynamic_page_table() != 0)
                arm64_early_puts("ARM64_DYNAMIC_PGTABLE_FAILED\n");
        }
    } else {
        arm64_early_puts("ARM64_MMU_TRANSLATION_FAILED\n");
    }
}
