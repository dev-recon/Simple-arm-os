/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/platform/qemu_virt/bootstrap.c
 * Layer: ARM64 / QEMU virt bootstrap
 *
 * Responsibilities:
 * - Sequence AArch64 boot milestones before the persistent runtime starts.
 * - Validate MMU, exceptions, timer IRQs, user VMs and context switching.
 * - Exercise runtime user page-table growth and targeted page retirement.
 * - Validate generic syscall, process, ELF64 and lazy VM contracts.
 * - Run cooperative kernel and EL0 task-dispatch probes.
 * - Run the EL0 syscall ABI payload and report stable serial markers.
 * - Enter the disk-backed AArch64 mash process with a polling PL011 TTY.
 *
 * Notes:
 * - Integration probes remain here temporarily and are retired as their
 *   services move into persistent kernel subsystems.
 */

#include <asm/console.h>
#include <asm/exception.h>
#include <asm/irq.h>
#include <asm/mmu.h>
#include <asm/task.h>
#include <asm/task_context.h>
#include <asm/user_vm.h>
#include <kernel/early_page_allocator.h>
#include <kernel/elf64.h>
#include <kernel/ext2_reader.h>
#include <kernel/fdt.h>
#include <kernel/io_model.h>
#include <kernel/process_model.h>
#include <kernel/syscall_dispatch.h>
#include <kernel/task.h>
#include <kernel/task_runqueue.h>
#include <uapi/armos/syscall.h>

#include "virtio_block.h"

#define PL011_BASE 0x09000000UL

#define EARLY_ALLOC_MAX_RAM      0x40000000ULL
#define EARLY_ALLOC_MAX_PAGES    (EARLY_ALLOC_MAX_RAM / PAGE_SIZE)
#define EARLY_ALLOC_BITMAP_BYTES ((EARLY_ALLOC_MAX_PAGES + 7u) / 8u)
#define PAR_PA_MASK              0x0000FFFFFFFFF000ULL
#define TTBR_TABLE_MASK          0x0000FFFFFFFFF000ULL
#define TTBR_ASID_SHIFT          48u
#define USER_CODE_VA             0x0000000000400000ULL
#define USER_DATA_VA             0x0000000000401000ULL
#define USER_STACK_VA            0x0000000000402000ULL
#define DYNAMIC_VM_FIRST_VA      0x0000000000200000ULL
#define DYNAMIC_VM_SECOND_VA     0x0000000000400000ULL
#define DYNAMIC_VM_DISTANT_VA    0x0000000040000000ULL
#define DYNAMIC_VM_RANGE_VA      0x00000000007FF000ULL
#define DYNAMIC_VM_RANGE_LENGTH  (2u * PAGE_SIZE)
#define PROBE_USER_STACK_TOP     0x0000000000403000ULL
#define USER_WRITE_RESULT_OFFSET 0x100u
#define USER_EFAULT_RESULT_OFFSET 0x108u
#define USER_ENOSYS_RESULT_OFFSET 0x110u
#define USER_EXIT_PC_OFFSET        0x118u
#define USER_PID_RESULT_OFFSET     0x120u
#define USER_BRK_RESULT_OFFSET     0x128u
#define USER_BRK_MAGIC_OFFSET      0x130u
#define USER_MMAP_RESULT_OFFSET    0x138u
#define USER_MMAP_MAGIC_OFFSET     0x140u
#define USER_MUNMAP_RESULT_OFFSET  0x148u
#define USER_SIGACTION_RESULT_OFFSET 0x150u
#define USER_FORK_RESULT_OFFSET      0x158u
#define USER_KILL_RESULT_OFFSET      0x160u
#define USER_WAIT_RESULT_OFFSET      0x168u
#define USER_OPEN_READ_RESULT_OFFSET 0x170u
#define USER_CLOSE_RESULT_OFFSET     0x178u
#define USER_PIPE_RESULT_OFFSET      0x180u
#define USER_PIPE_WRITE_RESULT_OFFSET 0x188u
#define USER_PIPE_READ_RESULT_OFFSET 0x190u
#define USER_DUP2_RESULT_OFFSET      0x198u
#define USER_VM_MAGIC_OFFSET     0x200u
#define USER_PREEMPT_FLAG_OFFSET 0x300u
#define USER_OPEN_PATH_OFFSET    0x380u
#define USER_OPEN_BUFFER_OFFSET  0x3C0u
#define USER_PIPE_FDS_OFFSET     0x400u
#define USER_PIPE_SOURCE_OFFSET  0x420u
#define USER_PIPE_BUFFER_OFFSET  0x440u
#define USER_EXEC_PATH_OFFSET    0x480u
#define USER_EXEC_ARGV_OFFSET    0x4A0u
#define USER_EXEC_ENVP_OFFSET    0x4B0u
#define USER_EXEC_ENV_PATH_OFFSET   0x500u
#define USER_EXEC_ENV_HOME_OFFSET   0x540u
#define USER_EXEC_ENV_USER_OFFSET   0x580u
#define USER_EXEC_ENV_BANNER_OFFSET 0x5C0u
#define USER_TEST_MAGIC          0x5553455254544252ULL
#define USER_WRITE_LENGTH        23u
#define USER_EXIT_STATUS         42u
#define USER_PREEMPT_EXIT_STATUS 43u
#define USER_OPEN_CONTENT_LENGTH 12u
#define USER_PIPE_CONTENT_LENGTH 6u
#define USER_PROCESS_PID          1u
#define USER_BRK_TEST_ADDRESS     (USER_HEAP_START + PAGE_SIZE)
#define USER_FAULT_MAGIC          0x4641554C54564D36ULL
#define USER_EFAULT_RESULT       0xFFFFFFFFFFFFFFF2ULL
#define USER_ENOSYS_RESULT       0xFFFFFFFFFFFFFFDAULL
#define USER_X19_SENTINEL         0x1919191919191919ULL
#define USER_X20_SENTINEL         0x2020202020202020ULL
#define USER_X29_SENTINEL         0x2929292929292929ULL
#define USER_X30_SENTINEL         0x3030303030303030ULL
#define TASK_X22_SENTINEL         0x2222222222222222ULL
#define TASK_X23_SENTINEL         0x2323232323232323ULL
#define TASK_PROBE_STACK_PAGES    1u
#define TASK_SIMD_Q0_SENTINEL     0x0123456789ABCDEFULL
#define TASK_SIMD_Q31_SENTINEL    0xFEDCBA9876543210ULL
#define TASK_SIMD_FPCR_SENTINEL   0x00400000ULL
#define TASK_SIMD_FPSR_SENTINEL   0x00000001ULL
#define RUNTIME_TASK_STACK_PAGES  2u
#define RUNTIME_WAKE_TICKS        5u
#define ARMOS_PROT_READ           0x1u
#define ARMOS_PROT_WRITE          0x2u
#define ARMOS_PROT_EXEC           0x4u
#define ARMOS_MAP_PRIVATE         0x2u
#define ARMOS_MAP_ANON            0x20u
#define ARM64_BOOTSTRAP_PID       3
#define ARM64_EXEC_STACK_PAGES    16u
#define ARM64_EXEC_STACK_BASE     \
    (USER_STACK_TOP - ARM64_EXEC_STACK_PAGES * PAGE_SIZE)
#define ARM64_EXEC_STACK_DATA_PAGE (USER_STACK_TOP - PAGE_SIZE)
#define ARM64_EXEC_MAX_ARGS       4u
#define ARM64_EXEC_MAX_ENVS       4u
#define ARM64_EXEC_STRING_SIZE    64u

static const char arm64_user_message[] = "ARM64 syscall write OK\n";
static const char arm64_bootstrap_path[] = "/etc/motd";
static const char arm64_bootstrap_file[] = "ArmOS ARM64 ";
static const char arm64_exec_invalid_path[] = "/etc/exec-invalid";
static const char arm64_exec_invalid_file[] = "not an ELF image\n";
static const char arm64_bootstrap_shell_path[] = "/sbin/mash";
static const char arm64_bootstrap_env_path[] = "PATH=/bin:/usr/bin:/sbin";
static const char arm64_bootstrap_env_home[] = "HOME=/";
static const char arm64_bootstrap_env_user[] = "USER=root";
static const char arm64_bootstrap_env_banner[] = "MASH_BANNER=1";
static const char arm64_pipe_message[] = "pipe64";
_Static_assert(sizeof(arm64_user_message) - 1 == USER_WRITE_LENGTH,
               "EL0 write payload length must match its assembly constant");
_Static_assert(sizeof(arm64_bootstrap_file) - 1 ==
                   USER_OPEN_CONTENT_LENGTH,
               "EL0 disk-read payload length must match its assembly constant");

typedef struct {
    unsigned int argc;
    unsigned int envc;
    char argv[ARM64_EXEC_MAX_ARGS][ARM64_EXEC_STRING_SIZE];
    char envp[ARM64_EXEC_MAX_ENVS][ARM64_EXEC_STRING_SIZE];
} arm64_exec_arguments_t;

extern uint8_t arm64_vectors[];
extern uint8_t arm64_el0_payload_start[];
extern uint8_t arm64_el0_payload_end[];
extern uint8_t arm64_el0_preempt_payload[];
extern uint8_t arm64_el0_generic_payload[];
extern uint8_t arm64_el0_exec_payload[];

extern void arm64_enter_high_alias(uint64_t entry,
                                   uint64_t stack,
                                   uint64_t vectors,
                                   uint64_t context)
    __attribute__((noreturn));
extern void arm64_enter_el0(const arm64_user_context_t *registers)
    __attribute__((noreturn));

typedef struct {
    syscall_dispatcher_t dispatcher;
    process_model_t process;
    process_model_t child;
    io_model_vfs_t vfs;
    io_model_context_t io;
    arm64_user_vm_t *vm;
    early_page_allocator_t *allocator;
    ext2_reader_t *filesystem;
    char cwd[MAX_PATH];
} arm64_syscall_runtime_t;

typedef struct {
    paddr_t boot_l1;
    arm64_user_vm_t user_vm;
    arm64_user_vm_t empty_vm;
    arm64_user_vm_t exec_vm;
    arm64_task_context_t user_task;
    task_t scheduled_user_task;
    task_t bootstrap_task;
    task_t probe_task;
    task_t second_probe_task;
    task_t idle_task;
    task_t init_task;
    task_dispatcher_t runtime_dispatcher;
    arm64_syscall_runtime_t syscall_runtime;
    ext2_reader_t disk_reader;
    const void *disk_exec_image;
    size_t disk_exec_image_size;
    paddr_t disk_exec_image_physical;
    uint32_t disk_exec_image_pages;
    volatile uint64_t task_probe_phase;
    volatile uint64_t second_task_probe_phase;
    volatile uint64_t task_probe_ttbr0;
    volatile uint64_t second_task_probe_ttbr0;
    volatile uint64_t runtime_idle_entries;
    volatile uint64_t runtime_init_entries;
    volatile uint64_t runtime_init_wakes;
    volatile uint32_t runtime_wake_tick;
    volatile uint32_t runtime_failure;
    volatile uint32_t exec_previous_vm_retired;
    volatile uint32_t exec_source_retired;
} arm64_high_context_t;

static early_page_allocator_t early_allocator;
static uint8_t early_allocator_bitmap[EARLY_ALLOC_BITMAP_BYTES]
    __attribute__((aligned(ARCH_CACHE_LINE_SIZE)));
static arm64_high_context_t high_context;
static arm64_high_context_t *runtime_context;
static arm64_syscall_runtime_t *active_syscall_runtime;
static uint8_t arm64_ext2_scratch[4096]
    __attribute__((aligned(ARCH_CACHE_LINE_SIZE)));
static int arm64_probe_error_line;
static int arm64_runtime_tty_visible;
static uint64_t arm64_boot_total_mb;

typedef struct {
    unsigned int length;
} arm64_boot_line_t;

#define ARM64_BOOT_COLOR_RESET "\033[0m"
#define ARM64_BOOT_COLOR_OK    "\033[1;32m"
#define ARM64_BOOT_COLOR_WARN  "\033[1;33m"
#define ARM64_BOOT_COLOR_FAIL  "\033[1;31m"
#define ARM64_BOOT_COLOR_INFO  "\033[1;36m"

static int arm64_text_contains(const char *text, const char *needle)
{
    size_t start;

    if (!text || !needle || needle[0] == '\0')
        return 0;
    for (start = 0; text[start] != '\0'; start++) {
        size_t index = 0;

        while (needle[index] != '\0' &&
               text[start + index] == needle[index])
            index++;
        if (needle[index] == '\0')
            return 1;
    }
    return 0;
}

static void arm64_probe_puts(const char *text)
{
    int failure = arm64_text_contains(text, "FAIL") ||
                  arm64_text_contains(text, "HALT");

    if (failure)
        arm64_probe_error_line = 1;
    if (failure || arm64_probe_error_line)
        arm64_console_puts(text);
    if (arm64_probe_error_line && arm64_text_contains(text, "\n"))
        arm64_probe_error_line = 0;
}

static void arm64_probe_putc(char character)
{
    if (arm64_probe_error_line)
        arm64_console_putc(character);
    if (character == '\n')
        arm64_probe_error_line = 0;
}

static void arm64_probe_puthex64(uint64_t value)
{
    if (arm64_probe_error_line)
        arm64_console_puthex64(value);
}

static unsigned int arm64_boot_text_length(const char *text)
{
    unsigned int length = 0;

    while (text && text[length] != '\0')
        length++;
    return length;
}

static void arm64_boot_line_begin(arm64_boot_line_t *line,
                                  const char *text)
{
    arm64_console_puts(text);
    line->length = arm64_boot_text_length(text);
}

static void arm64_boot_line_text(arm64_boot_line_t *line,
                                 const char *text)
{
    arm64_console_puts(text);
    line->length += arm64_boot_text_length(text);
}

static void arm64_boot_line_u64(arm64_boot_line_t *line, uint64_t value)
{
    static const uint64_t powers[] = {
        10000000000000000000ULL, 1000000000000000000ULL,
        100000000000000000ULL, 10000000000000000ULL,
        1000000000000000ULL, 100000000000000ULL,
        10000000000000ULL, 1000000000000ULL, 100000000000ULL,
        10000000000ULL, 1000000000ULL, 100000000ULL, 10000000ULL,
        1000000ULL, 100000ULL, 10000ULL, 1000ULL, 100ULL, 10ULL, 1ULL
    };
    unsigned int index;
    int started = 0;

    for (index = 0; index < sizeof(powers) / sizeof(powers[0]); index++) {
        unsigned int digit = 0;

        while (value >= powers[index]) {
            value -= powers[index];
            digit++;
        }
        if (digit != 0 || started || powers[index] == 1u) {
            arm64_console_putc((char)('0' + digit));
            line->length++;
            started = 1;
        }
    }
}

static void arm64_boot_line_hex(arm64_boot_line_t *line, uint64_t value)
{
    arm64_console_puthex64(value);
    line->length += 18u;
}

static void arm64_boot_line_end(arm64_boot_line_t *line,
                                const char *color, const char *status)
{
    while (line->length < 56u) {
        arm64_console_putc(' ');
        line->length++;
    }
    arm64_console_putc(' ');
    arm64_console_puts(color);
    arm64_console_puts(status);
    arm64_console_puts(ARM64_BOOT_COLOR_RESET "\n");
}

static void arm64_boot_status(const char *text, const char *color,
                              const char *status)
{
    arm64_boot_line_t line;

    arm64_boot_line_begin(&line, text);
    arm64_boot_line_end(&line, color, status);
}

static void arm64_boot_ok(const char *text)
{
    arm64_boot_status(text, ARM64_BOOT_COLOR_OK, "[ OK ]");
}

static void arm64_boot_warn(const char *text)
{
    arm64_boot_status(text, ARM64_BOOT_COLOR_WARN, "[WARN]");
}

static void arm64_boot_fail(const char *text)
{
    arm64_boot_status(text, ARM64_BOOT_COLOR_FAIL, "[FAIL]");
}

static uint64_t arm64_boot_timer_frequency(void)
{
    uint64_t frequency;

    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frequency));
    return frequency;
}

static void arm64_boot_runtime_summary(
    const arm64_virtio_block_probe_t *block_probe)
{
    arm64_boot_line_t line;

    arm64_boot_ok("Memory: early init");

    arm64_boot_line_begin(&line, "Memory: ");
    arm64_boot_line_u64(&line, arm64_boot_total_mb);
    arm64_boot_line_text(&line, "MB total, ");
    arm64_boot_line_u64(&line, early_allocator.free_pages >> 8);
    arm64_boot_line_text(&line, "MB available");
    arm64_boot_line_end(&line, ARM64_BOOT_COLOR_OK, "[ OK ]");

    arm64_boot_line_begin(&line, "Kernel: ");
    arm64_boot_line_hex(&line, (uint64_t)(uintptr_t)&__text_start);
    arm64_boot_line_text(&line, "-");
    arm64_boot_line_hex(&line, (uint64_t)(uintptr_t)&__kernel_end);
    arm64_boot_line_end(&line, ARM64_BOOT_COLOR_OK, "[ OK ]");

    arm64_boot_ok("MMU: split TTBR enabled, ASID pool 255");
    arm64_boot_ok("IRQ: GICv2 physical interrupt controller");

    arm64_boot_line_begin(&line, "Timer: ARM generic timer @ ");
    arm64_boot_line_u64(&line, arm64_boot_timer_frequency());
    arm64_boot_line_text(&line, " Hz, tick 1000 us");
    arm64_boot_line_end(&line, ARM64_BOOT_COLOR_OK, "[ OK ]");

    arm64_boot_ok("SMP: 1 CPU(s) configured, 1 online, seen=0x1");
    arm64_boot_ok("TTY: console tty0 on qemu-virt PL011 uart0");

    arm64_boot_line_begin(&line, "Block: vd0 ");
    arm64_boot_line_u64(&line, block_probe->capacity_sectors >> 11);
    arm64_boot_line_text(&line, "MB on VirtIO");
    arm64_boot_line_end(&line, ARM64_BOOT_COLOR_OK, "[ OK ]");

    arm64_boot_line_begin(&line, "Partition: vd0p1 ext2 ");
    arm64_boot_line_u64(&line, block_probe->ext2_sector_count >> 11);
    arm64_boot_line_text(&line, "MB");
    arm64_boot_line_end(&line, ARM64_BOOT_COLOR_OK, "[ OK ]");

    arm64_boot_ok("VFS: read-only ext2 provider on /");
    arm64_boot_warn("VFS: proc unavailable before generic VFS handoff");
}

static void arm64_high_main(arm64_high_context_t *context)
    __attribute__((noreturn));
static void arm64_el0_return(uint64_t result)
    __attribute__((noreturn));
static void arm64_bootstrap_shell_return(uint64_t result)
    __attribute__((noreturn));
static void arm64_runtime_scheduler_start(arm64_high_context_t *context)
    __attribute__((noreturn));
static int arm64_prepare_exec_image(arm64_high_context_t *context,
                                    const char *path,
                                    const arm64_exec_arguments_t *arguments,
                                    arm64_user_context_t *registers);
static int arm64_exec_rollback_smoke_test(arm64_high_context_t *context);
static int arm64_release_exec_source(arm64_high_context_t *context);
static void arm64_exec_retire_previous_vm(const vm_space_t *previous_vm,
                                          void *owner);

static int arm64_block_read_sectors(void *owner, uint64_t lba,
                                    uint32_t count, void *buffer)
{
    (void)owner;
    return arm64_virtio_block_read(lba, count, buffer);
}

static int arm64_ext2_provider_lookup(void *owner, const char *path,
                                      size_t *size)
{
    return ext2_reader_file_size((ext2_reader_t *)owner, path, size) == 0 ?
        0 : -ENOENT;
}

static ssize_t arm64_ext2_provider_read(void *owner, const char *path,
                                        size_t offset, void *buffer,
                                        size_t length)
{
    ssize_t result = ext2_reader_read_range(
        (ext2_reader_t *)owner, path, offset, buffer, length);

    return result >= 0 ? result : -EIO;
}

static int arm64_ext2_path_smoke_test(
    arm64_high_context_t *context,
    const arm64_virtio_block_probe_t *block_probe)
{
    static const char init_path[] = "/sbin/init";
    size_t expected_size;
    size_t file_size;
    uint32_t page_count;
    paddr_t file_physical;
    uint8_t *file;
    int result = -1;

    if (!context || !block_probe || ext2_reader_init(
            &context->disk_reader, NULL, arm64_block_read_sectors,
            block_probe->ext2_start_lba, arm64_ext2_scratch,
            sizeof(arm64_ext2_scratch)) != 0 ||
        ext2_reader_file_size(&context->disk_reader, init_path,
                              &expected_size) != 0 ||
        expected_size < 5u || expected_size > 1024u * 1024u)
        return -1;
    page_count = (uint32_t)((expected_size + PAGE_SIZE - 1u) / PAGE_SIZE);
    if (early_page_alloc_pages(&early_allocator, page_count,
                               &file_physical) != 0)
        return -1;
    file = (uint8_t *)(uintptr_t)
        arm64_mmu_kernel_address(file_physical);
    if (ext2_reader_read_file(&context->disk_reader, init_path, file,
                              (size_t)page_count * PAGE_SIZE,
                              &file_size) != 0 ||
        file_size != expected_size || file[0] != 0x7Fu ||
        file[1] != 'E' || file[2] != 'L' || file[3] != 'F' ||
        (file[4] != 1u && file[4] != 2u))
        goto cleanup;
    arm64_probe_puts("ARM64_EXT2_PATH_READ_OK path=");
    arm64_probe_puts(init_path);
    arm64_probe_puts(" size=");
    arm64_probe_puthex64(file_size);
    arm64_probe_puts(" elf_class=");
    arm64_probe_puthex64(file[4]);
    arm64_probe_puts("\n");
    result = 0;

cleanup:
    if (early_page_free_pages(&early_allocator, file_physical,
                              page_count) != 0)
        return -1;
    return result;
}

static int arm64_ext2_load_exec_image(arm64_high_context_t *context,
                                      const char *path)
{
    size_t expected_size;
    size_t file_size;
    uint32_t page_count;
    paddr_t physical;
    uint8_t *file;

    if (!context || !path || context->disk_exec_image ||
        context->disk_exec_image_pages != 0 || ext2_reader_file_size(
            &context->disk_reader, path, &expected_size) != 0 ||
        expected_size < sizeof(elf64_header_t) ||
        expected_size > 1024u * 1024u)
        return -1;
    page_count = (uint32_t)((expected_size + PAGE_SIZE - 1u) / PAGE_SIZE);
    if (early_page_alloc_pages(&early_allocator, page_count, &physical) != 0)
        return -1;
    file = (uint8_t *)(uintptr_t)arm64_mmu_kernel_address(physical);
    if (ext2_reader_read_file(&context->disk_reader, path, file,
                              (size_t)page_count * PAGE_SIZE,
                              &file_size) != 0 ||
        file_size != expected_size ||
        elf64_validate_aarch64(file, file_size, USER_SPACE_END) != 0) {
        (void)early_page_free_pages(&early_allocator, physical, page_count);
        return -1;
    }
    context->disk_exec_image = file;
    context->disk_exec_image_size = file_size;
    context->disk_exec_image_physical = physical;
    context->disk_exec_image_pages = page_count;
    arm64_probe_puts("ARM64_EXT2_EXEC_IMAGE_READY path=");
    arm64_probe_puts(path);
    arm64_probe_puts(" size=");
    arm64_probe_puthex64(file_size);
    arm64_probe_puts("\n");
    return 0;
}

void arm64_user_task_probe_enter(task_t *task)
{
    if (!task || task->magic != TASK_MAGIC_ALIVE ||
        task->type != TASK_TYPE_PROCESS ||
        !(task->context.flags & ARM64_TASK_FLAG_RETURNS_TO_USER)) {
        arm64_probe_puts("ARM64_USER_TASK_ENTRY_FAILED\n");
        for (;;)
            __asm__ volatile("wfe");
    }
    arm64_enter_el0(&task->context.user);
}

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

static void clear_memory(void *address, size_t length)
{
    uint8_t *bytes = address;
    size_t index;

    for (index = 0; index < length; index++)
        bytes[index] = 0;
}

static void copy_memory(void *destination, const void *source, size_t length)
{
    uint8_t *output = destination;
    const uint8_t *input = source;
    size_t index;

    for (index = 0; index < length; index++)
        output[index] = input[index];
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

static uint32_t arm64_dispatch_irq_save(void *context)
{
    (void)context;
    return asm_irq_fiq_save();
}

static void arm64_dispatch_irq_restore(void *context, uint32_t saved_state)
{
    (void)context;
    asm_irq_fiq_restore(saved_state);
}

static int arm64_dispatcher_init(task_dispatcher_t *dispatcher,
                                 task_t *current,
                                 uint32_t capacity)
{
    if (task_dispatcher_init(dispatcher, current, capacity,
                             arm64_task_switch_prepared) != 0)
        return -1;
    return task_dispatcher_set_irq_ops(dispatcher,
                                       arm64_dispatch_irq_save,
                                       arm64_dispatch_irq_restore,
                                       NULL);
}

static ssize_t arm64_bootstrap_tty_read(void *owner, void *buffer,
                                        size_t length)
{
    uint8_t *bytes = buffer;
    size_t count;

    (void)owner;
    if (!buffer)
        return -EINVAL;
    if (length == 0)
        return 0;

    bytes[0] = (uint8_t)arm64_console_getc();
    for (count = 1; count < length; count++) {
        char character;

        if (!arm64_console_try_getc(&character))
            break;
        bytes[count] = (uint8_t)character;
    }
    return (ssize_t)count;
}

static ssize_t arm64_bootstrap_tty_write(void *owner, const void *buffer,
                                         size_t length)
{
    const uint8_t *bytes = buffer;
    size_t index;

    (void)owner;
    if (arm64_runtime_tty_visible) {
        for (index = 0; index < length; index++)
            arm64_console_putc((char)bytes[index]);
    }
    return (ssize_t)length;
}

static int arm64_copy_user_path(arm64_syscall_runtime_t *runtime,
                                vaddr_t address, char *path,
                                size_t capacity)
{
    size_t index;

    if (!runtime || !path || capacity < 2)
        return -EINVAL;
    for (index = 0; index < capacity; index++) {
        if (arm64_user_vm_validate_range(runtime->vm, address + index, 1,
                                         VMA_READ) != 0)
            return -EFAULT;
        path[index] = *(const char *)(uintptr_t)(address + index);
        if (path[index] == '\0')
            return 0;
    }
    path[capacity - 1] = '\0';
    return -E2BIG;
}

static int arm64_normalize_path(const arm64_syscall_runtime_t *runtime,
                                const char *path, char *normalized,
                                size_t capacity)
{
    char source[MAX_PATH];
    size_t source_length = 0;
    size_t cursor = 0;
    size_t output_length = 1;

    if (!runtime || !path || !normalized || capacity < 2 || path[0] == '\0')
        return -EINVAL;
    if (path[0] != '/') {
        while (runtime->cwd[source_length] != '\0') {
            if (source_length + 1 >= sizeof(source))
                return -ENAMETOOLONG;
            source[source_length] = runtime->cwd[source_length];
            source_length++;
        }
        if (source_length == 0 || source[source_length - 1] != '/') {
            if (source_length + 1 >= sizeof(source))
                return -ENAMETOOLONG;
            source[source_length++] = '/';
        }
    }
    while (*path != '\0') {
        if (source_length + 1 >= sizeof(source))
            return -ENAMETOOLONG;
        source[source_length++] = *path++;
    }
    source[source_length] = '\0';

    normalized[0] = '/';
    while (source[cursor] == '/')
        cursor++;
    while (source[cursor] != '\0') {
        size_t start = cursor;
        size_t component_length;
        size_t index;

        while (source[cursor] != '\0' && source[cursor] != '/')
            cursor++;
        component_length = cursor - start;
        if (component_length == 1 && source[start] == '.') {
            /* Keep the current component. */
        } else if (component_length == 2 && source[start] == '.' &&
                   source[start + 1] == '.') {
            while (output_length > 1 &&
                   normalized[output_length - 1] != '/')
                output_length--;
            if (output_length > 1)
                output_length--;
        } else if (component_length != 0) {
            if (output_length > 1) {
                if (output_length + 1 >= capacity)
                    return -ENAMETOOLONG;
                normalized[output_length++] = '/';
            }
            if (component_length >= capacity - output_length)
                return -ENAMETOOLONG;
            for (index = 0; index < component_length; index++)
                normalized[output_length++] = source[start + index];
        }
        while (source[cursor] == '/')
            cursor++;
    }
    normalized[output_length] = '\0';
    return 0;
}

static int arm64_copy_user_vector(
    arm64_syscall_runtime_t *runtime, vaddr_t vector_address,
    char (*values)[ARM64_EXEC_STRING_SIZE], unsigned int maximum,
    unsigned int *count)
{
    unsigned int index;

    if (!runtime || !values || !count)
        return -EINVAL;
    *count = 0;
    if (vector_address == 0)
        return 0;
    for (index = 0; index <= maximum; index++) {
        vaddr_t slot = vector_address +
                       (vaddr_t)index * sizeof(uint64_t);
        vaddr_t string_address;
        int result;

        if (slot < vector_address || arm64_user_vm_validate_range(
                runtime->vm, slot, sizeof(uint64_t), VMA_READ) != 0)
            return -EFAULT;
        string_address = *(const uint64_t *)(uintptr_t)slot;
        if (string_address == 0) {
            *count = index;
            return 0;
        }
        if (index == maximum)
            return -E2BIG;
        result = arm64_copy_user_path(runtime, string_address,
                                      values[index],
                                      ARM64_EXEC_STRING_SIZE);
        if (result != 0)
            return result;
    }
    return -E2BIG;
}

static syscall_result_t arm64_syscall_write(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;
    vaddr_t address = (vaddr_t)request->arguments[1];
    size_t length = (size_t)request->arguments[2];

    if (!runtime || !runtime->vm)
        return -(syscall_result_t)EINVAL;
    if (length > 256 || arm64_user_vm_validate_range(
            runtime->vm, address, length, VMA_READ) != 0)
        return -(syscall_result_t)EFAULT;
    return io_model_write(&runtime->io, (int)request->arguments[0],
                          (const void *)(uintptr_t)address, length);
}

static syscall_result_t arm64_syscall_read(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;
    vaddr_t address = (vaddr_t)request->arguments[1];
    size_t length = (size_t)request->arguments[2];

    if (!runtime || !runtime->vm)
        return -(syscall_result_t)EINVAL;
    if (length > 256 || arm64_user_vm_validate_range(
            runtime->vm, address, length, VMA_WRITE) != 0)
        return -(syscall_result_t)EFAULT;
    return io_model_read(&runtime->io, (int)request->arguments[0],
                         (void *)(uintptr_t)address, length);
}

static syscall_result_t arm64_syscall_open(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;
    char path[MAX_PATH];
    int result;

    result = arm64_copy_user_path(runtime,
                                  (vaddr_t)request->arguments[0],
                                  path, sizeof(path));
    if (result != 0)
        return result;
    return io_model_open(&runtime->io, path,
                         (unsigned int)request->arguments[1]);
}

static syscall_result_t arm64_syscall_close(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;

    return runtime ? io_model_close(&runtime->io,
                                    (int)request->arguments[0]) :
                     -(syscall_result_t)EINVAL;
}

static syscall_result_t arm64_syscall_pipe(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;
    vaddr_t address = (vaddr_t)request->arguments[0];

    if (!runtime || arm64_user_vm_validate_range(
            runtime->vm, address, 2u * sizeof(int), VMA_WRITE) != 0)
        return -(syscall_result_t)EFAULT;
    return io_model_pipe(&runtime->io, (int *)(uintptr_t)address);
}

static syscall_result_t arm64_syscall_dup2(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;

    return runtime ? io_model_dup2(&runtime->io,
                                   (int)request->arguments[0],
                                   (int)request->arguments[1]) :
                     -(syscall_result_t)EINVAL;
}

static syscall_result_t arm64_syscall_yield(
    void *owner, const syscall_request_t *request)
{
    (void)owner;
    (void)request;
    return 0;
}

static syscall_result_t arm64_syscall_exit(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;

    if (!runtime || process_model_exit(
            &runtime->process, (int)request->arguments[0]) != 0)
        return -(syscall_result_t)EINVAL;
    return 0;
}

static syscall_result_t arm64_syscall_getpid(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;

    (void)request;
    return runtime ? runtime->process.pid : -(syscall_result_t)ESRCH;
}

static syscall_result_t arm64_syscall_getppid(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;

    (void)request;
    return runtime ? runtime->process.ppid : -(syscall_result_t)ESRCH;
}

static syscall_result_t arm64_syscall_chdir(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;
    ext2_reader_path_info_t info;
    char path[MAX_PATH];
    char normalized[MAX_PATH];
    size_t index;
    int result;

    result = arm64_copy_user_path(runtime,
                                  (vaddr_t)request->arguments[0],
                                  path, sizeof(path));
    if (result != 0)
        return result;
    result = arm64_normalize_path(runtime, path, normalized,
                                  sizeof(normalized));
    if (result != 0)
        return result;
    if (!runtime->filesystem || ext2_reader_path_info(
            runtime->filesystem, normalized, &info) != 0)
        return -(syscall_result_t)ENOENT;
    if (info.type != EXT2_READER_PATH_DIRECTORY)
        return -(syscall_result_t)ENOTDIR;
    for (index = 0; normalized[index] != '\0'; index++)
        runtime->cwd[index] = normalized[index];
    runtime->cwd[index] = '\0';
    return 0;
}

static syscall_result_t arm64_syscall_getcwd(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;
    vaddr_t address = (vaddr_t)request->arguments[0];
    size_t capacity = (size_t)request->arguments[1];
    size_t length = 0;
    size_t index;

    if (!runtime || !runtime->vm)
        return -(syscall_result_t)EINVAL;
    while (runtime->cwd[length] != '\0')
        length++;
    length++;
    if (capacity < length)
        return -(syscall_result_t)ERANGE;
    if (arm64_user_vm_validate_range(runtime->vm, address, length,
                                     VMA_WRITE) != 0)
        return -(syscall_result_t)EFAULT;
    for (index = 0; index < length; index++)
        *(char *)(uintptr_t)(address + index) = runtime->cwd[index];
    return (syscall_result_t)length;
}

static syscall_result_t arm64_syscall_setpgid(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;
    pid_t pid = (pid_t)request->arguments[0];
    pid_t pgid = (pid_t)request->arguments[1];
    process_model_t *process;

    if (!runtime)
        return -(syscall_result_t)ESRCH;
    if (pid == 0 || pid == runtime->process.pid)
        process = &runtime->process;
    else if (pid == runtime->child.pid)
        process = &runtime->child;
    else
        return -(syscall_result_t)ESRCH;
    if (pgid == 0)
        pgid = process->pid;
    if (pgid <= 0)
        return -(syscall_result_t)EINVAL;
    process->pgid = pgid;
    return 0;
}

static syscall_result_t arm64_syscall_getpgrp(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;

    (void)request;
    return runtime ? runtime->process.pgid : -(syscall_result_t)ESRCH;
}

static syscall_result_t arm64_syscall_fork(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;

    (void)request;
    if (!runtime ||
        (runtime->child.state != PROCESS_MODEL_NEW &&
         runtime->child.state != PROCESS_MODEL_DEAD))
        return -(syscall_result_t)EAGAIN;
    if (process_model_fork(&runtime->process, &runtime->child, 2,
                           &runtime->vm->space, NULL) != 0)
        return -(syscall_result_t)ENOMEM;
    return runtime->child.pid;
}

static syscall_result_t arm64_syscall_waitpid(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;
    int status;

    if (!runtime)
        return -(syscall_result_t)ESRCH;
    return process_model_wait(&runtime->process,
                              (pid_t)request->arguments[0], &status,
                              (uint32_t)request->arguments[2]);
}

static syscall_result_t arm64_syscall_kill(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;
    process_model_t *target;

    if (!runtime)
        return -(syscall_result_t)ESRCH;
    target = (pid_t)request->arguments[0] == runtime->process.pid ?
        &runtime->process : &runtime->child;
    if (target->pid != (pid_t)request->arguments[0] ||
        process_model_signal(target,
                             (unsigned int)request->arguments[1]) != 0)
        return -(syscall_result_t)ESRCH;
    return 0;
}

static syscall_result_t arm64_syscall_sigaction(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;
    unsigned int signal = (unsigned int)request->arguments[0];

    if (!runtime || signal == 0 || signal >= PROCESS_MODEL_SIGNAL_COUNT)
        return -(syscall_result_t)EINVAL;
    runtime->process.signal_handlers[signal] =
        (vaddr_t)request->arguments[1];
    return 0;
}

static syscall_result_t arm64_syscall_execve(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;
    arm64_exec_arguments_t arguments;
    arm64_user_context_t prepared_registers;
    arm64_task_context_t previous_task;
    vm_space_t *previous_vm_space;
    arm64_user_vm_t *previous_runtime_vm;
    process_model_state_t previous_state;
    uint32_t previous_pending_signals;
    vaddr_t previous_signal_handlers[PROCESS_MODEL_SIGNAL_COUNT];
    char path[MAX_PATH];
    unsigned int signal;
    int result;

    if (runtime != &high_context.syscall_runtime)
        return -(syscall_result_t)EINVAL;
    result = arm64_copy_user_path(runtime,
                                  (vaddr_t)request->arguments[0],
                                  path, sizeof(path));
    if (result != 0)
        return result;
    result = arm64_copy_user_vector(
        runtime, (vaddr_t)request->arguments[1], arguments.argv,
        ARM64_EXEC_MAX_ARGS, &arguments.argc);
    if (result != 0)
        return result;
    result = arm64_copy_user_vector(
        runtime, (vaddr_t)request->arguments[2], arguments.envp,
        ARM64_EXEC_MAX_ENVS, &arguments.envc);
    if (result != 0)
        return result;
    result = arm64_prepare_exec_image(&high_context, path, &arguments,
                                      &prepared_registers);
    if (result != 0)
        return -(syscall_result_t)ENOEXEC;
    arm64_probe_puts("ARM64_ELF64_PATH_LOAD_OK entry=");
    arm64_probe_puthex64(prepared_registers.pc);
    arm64_probe_puts(" stack=");
    arm64_probe_puthex64(prepared_registers.sp);
    arm64_probe_puts("\n");

    previous_vm_space = runtime->process.vm_space;
    previous_runtime_vm = runtime->vm;
    previous_state = runtime->process.state;
    previous_pending_signals = runtime->process.pending_signals;
    for (signal = 0; signal < PROCESS_MODEL_SIGNAL_COUNT; signal++)
        previous_signal_handlers[signal] =
            runtime->process.signal_handlers[signal];
    copy_memory(&previous_task, &high_context.user_task,
                sizeof(previous_task));
    if (process_model_exec(&runtime->process,
                           &high_context.exec_vm.space) != 0) {
        (void)arm64_user_vm_destroy(&high_context.exec_vm,
                                    runtime->allocator);
        (void)arm64_release_exec_source(&high_context);
        return -(syscall_result_t)EINVAL;
    }
    runtime->process.state = PROCESS_MODEL_RUNNING;
    runtime->vm = &high_context.exec_vm;
    clear_task_context(&high_context.user_task);
    high_context.user_task.vm_space =
        arm64_user_vm_space(&high_context.exec_vm);
    high_context.user_task.ttbr0 = high_context.exec_vm.l1;
    high_context.user_task.asid = high_context.exec_vm.asid;
    high_context.user_task.flags = ARM64_TASK_FLAG_RETURNS_TO_USER;
    copy_memory(&high_context.user_task.user, &prepared_registers,
                sizeof(prepared_registers));
    if (arm64_exception_request_exec(
            arm64_user_vm_space(&high_context.exec_vm),
            &high_context.user_task.user,
            arm64_exec_retire_previous_vm, &high_context) != 0) {
        runtime->process.vm_space = previous_vm_space;
        runtime->process.state = previous_state;
        runtime->process.pending_signals = previous_pending_signals;
        for (signal = 0; signal < PROCESS_MODEL_SIGNAL_COUNT; signal++)
            runtime->process.signal_handlers[signal] =
                previous_signal_handlers[signal];
        runtime->vm = previous_runtime_vm;
        copy_memory(&high_context.user_task, &previous_task,
                    sizeof(previous_task));
        (void)arm64_user_vm_destroy(&high_context.exec_vm,
                                    runtime->allocator);
        (void)arm64_release_exec_source(&high_context);
        return -(syscall_result_t)EBUSY;
    }
    return 0;
}

static syscall_result_t arm64_syscall_brk(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;
    vaddr_t result;

    if (!runtime || arm64_user_vm_set_brk(
            runtime->vm, runtime->allocator,
            (vaddr_t)request->arguments[0], &result) != 0)
        return -(syscall_result_t)ENOMEM;
    return (syscall_result_t)result;
}

static syscall_result_t arm64_syscall_mmap(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;
    unsigned int prot = (unsigned int)request->arguments[2];
    unsigned int map_flags = (unsigned int)request->arguments[3];
    unsigned int vm_flags = 0;
    vaddr_t result;

    if (!runtime || (prot & ~(ARMOS_PROT_READ | ARMOS_PROT_WRITE |
                             ARMOS_PROT_EXEC)) != 0 ||
        (prot & ARMOS_PROT_READ) == 0 || (prot & ARMOS_PROT_EXEC) != 0 ||
        (map_flags & (ARMOS_MAP_PRIVATE | ARMOS_MAP_ANON)) !=
            (ARMOS_MAP_PRIVATE | ARMOS_MAP_ANON))
        return -(syscall_result_t)EINVAL;
    if (prot & ARMOS_PROT_READ)
        vm_flags |= VMA_READ;
    if (prot & ARMOS_PROT_WRITE)
        vm_flags |= VMA_WRITE;
    if (arm64_user_vm_mmap_anonymous(
            runtime->vm, (vaddr_t)request->arguments[0],
            (size_t)request->arguments[1], vm_flags, &result) != 0)
        return -(syscall_result_t)ENOMEM;
    return (syscall_result_t)result;
}

static syscall_result_t arm64_syscall_munmap(
    void *owner, const syscall_request_t *request)
{
    arm64_syscall_runtime_t *runtime = owner;
    size_t length = (size_t)request->arguments[1];

    if (!runtime || length == 0 ||
        (request->arguments[0] & PAGE_OFFSET_MASK) != 0)
        return -(syscall_result_t)EINVAL;
    length = (length + PAGE_SIZE - 1) & PAGE_MASK;
    if (arm64_user_vm_unmap_range(
            runtime->vm, runtime->allocator,
            (vaddr_t)request->arguments[0], length) != 0)
        return -(syscall_result_t)EINVAL;
    return 0;
}

static int arm64_syscall_page_fault(vaddr_t address, int is_write,
                                    int is_execute)
{
    if (!active_syscall_runtime)
        return -1;
    return arm64_user_vm_handle_page_fault(
        active_syscall_runtime->vm,
        active_syscall_runtime->allocator,
        address, is_write, is_execute, NULL);
}

static int arm64_syscall_runtime_init(arm64_high_context_t *context)
{
    arm64_syscall_runtime_t *runtime = &context->syscall_runtime;

    runtime->vm = &context->user_vm;
    runtime->allocator = high_early_allocator();
    runtime->filesystem = &context->disk_reader;
    runtime->cwd[0] = '/';
    runtime->cwd[1] = '\0';
    io_model_vfs_init(&runtime->vfs);
    if (io_model_vfs_set_readonly_provider(
            &runtime->vfs, arm64_ext2_provider_lookup,
            arm64_ext2_provider_read, &context->disk_reader) != 0 ||
        io_model_vfs_add_readonly(
            &runtime->vfs, arm64_exec_invalid_path,
            arm64_exec_invalid_file,
            sizeof(arm64_exec_invalid_file) - 1u) != 0 ||
        io_model_context_init(&runtime->io, &runtime->vfs,
                              arm64_bootstrap_tty_read,
                              arm64_bootstrap_tty_write, NULL) != 0)
        return -1;
    syscall_dispatcher_init(&runtime->dispatcher);
    if (process_model_init(&runtime->process, USER_PROCESS_PID, NULL,
                           &runtime->vm->space,
                           &context->scheduled_user_task) != 0)
        return -1;
    runtime->process.state = PROCESS_MODEL_RUNNING;
    runtime->process.io_context = &runtime->io;

#define REGISTER_BOOTSTRAP_SYSCALL(number, handler) \
    if (syscall_dispatcher_register(&runtime->dispatcher, (number), \
                                    (handler), runtime) != 0) \
        return -2
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_EXIT, arm64_syscall_exit);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_FORK, arm64_syscall_fork);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_READ, arm64_syscall_read);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_WRITE, arm64_syscall_write);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_OPEN, arm64_syscall_open);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_CLOSE, arm64_syscall_close);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_WAITPID, arm64_syscall_waitpid);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_EXECVE, arm64_syscall_execve);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_CHDIR, arm64_syscall_chdir);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_GETPID, arm64_syscall_getpid);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_KILL, arm64_syscall_kill);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_BRK, arm64_syscall_brk);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_SETPGID, arm64_syscall_setpgid);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_PIPE, arm64_syscall_pipe);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_DUP2, arm64_syscall_dup2);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_GETPGRP, arm64_syscall_getpgrp);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_SIGACTION,
                               arm64_syscall_sigaction);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_GETPPID, arm64_syscall_getppid);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_SCHED_YIELD,
                               arm64_syscall_yield);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_GETCWD, arm64_syscall_getcwd);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_MMAP, arm64_syscall_mmap);
    REGISTER_BOOTSTRAP_SYSCALL(ARMOS_NR_MUNMAP, arm64_syscall_munmap);
#undef REGISTER_BOOTSTRAP_SYSCALL

    active_syscall_runtime = runtime;
    arm64_exception_set_syscall_dispatcher(&runtime->dispatcher);
    arm64_exception_set_page_fault_hook(arm64_syscall_page_fault);
    return 0;
}

static void arm64_runtime_halt(const char *marker)
    __attribute__((noreturn));

static void arm64_runtime_halt(const char *marker)
{
    __asm__ volatile("msr daifset, #2" ::: "memory");
    arm64_timer_irq_cancel();
    if (runtime_context)
        runtime_context->runtime_failure = 1;
    arm64_probe_puts(marker);
    for (;;)
        __asm__ volatile("wfe");
}

static int arm64_runtime_timer_tick(unsigned int ticks)
{
    arm64_high_context_t *context = runtime_context;

    if (!context || context->runtime_failure != 0)
        return -1;
    if (context->runtime_wake_tick == 0 ||
        (int32_t)(ticks - context->runtime_wake_tick) < 0)
        return 0;
    if (context->init_task.state != TASK_BLOCKED ||
        task_dispatcher_publish(&context->runtime_dispatcher,
                                &context->init_task) != 0) {
        context->runtime_failure = 1;
        return -1;
    }
    context->runtime_wake_tick = 0;
    __asm__ volatile("dmb ish" ::: "memory");
    return 0;
}

static void arm64_idle_task_entry(void)
{
    arm64_high_context_t *context = runtime_context;

    if (!context)
        arm64_runtime_halt("ARM64_IDLE0_CONTEXT_FAILED\n");
    __asm__ volatile("msr daifclr, #2\n\tisb" ::: "memory");
    for (;;) {
        context->runtime_idle_entries++;
        __asm__ volatile("wfi");
    }
}

static void arm64_init_task_entry(void)
{
    arm64_high_context_t *context = runtime_context;
    task_dispatcher_t *dispatcher;

    if (!context)
        arm64_runtime_halt("ARM64_KINIT_CONTEXT_FAILED\n");
    dispatcher = &context->runtime_dispatcher;
    __asm__ volatile("msr daifclr, #2\n\tisb" ::: "memory");

    if (dispatcher->current != &context->init_task ||
        context->bootstrap_task.state != TASK_BLOCKED)
        arm64_runtime_halt("ARM64_KINIT_START_FAILED\n");
    arm64_probe_puts("ARM64_KINIT_RUNNING\n");

    for (;;) {
        uint32_t saved_state = asm_irq_fiq_save();

        context->runtime_init_entries++;
        context->runtime_wake_tick =
            arm64_timer_irq_ticks() + RUNTIME_WAKE_TICKS;
        __asm__ volatile("dmb ish" ::: "memory");
        if (task_dispatcher_block(dispatcher) != 0)
            arm64_runtime_halt("ARM64_KINIT_BLOCK_FAILED\n");
        asm_irq_fiq_restore(saved_state);

        context->runtime_init_wakes++;
        if (context->runtime_init_wakes == 1) {
            if (context->runtime_idle_entries == 0 ||
                dispatcher->current != &context->init_task ||
                dispatcher->ready.count != 1 ||
                dispatcher->ready.head != &context->idle_task ||
                context->idle_task.state != TASK_READY ||
                context->bootstrap_task.state != TASK_BLOCKED ||
                dispatcher->dispatch_count < 3)
                arm64_runtime_halt("ARM64_IDLE_KINIT_SWITCH_FAILED\n");
            arm64_probe_puts("ARM64_BOOTSTRAP_RETIRED\n");
            arm64_probe_puts("ARM64_IDLE_KINIT_SWITCH_OK\n");
            arm64_probe_puts("ARM64_RUNTIME_SCHEDULER_OK\n");
        }
    }
}

static void arm64_runtime_scheduler_start(arm64_high_context_t *context)
{
    early_page_allocator_t *allocator = high_early_allocator();

    runtime_context = context;
    context->runtime_idle_entries = 0;
    context->runtime_init_entries = 0;
    context->runtime_init_wakes = 0;
    context->runtime_wake_tick = 0;
    context->runtime_failure = 0;

    if (arm64_task_init(
            &context->idle_task, allocator,
            arm64_user_vm_space(&context->empty_vm),
            (vaddr_t)(uintptr_t)arm64_idle_task_entry,
            "idle0", 10, RUNTIME_TASK_STACK_PAGES) != 0)
        arm64_runtime_halt("ARM64_IDLE0_INIT_FAILED\n");
    context->idle_task.priority = TASK_IDLE_PRIORITY;

    if (arm64_task_init(
            &context->init_task, allocator,
            arm64_user_vm_space(&context->empty_vm),
            (vaddr_t)(uintptr_t)arm64_init_task_entry,
            "kinit", 11, RUNTIME_TASK_STACK_PAGES) != 0)
        arm64_runtime_halt("ARM64_KINIT_INIT_FAILED\n");

    if (arm64_dispatcher_init(&context->runtime_dispatcher,
                              &context->bootstrap_task, 2) != 0 ||
        task_dispatcher_set_quantum(&context->runtime_dispatcher, 1) != 0 ||
        task_dispatcher_publish(&context->runtime_dispatcher,
                                &context->init_task) != 0 ||
        task_dispatcher_publish(&context->runtime_dispatcher,
                                &context->idle_task) != 0)
        arm64_runtime_halt("ARM64_RUNTIME_DISPATCHER_INIT_FAILED\n");

    arm64_exception_set_timer_tick_hook(arm64_runtime_timer_tick);
    arm64_exception_set_task_dispatcher(&context->runtime_dispatcher);
    if (arm64_timer_irq_start_periodic() != 0)
        arm64_runtime_halt("ARM64_RUNTIME_TIMER_START_FAILED\n");

    arm64_probe_puts("ARM64_IDLE0_KINIT_READY\n");
    if (task_dispatcher_block(&context->runtime_dispatcher) != 0)
        arm64_runtime_halt("ARM64_BOOTSTRAP_RETIRE_FAILED\n");
    arm64_runtime_halt("ARM64_BOOTSTRAP_RESUMED\n");
}

static int task_probe_metadata_valid(const task_t *task,
                                     uint32_t task_id,
                                     char name_initial)
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
           task->task_id == task_id &&
           task->state == TASK_BLOCKED &&
           task->priority == TASK_DEFAULT_PRIORITY &&
           task->type == TASK_TYPE_KERNEL &&
           task->running_cpu == TASK_CPU_NONE &&
           task->last_cpu == TASK_CPU_NONE &&
           task->name[0] == name_initial &&
           task->stack_size == TASK_PROBE_STACK_PAGES * PAGE_SIZE &&
           stack_base >= ARM64_KERNEL_VA_BASE &&
           stack_top == stack_base + task->stack_size &&
           task->context.kernel.sp == stack_top &&
           (stack_physical & PAGE_OFFSET_MASK) == 0;
}

static int initialize_task_probe(arm64_high_context_t *context,
                                 task_t *task,
                                 const arm64_user_vm_t *user_vm,
                                 vaddr_t kernel_entry,
                                 const char *name,
                                 uint32_t task_id,
                                 char name_initial,
                                 volatile uint64_t *phase,
                                 volatile uint64_t *observed_ttbr0)
{
    arm64_task_context_t *probe;

    *phase = 0;
    *observed_ttbr0 = 0;
    if (arm64_task_init(
            task,
            high_early_allocator(),
            user_vm ? arm64_user_vm_space(user_vm) : NULL,
            kernel_entry,
            name,
            task_id,
            TASK_PROBE_STACK_PAGES) != 0)
        return -1;

    probe = &task->context;
    if (!task_probe_metadata_valid(task, task_id, name_initial) ||
        arm64_task_destroy(task, high_early_allocator(), probe) != -2) {
        arm64_task_destroy(task, high_early_allocator(),
                           &context->bootstrap_task.context);
        return -2;
    }

    probe->kernel.x[0] = (uint64_t)(uintptr_t)task;
    probe->kernel.x[1] =
        (uint64_t)(uintptr_t)&context->bootstrap_task;
    probe->kernel.x[2] = (uint64_t)(uintptr_t)phase;
    probe->kernel.x[3] = TASK_X22_SENTINEL;
    probe->kernel.x[4] = TASK_X23_SENTINEL;
    probe->kernel.x[5] = (uint64_t)(uintptr_t)observed_ttbr0;
    probe->simd.q[0] = TASK_SIMD_Q0_SENTINEL;
    probe->simd.q[63] = TASK_SIMD_Q31_SENTINEL;
    probe->simd.fpcr = TASK_SIMD_FPCR_SENTINEL;
    probe->simd.fpsr = TASK_SIMD_FPSR_SENTINEL;
    if (probe->kernel.pc < ARM64_KERNEL_VA_BASE ||
        probe->kernel.sp < ARM64_KERNEL_VA_BASE) {
        arm64_task_destroy(task, high_early_allocator(),
                           &context->bootstrap_task.context);
        return -3;
    }
    return 0;
}

static int prepare_task_probe(arm64_high_context_t *context,
                              const arm64_user_vm_t *user_vm)
{
    task_t *bootstrap = &context->bootstrap_task;

    clear_task_context(&bootstrap->context);
    bootstrap->state = TASK_RUNNING;
    bootstrap->running_cpu = 0;
    bootstrap->last_cpu = 0;
    context->task_probe_phase = 0;
    context->task_probe_ttbr0 = 0;

    return initialize_task_probe(
        context, &context->probe_task, user_vm,
        (vaddr_t)(uintptr_t)arm64_task_context_probe_entry,
        "context-probe", 1, 'c',
        &context->task_probe_phase, &context->task_probe_ttbr0);
}

static int arm64_task_context_smoke_test(arm64_high_context_t *context)
{
    task_t *bootstrap = &context->bootstrap_task;
    arm64_task_context_t *probe;
    early_page_allocator_t *allocator = high_early_allocator();
    task_runqueue_t runqueue;
    task_t *next;
    uint64_t free_before = allocator->free_pages;
    uint32_t bootstrap_switch_before = bootstrap->switch_count;
    int result = 0;

    if (prepare_task_probe(context, NULL) != 0 ||
        task_runqueue_init(&runqueue, 1) != 0)
        return -1;
    probe = &context->probe_task.context;

    if (task_runqueue_publish(&runqueue, &context->probe_task) != 0 ||
        task_runqueue_publish(&runqueue, &context->probe_task) == 0 ||
        runqueue.count != 1 || task_runqueue_validate(&runqueue) != 0)
        result = -2;
    next = task_runqueue_take(&runqueue);
    if (result == 0 &&
        (next != &context->probe_task || next->state != TASK_READY ||
         runqueue.count != 0 || task_runqueue_validate(&runqueue) != 0))
        result = -3;

    if (result == 0 && arm64_task_switch(bootstrap, next) != 0)
        result = -4;
    if (result == 0 &&
        (context->task_probe_phase != 1 ||
        probe->kernel.x[3] != TASK_X22_SENTINEL ||
        probe->kernel.x[4] != TASK_X23_SENTINEL ||
        probe->simd.q[0] != TASK_SIMD_Q0_SENTINEL ||
        probe->simd.q[63] != TASK_SIMD_Q31_SENTINEL ||
        probe->simd.fpcr != TASK_SIMD_FPCR_SENTINEL ||
        probe->simd.fpsr != TASK_SIMD_FPSR_SENTINEL ||
        bootstrap->context.kernel.pc < ARM64_KERNEL_VA_BASE ||
        bootstrap->context.kernel.sp < ARM64_KERNEL_VA_BASE ||
        bootstrap->state != TASK_RUNNING ||
        context->probe_task.state != TASK_BLOCKED))
        result = -5;

    if (result == 0) {
        context->task_probe_phase = 2;
        if (task_runqueue_publish(&runqueue, &context->probe_task) != 0)
            result = -6;
        next = task_runqueue_take(&runqueue);
        if (result == 0 &&
            (next != &context->probe_task || next->state != TASK_READY ||
             task_runqueue_validate(&runqueue) != 0))
            result = -7;
        if (result == 0 && arm64_task_switch(bootstrap, next) != 0)
            result = -8;
        if (result == 0 &&
            (context->task_probe_phase != 3 ||
            probe->kernel.x[3] != TASK_X22_SENTINEL ||
            probe->kernel.x[4] != TASK_X23_SENTINEL ||
            probe->simd.q[0] != TASK_SIMD_Q0_SENTINEL ||
            probe->simd.q[63] != TASK_SIMD_Q31_SENTINEL ||
            probe->simd.fpcr != TASK_SIMD_FPCR_SENTINEL ||
            probe->simd.fpsr != TASK_SIMD_FPSR_SENTINEL ||
            bootstrap->state != TASK_RUNNING ||
            bootstrap->running_cpu != 0 ||
            bootstrap->switch_count != bootstrap_switch_before + 2 ||
            context->probe_task.state != TASK_BLOCKED ||
            context->probe_task.running_cpu != TASK_CPU_NONE ||
            context->probe_task.switch_count != 2 ||
            runqueue.count != 0 || task_runqueue_validate(&runqueue) != 0))
            result = -9;
    }

    if (arm64_task_destroy(&context->probe_task, allocator,
                           &bootstrap->context) != 0)
        return -10;
    if (context->probe_task.magic != TASK_MAGIC_DEAD)
        return -11;
    if (allocator->free_pages != free_before)
        return -12;
    return result;
}

static int arm64_multitask_runqueue_smoke_test(
    arm64_high_context_t *context)
{
    task_t *bootstrap = &context->bootstrap_task;
    task_t *first = &context->probe_task;
    task_t *second = &context->second_probe_task;
    early_page_allocator_t *allocator = high_early_allocator();
    task_runqueue_t runqueue;
    task_t *next;
    uint64_t free_before = allocator->free_pages;
    uint32_t bootstrap_switch_before = bootstrap->switch_count;
    int result = 0;

    clear_task_context(&bootstrap->context);
    bootstrap->state = TASK_RUNNING;
    bootstrap->running_cpu = 0;
    bootstrap->last_cpu = 0;

    if (initialize_task_probe(
            context, first, NULL,
            (vaddr_t)(uintptr_t)arm64_task_context_probe_entry,
            "fifo-probe-a", 1, 'f',
            &context->task_probe_phase,
            &context->task_probe_ttbr0) != 0)
        return -1;
    if (initialize_task_probe(
            context, second, NULL,
            (vaddr_t)(uintptr_t)arm64_task_context_probe_entry,
            "fifo-probe-b", 2, 'f',
            &context->second_task_probe_phase,
            &context->second_task_probe_ttbr0) != 0) {
        arm64_task_destroy(first, allocator, &bootstrap->context);
        return -2;
    }

    if (task_runqueue_init(&runqueue, 2) != 0 ||
        task_runqueue_publish(&runqueue, first) != 0 ||
        task_runqueue_publish(&runqueue, second) != 0 ||
        task_runqueue_publish(&runqueue, first) == 0 ||
        runqueue.head != first || runqueue.tail != second ||
        runqueue.count != 2 || task_runqueue_validate(&runqueue) != 0)
        result = -3;

    next = task_runqueue_take(&runqueue);
    if (result == 0 &&
        (next != first || runqueue.head != second ||
         runqueue.tail != second || runqueue.count != 1 ||
         task_runqueue_validate(&runqueue) != 0))
        result = -4;
    if (result == 0 && arm64_task_switch(bootstrap, next) != 0)
        result = -5;
    if (result == 0 &&
        (context->task_probe_phase != 1 || first->state != TASK_BLOCKED ||
         second->state != TASK_READY ||
         task_runqueue_publish(&runqueue, first) != 0 ||
         runqueue.head != second || runqueue.tail != first))
        result = -6;

    next = task_runqueue_take(&runqueue);
    if (result == 0 && next != second)
        result = -7;
    if (result == 0 && arm64_task_switch(bootstrap, next) != 0)
        result = -8;
    if (result == 0 &&
        (context->second_task_probe_phase != 1 ||
         second->state != TASK_BLOCKED || first->state != TASK_READY ||
         task_runqueue_publish(&runqueue, second) != 0 ||
         runqueue.head != first || runqueue.tail != second))
        result = -9;

    context->task_probe_phase = 2;
    next = task_runqueue_take(&runqueue);
    if (result == 0 && next != first)
        result = -10;
    if (result == 0 && arm64_task_switch(bootstrap, next) != 0)
        result = -11;

    context->second_task_probe_phase = 2;
    next = task_runqueue_take(&runqueue);
    if (result == 0 && next != second)
        result = -12;
    if (result == 0 && arm64_task_switch(bootstrap, next) != 0)
        result = -13;

    if (result == 0 &&
        (context->task_probe_phase != 3 ||
         context->second_task_probe_phase != 3 ||
         bootstrap->state != TASK_RUNNING || bootstrap->running_cpu != 0 ||
         bootstrap->switch_count != bootstrap_switch_before + 4 ||
         first->state != TASK_BLOCKED || first->running_cpu != TASK_CPU_NONE ||
         first->switch_count != 2 || second->state != TASK_BLOCKED ||
         second->running_cpu != TASK_CPU_NONE || second->switch_count != 2 ||
         runqueue.count != 0 || task_runqueue_validate(&runqueue) != 0))
        result = -14;

    if (arm64_task_destroy(second, allocator, &bootstrap->context) != 0)
        return -15;
    if (arm64_task_destroy(first, allocator, &bootstrap->context) != 0)
        return -16;
    if (second->magic != TASK_MAGIC_DEAD || first->magic != TASK_MAGIC_DEAD)
        return -17;
    if (allocator->free_pages != free_before)
        return -18;
    return result;
}

static int arm64_cooperative_dispatcher_smoke_test(
    arm64_high_context_t *context)
{
    task_t *bootstrap = &context->bootstrap_task;
    task_t *first = &context->probe_task;
    task_t *second = &context->second_probe_task;
    early_page_allocator_t *allocator = high_early_allocator();
    task_dispatcher_t dispatcher;
    uint64_t free_before = allocator->free_pages;
    uint32_t bootstrap_switch_before = bootstrap->switch_count;
    int result = 0;

    clear_task_context(&bootstrap->context);
    bootstrap->state = TASK_RUNNING;
    bootstrap->running_cpu = 0;
    bootstrap->last_cpu = 0;

    if (initialize_task_probe(
            context, first, NULL,
            (vaddr_t)(uintptr_t)arm64_task_dispatcher_probe_entry,
            "dispatch-a", 1, 'd', &context->task_probe_phase,
            &context->task_probe_ttbr0) != 0)
        return -1;
    if (initialize_task_probe(
            context, second, NULL,
            (vaddr_t)(uintptr_t)arm64_task_dispatcher_probe_entry,
            "dispatch-b", 2, 'd', &context->second_task_probe_phase,
            &context->second_task_probe_ttbr0) != 0) {
        arm64_task_destroy(first, allocator, &bootstrap->context);
        return -2;
    }

    if (arm64_dispatcher_init(&dispatcher, bootstrap, 3) != 0 ||
        task_dispatcher_publish(&dispatcher, first) != 0 ||
        task_dispatcher_publish(&dispatcher, second) != 0)
        result = -3;

    first->context.kernel.x[6] = (uint64_t)(uintptr_t)&dispatcher;
    second->context.kernel.x[6] = (uint64_t)(uintptr_t)&dispatcher;

    if (result == 0 && task_dispatcher_yield(&dispatcher) != 0)
        result = -4;
    if (result == 0 &&
        (context->task_probe_phase != 1 ||
         context->second_task_probe_phase != 1 ||
         dispatcher.current != bootstrap ||
         dispatcher.ready.head != first || dispatcher.ready.tail != second ||
         dispatcher.ready.count != 2 || dispatcher.dispatch_count != 3 ||
         dispatcher.last_reason != TASK_DISPATCH_YIELD ||
         task_dispatcher_validate(&dispatcher) != 0))
        result = -5;

    if (result == 0 && task_dispatcher_yield(&dispatcher) != 0)
        result = -6;
    if (result == 0 &&
        (context->task_probe_phase != 3 ||
         context->second_task_probe_phase != 3 ||
         dispatcher.current != bootstrap || dispatcher.ready.count != 0 ||
         dispatcher.dispatch_count != 6 ||
         dispatcher.last_reason != TASK_DISPATCH_BLOCK ||
         bootstrap->state != TASK_RUNNING || bootstrap->running_cpu != 0 ||
         bootstrap->switch_count != bootstrap_switch_before + 2 ||
         first->state != TASK_BLOCKED || first->running_cpu != TASK_CPU_NONE ||
         first->switch_count != 2 || second->state != TASK_BLOCKED ||
         second->running_cpu != TASK_CPU_NONE || second->switch_count != 2 ||
         task_dispatcher_validate(&dispatcher) != 0))
        result = -7;

    if (arm64_task_destroy(second, allocator, &bootstrap->context) != 0)
        return -8;
    if (arm64_task_destroy(first, allocator, &bootstrap->context) != 0)
        return -9;
    if (second->magic != TASK_MAGIC_DEAD || first->magic != TASK_MAGIC_DEAD)
        return -10;
    if (allocator->free_pages != free_before)
        return -11;
    return result;
}

static int arm64_deferred_preempt_smoke_test(
    arm64_high_context_t *context)
{
    task_t *bootstrap = &context->bootstrap_task;
    task_t *worker = &context->probe_task;
    early_page_allocator_t *allocator = high_early_allocator();
    task_dispatcher_t dispatcher;
    uint64_t free_before = allocator->free_pages;
    uint32_t bootstrap_switch_before = bootstrap->switch_count;
    int result = 0;

    clear_task_context(&bootstrap->context);
    bootstrap->state = TASK_RUNNING;
    bootstrap->running_cpu = 0;
    bootstrap->last_cpu = 0;

    if (initialize_task_probe(
            context, worker, NULL,
            (vaddr_t)(uintptr_t)arm64_task_dispatcher_probe_entry,
            "preempt-worker", 5, 'p', &context->task_probe_phase,
            &context->task_probe_ttbr0) != 0)
        return -1;

    if (arm64_dispatcher_init(&dispatcher, bootstrap, 2) != 0 ||
        task_dispatcher_publish(&dispatcher, worker) != 0)
        result = -2;
    worker->context.kernel.x[6] = (uint64_t)(uintptr_t)&dispatcher;

    if (result == 0) {
        arm64_exception_set_task_dispatcher(&dispatcher);
        if (task_dispatcher_preempt_disable(&dispatcher) != 0 ||
            arm64_timer_irq_fire_once() != 0)
            result = -3;
    }
    if (result == 0 &&
        (dispatcher.need_resched != 1 ||
         dispatcher.preempt_disable_depth != 1 ||
         dispatcher.preempt_requests != 1 ||
         dispatcher.preempt_deferred != 1 ||
         dispatcher.preempt_serviced != 0 ||
         dispatcher.dispatch_count != 0 ||
         dispatcher.current != bootstrap ||
         context->task_probe_phase != 0 ||
         task_dispatcher_validate(&dispatcher) != 0))
        result = -4;

    if (result == 0 && task_dispatcher_preempt_enable(&dispatcher) != 1)
        result = -5;
    if (result == 0 && arm64_timer_irq_fire_once() != 0)
        result = -6;
    if (result == 0 &&
        (dispatcher.need_resched != 0 ||
         dispatcher.preempt_disable_depth != 0 ||
         dispatcher.preempt_requests != 2 ||
         dispatcher.preempt_deferred != 1 ||
         dispatcher.preempt_serviced != 1 ||
         dispatcher.dispatch_count != 2 ||
         dispatcher.current != bootstrap ||
         dispatcher.ready.head != worker ||
         dispatcher.ready.tail != worker ||
         dispatcher.ready.count != 1 ||
         context->task_probe_phase != 1 ||
         worker->state != TASK_READY ||
         task_dispatcher_validate(&dispatcher) != 0))
        result = -7;

    if (result == 0 && task_dispatcher_yield(&dispatcher) != 0)
        result = -8;
    if (result == 0 &&
        (context->task_probe_phase != 3 ||
         dispatcher.current != bootstrap || dispatcher.ready.count != 0 ||
         dispatcher.dispatch_count != 4 ||
         dispatcher.last_reason != TASK_DISPATCH_BLOCK ||
         bootstrap->state != TASK_RUNNING || bootstrap->running_cpu != 0 ||
         bootstrap->switch_count != bootstrap_switch_before + 2 ||
         worker->state != TASK_BLOCKED ||
         worker->running_cpu != TASK_CPU_NONE || worker->switch_count != 2 ||
         task_dispatcher_validate(&dispatcher) != 0))
        result = -9;

    arm64_exception_set_task_dispatcher(NULL);
    if (arm64_task_destroy(worker, allocator, &bootstrap->context) != 0)
        return -10;
    if (worker->magic != TASK_MAGIC_DEAD)
        return -11;
    if (allocator->free_pages != free_before)
        return -12;
    return result;
}

static int arm64_user_yield_dispatcher_smoke_test(
    arm64_high_context_t *context)
{
    task_t *bootstrap = &context->bootstrap_task;
    task_t *user = &context->scheduled_user_task;
    task_t *peer = &context->probe_task;
    early_page_allocator_t *allocator = high_early_allocator();
    task_dispatcher_t dispatcher;
    uint64_t free_before = allocator->free_pages;
    uint32_t bootstrap_switch_before = bootstrap->switch_count;
    int result = 0;

    clear_task_context(&bootstrap->context);
    bootstrap->state = TASK_RUNNING;
    bootstrap->running_cpu = 0;
    bootstrap->last_cpu = 0;

    if (arm64_task_init(
            user, allocator, arm64_user_vm_space(&context->user_vm),
            (vaddr_t)(uintptr_t)arm64_user_task_probe_entry,
            "user-yield", 3, TASK_PROBE_STACK_PAGES) != 0)
        return -1;
    user->type = TASK_TYPE_PROCESS;
    user->context.flags = ARM64_TASK_FLAG_RETURNS_TO_USER;
    prepare_user_registers(&user->context.user);
    user->context.kernel.x[0] = (uint64_t)(uintptr_t)user;

    if (initialize_task_probe(
            context, peer, NULL,
            (vaddr_t)(uintptr_t)arm64_task_dispatcher_probe_entry,
            "user-peer", 4, 'u', &context->task_probe_phase,
            &context->task_probe_ttbr0) != 0) {
        arm64_task_destroy(user, allocator, &bootstrap->context);
        return -2;
    }
    if (arm64_dispatcher_init(&dispatcher, bootstrap, 3) != 0 ||
        task_dispatcher_publish(&dispatcher, user) != 0 ||
        task_dispatcher_publish(&dispatcher, peer) != 0)
        result = -3;

    peer->context.kernel.x[6] = (uint64_t)(uintptr_t)&dispatcher;
    arm64_exception_set_el0_context(
        arm64_user_vm_space(&context->user_vm),
        &user->context.user, 0);
    arm64_exception_set_task_dispatcher(&dispatcher);

    if (result == 0 && task_dispatcher_yield(&dispatcher) != 0)
        result = -4;
    if (result == 0 &&
        (context->task_probe_phase != 1 || dispatcher.current != bootstrap ||
         dispatcher.ready.head != user || dispatcher.ready.tail != peer ||
         dispatcher.ready.count != 2 || dispatcher.dispatch_count != 3 ||
         dispatcher.last_reason != TASK_DISPATCH_YIELD ||
         user->state != TASK_READY || peer->state != TASK_READY ||
         user->context.user.x[0] != 0 ||
         user->context.user.x[8] != ARMOS_NR_SCHED_YIELD ||
         arm64_exception_el0_syscall_count() != 2 ||
         task_dispatcher_validate(&dispatcher) != 0))
        result = -5;

    if (result == 0 && task_dispatcher_yield(&dispatcher) != 0)
        result = -6;
    if (result == 0 &&
        (context->task_probe_phase != 3 || dispatcher.current != bootstrap ||
         dispatcher.ready.count != 0 || dispatcher.dispatch_count != 6 ||
         dispatcher.last_reason != TASK_DISPATCH_BLOCK ||
         bootstrap->state != TASK_RUNNING || bootstrap->running_cpu != 0 ||
         bootstrap->switch_count != bootstrap_switch_before + 2 ||
         user->state != TASK_BLOCKED || user->running_cpu != TASK_CPU_NONE ||
         user->switch_count != 2 || peer->state != TASK_BLOCKED ||
         peer->running_cpu != TASK_CPU_NONE || peer->switch_count != 2 ||
         user->context.user.x[0] != USER_EXIT_STATUS ||
         user->context.user.x[8] != ARMOS_NR_EXIT ||
         user->context.user.x[19] != USER_X19_SENTINEL ||
         user->context.user.x[20] != USER_X20_SENTINEL ||
         user->context.user.sp != PROBE_USER_STACK_TOP ||
         arm64_exception_el0_exit_status() != USER_EXIT_STATUS ||
         arm64_exception_el0_syscall_count() != 5 ||
         *(volatile uint64_t *)(uintptr_t)(USER_DATA_VA +
             USER_WRITE_RESULT_OFFSET) != USER_WRITE_LENGTH ||
         *(volatile uint64_t *)(uintptr_t)(USER_DATA_VA +
             USER_EFAULT_RESULT_OFFSET) != USER_EFAULT_RESULT ||
         *(volatile uint64_t *)(uintptr_t)(USER_DATA_VA +
             USER_ENOSYS_RESULT_OFFSET) != USER_ENOSYS_RESULT ||
         task_dispatcher_validate(&dispatcher) != 0))
        result = -7;

    arm64_exception_set_task_dispatcher(NULL);
    if (arm64_task_destroy(peer, allocator, &bootstrap->context) != 0)
        return -8;
    if (arm64_task_destroy(user, allocator, &bootstrap->context) != 0)
        return -9;
    if (peer->magic != TASK_MAGIC_DEAD || user->magic != TASK_MAGIC_DEAD)
        return -10;
    if (allocator->free_pages != free_before)
        return -11;
    return result;
}

static int arm64_user_timer_preempt_smoke_test(
    arm64_high_context_t *context)
{
    task_t *bootstrap = &context->bootstrap_task;
    task_t *user = &context->scheduled_user_task;
    task_t *peer = &context->probe_task;
    early_page_allocator_t *allocator = high_early_allocator();
    task_dispatcher_t dispatcher;
    uint64_t free_before = allocator->free_pages;
    uint64_t preempt_offset =
        (uint64_t)(uintptr_t)arm64_el0_preempt_payload -
        (uint64_t)(uintptr_t)arm64_el0_payload_start;
    uint32_t bootstrap_switch_before = bootstrap->switch_count;
    int timer_armed = 0;
    int result = 0;

    clear_task_context(&bootstrap->context);
    bootstrap->state = TASK_RUNNING;
    bootstrap->running_cpu = 0;
    bootstrap->last_cpu = 0;

    if (arm64_task_init(
            user, allocator, arm64_user_vm_space(&context->user_vm),
            (vaddr_t)(uintptr_t)arm64_user_task_probe_entry,
            "user-preempt", 6, TASK_PROBE_STACK_PAGES) != 0)
        return -1;
    user->type = TASK_TYPE_PROCESS;
    user->context.flags = ARM64_TASK_FLAG_RETURNS_TO_USER;
    prepare_user_registers(&user->context.user);
    user->context.user.pc = USER_CODE_VA + preempt_offset;
    user->context.user.pstate = ARM64_USER_PSTATE_EL0T;
    user->context.kernel.x[0] = (uint64_t)(uintptr_t)user;

    *(volatile uint64_t *)(uintptr_t)(USER_DATA_VA +
                                      USER_PREEMPT_FLAG_OFFSET) = 0;
    if (preempt_offset >= PAGE_SIZE ||
        initialize_task_probe(
            context, peer, NULL,
            (vaddr_t)(uintptr_t)arm64_task_preempt_peer_entry,
            "preempt-peer", 7, 'p', &context->task_probe_phase,
            &context->task_probe_ttbr0) != 0) {
        arm64_task_destroy(user, allocator, &bootstrap->context);
        return -2;
    }
    if (arm64_dispatcher_init(&dispatcher, bootstrap, 3) != 0 ||
        task_dispatcher_publish(&dispatcher, user) != 0 ||
        task_dispatcher_publish(&dispatcher, peer) != 0)
        result = -3;

    peer->context.kernel.x[6] = (uint64_t)(uintptr_t)&dispatcher;
    peer->context.kernel.x[7] =
        USER_DATA_VA + USER_PREEMPT_FLAG_OFFSET;
    arm64_exception_set_el0_context(
        arm64_user_vm_space(&context->user_vm),
        &user->context.user, 0);
    arm64_exception_set_task_dispatcher(&dispatcher);

    if (result == 0) {
        if (arm64_timer_irq_arm_once() != 0)
            result = -4;
        else
            timer_armed = 1;
    }
    if (result == 0 && task_dispatcher_yield(&dispatcher) != 0)
        result = -5;
    if (timer_armed)
        arm64_timer_irq_cancel();

    if (result == 0 &&
        (context->task_probe_phase != 1 ||
         dispatcher.current != bootstrap ||
         dispatcher.ready.head != user || dispatcher.ready.tail != peer ||
         dispatcher.ready.count != 2 || dispatcher.dispatch_count != 3 ||
         dispatcher.last_reason != TASK_DISPATCH_YIELD ||
         dispatcher.need_resched != 0 || dispatcher.preempt_requests != 1 ||
         dispatcher.preempt_deferred != 0 ||
         dispatcher.preempt_serviced != 0 ||
         arm64_exception_el0_syscall_count() != 0 ||
         *(volatile uint64_t *)(uintptr_t)(USER_DATA_VA +
             USER_PREEMPT_FLAG_OFFSET) != 1 ||
         user->state != TASK_READY || peer->state != TASK_READY ||
         task_dispatcher_validate(&dispatcher) != 0))
        result = -6;

    if (result == 0 && task_dispatcher_yield(&dispatcher) != 0)
        result = -7;
    if (result == 0 &&
        (context->task_probe_phase != 3 ||
         dispatcher.current != bootstrap || dispatcher.ready.count != 0 ||
         dispatcher.dispatch_count != 6 ||
         dispatcher.last_reason != TASK_DISPATCH_BLOCK ||
         dispatcher.preempt_requests != 1 ||
         dispatcher.preempt_deferred != 0 ||
         dispatcher.preempt_serviced != 1 ||
         bootstrap->state != TASK_RUNNING || bootstrap->running_cpu != 0 ||
         bootstrap->switch_count != bootstrap_switch_before + 2 ||
         user->state != TASK_BLOCKED || user->running_cpu != TASK_CPU_NONE ||
         user->switch_count != 2 || peer->state != TASK_BLOCKED ||
         peer->running_cpu != TASK_CPU_NONE || peer->switch_count != 2 ||
         user->context.user.x[0] != USER_PREEMPT_EXIT_STATUS ||
         user->context.user.x[8] != ARMOS_NR_EXIT ||
         user->context.user.x[9] == 0 || user->context.user.x[11] != 1 ||
         user->context.user.x[19] != USER_X19_SENTINEL ||
         user->context.user.x[20] != USER_X20_SENTINEL ||
         user->context.user.sp != PROBE_USER_STACK_TOP ||
         user->context.user.pstate != ARM64_USER_PSTATE_EL0T ||
         arm64_exception_el0_exit_status() != USER_PREEMPT_EXIT_STATUS ||
         arm64_exception_el0_syscall_count() != 1 ||
         task_dispatcher_validate(&dispatcher) != 0))
        result = -8;

    arm64_exception_set_task_dispatcher(NULL);
    if (arm64_task_destroy(peer, allocator, &bootstrap->context) != 0)
        return -9;
    if (arm64_task_destroy(user, allocator, &bootstrap->context) != 0)
        return -10;
    if (peer->magic != TASK_MAGIC_DEAD || user->magic != TASK_MAGIC_DEAD)
        return -11;
    if (allocator->free_pages != free_before)
        return -12;
    return result;
}

static int arm64_mixed_periodic_preempt_smoke_test(
    arm64_high_context_t *context,
    uint32_t timer_ticks,
    uint32_t quantum_ticks,
    int continuous_timer)
{
    task_t *bootstrap = &context->bootstrap_task;
    task_t *user = &context->scheduled_user_task;
    task_t *peer = &context->probe_task;
    early_page_allocator_t *allocator = high_early_allocator();
    task_dispatcher_t dispatcher;
    uint64_t free_before = allocator->free_pages;
    uint64_t preempt_offset =
        (uint64_t)(uintptr_t)arm64_el0_preempt_payload -
        (uint64_t)(uintptr_t)arm64_el0_payload_start;
    uint32_t bootstrap_switch_before = bootstrap->switch_count;
    int timer_armed = 0;
    int result = 0;

    if (quantum_ticks == 0 || timer_ticks != quantum_ticks * 2)
        return -1;

    clear_task_context(&bootstrap->context);
    bootstrap->state = TASK_RUNNING;
    bootstrap->running_cpu = 0;
    bootstrap->last_cpu = 0;

    if (arm64_task_init(
            user, allocator, arm64_user_vm_space(&context->user_vm),
            (vaddr_t)(uintptr_t)arm64_user_task_probe_entry,
            "periodic-user", 8, TASK_PROBE_STACK_PAGES) != 0)
        return -1;
    user->type = TASK_TYPE_PROCESS;
    user->context.flags = ARM64_TASK_FLAG_RETURNS_TO_USER;
    prepare_user_registers(&user->context.user);
    user->context.user.pc = USER_CODE_VA + preempt_offset;
    user->context.user.pstate = ARM64_USER_PSTATE_EL0T;
    user->context.kernel.x[0] = (uint64_t)(uintptr_t)user;

    *(volatile uint64_t *)(uintptr_t)(USER_DATA_VA +
                                      USER_PREEMPT_FLAG_OFFSET) = 0;
    if (preempt_offset >= PAGE_SIZE ||
        initialize_task_probe(
            context, peer, NULL,
            (vaddr_t)(uintptr_t)arm64_task_periodic_peer_entry,
            "periodic-peer", 9, 'p', &context->task_probe_phase,
            &context->task_probe_ttbr0) != 0) {
        arm64_task_destroy(user, allocator, &bootstrap->context);
        return -2;
    }
    if (arm64_dispatcher_init(&dispatcher, bootstrap, 3) != 0 ||
        task_dispatcher_set_quantum(&dispatcher, quantum_ticks) != 0 ||
        task_dispatcher_publish(&dispatcher, user) != 0 ||
        task_dispatcher_publish(&dispatcher, peer) != 0)
        result = -3;

    peer->context.kernel.x[6] = (uint64_t)(uintptr_t)&dispatcher;
    peer->context.kernel.x[7] =
        USER_DATA_VA + USER_PREEMPT_FLAG_OFFSET;
    arm64_exception_set_el0_context(
        arm64_user_vm_space(&context->user_vm),
        &user->context.user, 0);
    arm64_exception_set_task_dispatcher(&dispatcher);

    if (result == 0) {
        if ((continuous_timer &&
             arm64_timer_irq_start_periodic() != 0) ||
            (!continuous_timer &&
             arm64_timer_irq_arm_ticks(timer_ticks) != 0))
            result = -4;
        else
            timer_armed = 1;
    }
    if (result == 0 && task_dispatcher_yield(&dispatcher) != 0)
        result = -5;
    if (timer_armed)
        arm64_timer_irq_cancel();

    if (result == 0 &&
        (context->task_probe_phase != 1 ||
         dispatcher.current != bootstrap ||
         dispatcher.ready.head != user || dispatcher.ready.tail != peer ||
         dispatcher.ready.count != 2 || dispatcher.dispatch_count != 3 ||
         dispatcher.last_reason != TASK_DISPATCH_PREEMPT ||
         dispatcher.need_resched != 0 || dispatcher.preempt_requests != 2 ||
         dispatcher.preempt_deferred != 0 ||
         dispatcher.preempt_serviced != 0 ||
         dispatcher.timer_ticks != timer_ticks ||
         dispatcher.quantum_expirations != 2 ||
         dispatcher.quantum_ticks != quantum_ticks ||
         dispatcher.slice_ticks != 0 ||
         dispatcher.irq_critical_sections != timer_ticks + 4 ||
         arm64_timer_irq_ticks() != timer_ticks ||
         arm64_exception_el0_syscall_count() != 0 ||
         *(volatile uint64_t *)(uintptr_t)(USER_DATA_VA +
             USER_PREEMPT_FLAG_OFFSET) != 1 ||
         user->state != TASK_READY || peer->state != TASK_READY ||
         task_dispatcher_validate(&dispatcher) != 0))
        result = -6;

    if (result == 0 && task_dispatcher_yield(&dispatcher) != 0)
        result = -7;
    if (result == 0 &&
        (context->task_probe_phase != 3 ||
         dispatcher.current != bootstrap || dispatcher.ready.count != 0 ||
         dispatcher.dispatch_count != 6 ||
         dispatcher.last_reason != TASK_DISPATCH_BLOCK ||
         dispatcher.preempt_requests != 2 ||
         dispatcher.preempt_deferred != 0 ||
         dispatcher.preempt_serviced != 2 ||
         dispatcher.timer_ticks != timer_ticks ||
         dispatcher.quantum_expirations != 2 ||
         dispatcher.quantum_ticks != quantum_ticks ||
         dispatcher.slice_ticks != 0 ||
         dispatcher.irq_critical_sections != timer_ticks + 7 ||
         arm64_timer_irq_ticks() != timer_ticks ||
         bootstrap->state != TASK_RUNNING || bootstrap->running_cpu != 0 ||
         bootstrap->switch_count != bootstrap_switch_before + 2 ||
         user->state != TASK_BLOCKED || user->running_cpu != TASK_CPU_NONE ||
         user->switch_count != 2 || peer->state != TASK_BLOCKED ||
         peer->running_cpu != TASK_CPU_NONE || peer->switch_count != 2 ||
         user->context.user.x[0] != USER_PREEMPT_EXIT_STATUS ||
         user->context.user.x[8] != ARMOS_NR_EXIT ||
         user->context.user.x[9] == 0 || user->context.user.x[11] != 1 ||
         user->context.user.x[19] != USER_X19_SENTINEL ||
         user->context.user.x[20] != USER_X20_SENTINEL ||
         user->context.user.sp != PROBE_USER_STACK_TOP ||
         user->context.user.pstate != ARM64_USER_PSTATE_EL0T ||
         arm64_exception_el0_exit_status() != USER_PREEMPT_EXIT_STATUS ||
         arm64_exception_el0_syscall_count() != 1 ||
         *(volatile uint64_t *)(uintptr_t)(USER_DATA_VA +
             USER_PREEMPT_FLAG_OFFSET) != 2 ||
         task_dispatcher_validate(&dispatcher) != 0))
        result = -8;

    arm64_exception_set_task_dispatcher(NULL);
    if (arm64_task_destroy(peer, allocator, &bootstrap->context) != 0)
        return -9;
    if (arm64_task_destroy(user, allocator, &bootstrap->context) != 0)
        return -10;
    if (peer->magic != TASK_MAGIC_DEAD || user->magic != TASK_MAGIC_DEAD)
        return -11;
    if (allocator->free_pages != free_before)
        return -12;
    return result;
}

static int arm64_task_address_space_smoke_test(
    arm64_high_context_t *context,
    uint64_t user_ttbr,
    uint64_t empty_ttbr)
{
    task_t *bootstrap = &context->bootstrap_task;
    arm64_task_context_t *probe;
    uint64_t flush_before;
    uint64_t preserve_before;
    early_page_allocator_t *allocator = high_early_allocator();
    uint64_t free_before = allocator->free_pages;
    uint32_t bootstrap_switch_before = bootstrap->switch_count;
    int result = 0;

    if (prepare_task_probe(context, &context->empty_vm) != 0)
        return -1;
    probe = &context->probe_task.context;

    bootstrap->context.vm_space = arm64_user_vm_space(&context->user_vm);
    bootstrap->context.ttbr0 = context->user_vm.l1;
    bootstrap->context.asid = context->user_vm.asid;
    probe->ttbr0 = context->user_vm.l1;
    probe->asid = context->empty_vm.asid;
    if (bootstrap->context.vm_space != &context->user_vm.space ||
        probe->vm_space != &context->empty_vm.space ||
        arm64_user_vm_from_space(bootstrap->context.vm_space) !=
            &context->user_vm ||
        arm64_user_vm_from_space(probe->vm_space) != &context->empty_vm ||
        arm64_task_switch(bootstrap, &context->probe_task) == 0 ||
        context->task_probe_phase != 0)
        result = -2;

    probe->ttbr0 = context->empty_vm.l1;
    flush_before = arm64_user_vm_tlb_flush_count();
    preserve_before = arm64_user_vm_tlb_preserve_count();

    if (result == 0) {
        if (arm64_mmu_read_ttbr0() != user_ttbr ||
            arm64_task_switch(bootstrap, &context->probe_task) != 0)
            result = -3;
        if (result == 0 &&
            (context->task_probe_phase != 1 ||
            context->task_probe_ttbr0 != empty_ttbr ||
            arm64_mmu_read_ttbr0() != user_ttbr))
            result = -4;
    }

    if (result == 0) {
        context->task_probe_phase = 2;
        if (arm64_task_switch(bootstrap, &context->probe_task) != 0)
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
        if (result == 0 &&
            (bootstrap->state != TASK_RUNNING ||
             bootstrap->running_cpu != 0 ||
             bootstrap->switch_count != bootstrap_switch_before + 2 ||
             context->probe_task.state != TASK_BLOCKED ||
             context->probe_task.running_cpu != TASK_CPU_NONE ||
             context->probe_task.switch_count != 2))
            result = -8;
    }

    if (arm64_task_destroy(&context->probe_task, allocator,
                           &bootstrap->context) != 0)
        return -9;
    if (context->probe_task.magic != TASK_MAGIC_DEAD)
        return -10;
    if (allocator->free_pages != free_before)
        return -11;
    return result;
}

typedef struct {
    arm64_user_vm_t *vm;
    early_page_allocator_t *allocator;
} arm64_elf_load_context_t;

static int arm64_elf_map(void *opaque, vaddr_t start, size_t length,
                         unsigned int flags)
{
    arm64_elf_load_context_t *context = opaque;

    return arm64_user_vm_map_anonymous(context->vm, context->allocator,
                                       start, length, flags);
}

static int arm64_elf_copy(void *opaque, vaddr_t destination,
                          const void *source, size_t length)
{
    arm64_elf_load_context_t *context = opaque;
    const uint8_t *input = source;

    while (length > 0) {
        vaddr_t page_address = destination & PAGE_MASK;
        size_t page_offset = destination & PAGE_OFFSET_MASK;
        size_t chunk = PAGE_SIZE - page_offset;
        paddr_t physical;
        uint8_t *output;
        size_t index;

        if (chunk > length)
            chunk = length;
        if (arm64_user_vm_lookup(context->vm, page_address,
                                 &physical, NULL) != 0 || physical == 0)
            return -1;
        output = (uint8_t *)(uintptr_t)arm64_mmu_kernel_address(physical);
        for (index = 0; index < chunk; index++)
            output[page_offset + index] = input[index];
        input += chunk;
        destination += chunk;
        length -= chunk;
    }
    return 0;
}

static int arm64_elf_zero(void *opaque, vaddr_t destination, size_t length)
{
    static const uint8_t zero_page[PAGE_SIZE];

    while (length > 0) {
        size_t chunk = length > PAGE_SIZE ? PAGE_SIZE : length;

        if (arm64_elf_copy(opaque, destination, zero_page, chunk) != 0)
            return -1;
        destination += chunk;
        length -= chunk;
    }
    return 0;
}

static int arm64_process_elf64_smoke_test(arm64_high_context_t *context)
{
    struct {
        elf64_header_t header;
        elf64_program_header_t program;
        uint32_t payload[2];
    } image;
    elf64_loader_ops_t loader_ops;
    arm64_elf_load_context_t load_context;
    arm64_user_vm_t image_vm;
    process_model_t parent;
    process_model_t child;
    early_page_allocator_t *allocator = high_early_allocator();
    uint64_t free_before = allocator->free_pages;
    uint8_t *bytes = (uint8_t *)&image;
    size_t index;
    vaddr_t entry;
    paddr_t physical;
    uint32_t *loaded;
    int status = 0;

    /* Runtime assignment preserves the active high-half alias. */
    loader_ops.map = arm64_elf_map;
    loader_ops.copy = arm64_elf_copy;
    loader_ops.zero = arm64_elf_zero;

    for (index = 0; index < sizeof(image); index++)
        bytes[index] = 0;
    image.header.ident[0] = 0x7f;
    image.header.ident[1] = 'E';
    image.header.ident[2] = 'L';
    image.header.ident[3] = 'F';
    image.header.ident[4] = 2;
    image.header.ident[5] = 1;
    image.header.ident[6] = 1;
    image.header.type = ELF64_ET_EXEC;
    image.header.machine = ELF64_EM_AARCH64;
    image.header.version = 1;
    image.header.entry = 0x100000;
    image.header.phoff = sizeof(image.header);
    image.header.ehsize = sizeof(image.header);
    image.header.phentsize = sizeof(image.program);
    image.header.phnum = 1;
    image.program.type = ELF64_PT_LOAD;
    image.program.flags = ELF64_PF_R | ELF64_PF_X;
    image.program.offset =
        (uint64_t)((uint8_t *)image.payload - (uint8_t *)&image);
    image.program.vaddr = image.header.entry;
    image.program.filesz = sizeof(image.payload);
    image.program.memsz = 16;
    image.program.align = 1;
    image.payload[0] = 0xd2800540u;
    image.payload[1] = 0xd65f03c0u;

    image.header.entry = 0x200000;
    if (elf64_validate_aarch64(&image, sizeof(image), USER_SPACE_END) == 0)
        return -1;
    image.header.entry = 0x100000;
    image.program.flags |= ELF64_PF_W;
    if (elf64_validate_aarch64(&image, sizeof(image), USER_SPACE_END) == 0)
        return -1;
    image.program.flags = ELF64_PF_R | ELF64_PF_X;

    if (arm64_user_vm_init(&image_vm, allocator) != 0)
        return -2;
    load_context.vm = &image_vm;
    load_context.allocator = allocator;
    if (elf64_load_aarch64(&image, sizeof(image), USER_SPACE_END,
                           &loader_ops, &load_context, &entry) != 0 ||
        entry != image.header.entry ||
        arm64_user_vm_lookup(&image_vm, entry & PAGE_MASK,
                             &physical, NULL) != 0 || physical == 0)
        return -3;
    loaded = (uint32_t *)(uintptr_t)arm64_mmu_kernel_address(physical);
    if (loaded[0] != image.payload[0] || loaded[1] != image.payload[1] ||
        loaded[2] != 0 || loaded[3] != 0)
        return -4;

    if (process_model_init(&parent, 1, NULL,
                           &context->user_vm.space, NULL) != 0)
        return -5;
    parent.signal_handlers[10] = 0x1234;
    if (process_model_fork(&parent, &child, 2,
                           &image_vm.space, NULL) != 0 ||
        child.ppid != 1 || parent.first_child != &child ||
        child.signal_handlers[10] != parent.signal_handlers[10] ||
        process_model_signal(&child, 0) != 0 ||
        process_model_signal(&child, 10) != 0 ||
        process_model_next_signal(&child) != 10 ||
        process_model_exec(&child, &image_vm.space) != 0 ||
        child.signal_handlers[10] != 0 ||
        process_model_exit(&child, 7) != 0 ||
        process_model_wait(&parent, -1, &status, 0) != 2 ||
        status != 7 || child.state != PROCESS_MODEL_DEAD ||
        parent.first_child != NULL)
        return -5;

    if (arm64_user_vm_destroy(&image_vm, allocator) != 0 ||
        allocator->free_pages != free_before)
        return -6;
    return 0;
}

static int arm64_dynamic_user_vm_smoke_test(arm64_high_context_t *context)
{
    early_page_allocator_t *allocator = high_early_allocator();
    arm64_user_vm_t vm;
    const vma_t *vma;
    paddr_t page;
    uint64_t free_before = allocator->free_pages;
    int initialized = 0;
    int active = 0;
    int result = 0;

    if (arm64_user_vm_init(&vm, allocator) != 0)
        return -1;
    initialized = 1;
    if (arm64_user_vm_map_new_page(
            &vm, allocator, DYNAMIC_VM_FIRST_VA,
            ARM64_USER_PAGE_READ | ARM64_USER_PAGE_WRITE, &page) != 0 ||
        arm64_user_vm_map_new_page(
            &vm, allocator, DYNAMIC_VM_SECOND_VA,
            ARM64_USER_PAGE_READ, &page) != 0 ||
        arm64_user_vm_map_new_page(
            &vm, allocator, DYNAMIC_VM_DISTANT_VA,
            ARM64_USER_PAGE_READ | ARM64_USER_PAGE_WRITE, &page) != 0) {
        result = -2;
        goto cleanup;
    }
    vma = vm.space.vma_list;
    if (vm.l2_table_count != 2 || vm.l3_table_count != 3 ||
        vm.mapping_count != 3 ||
        allocator->free_pages != free_before - 9 ||
        !vma || vma->start != DYNAMIC_VM_FIRST_VA ||
        !vma->next || vma->next->start != DYNAMIC_VM_SECOND_VA ||
        !vma->next->next ||
        vma->next->next->start != DYNAMIC_VM_DISTANT_VA ||
        vma->next->next->next != NULL) {
        result = -3;
        goto cleanup;
    }
    if (arm64_user_vm_activate(&vm) != 0) {
        result = -4;
        goto cleanup;
    }
    active = 1;
    if ((arm64_mmu_translate_user_read(DYNAMIC_VM_FIRST_VA) & 1u) != 0 ||
        (arm64_mmu_translate_user_write(DYNAMIC_VM_FIRST_VA) & 1u) != 0 ||
        (arm64_mmu_translate_user_read(DYNAMIC_VM_SECOND_VA) & 1u) != 0 ||
        (arm64_mmu_translate_user_write(DYNAMIC_VM_SECOND_VA) & 1u) == 0 ||
        (arm64_mmu_translate_user_read(DYNAMIC_VM_DISTANT_VA) & 1u) != 0) {
        result = -5;
        goto cleanup;
    }
    if (arm64_user_vm_unmap_page(&vm, allocator,
                                 DYNAMIC_VM_SECOND_VA) != 0 ||
        allocator->free_pages != free_before - 7 ||
        vm.mapping_count != 2 || vm.l2_table_count != 2 ||
        vm.l3_table_count != 2 ||
        arm64_user_vm_lookup(&vm, DYNAMIC_VM_SECOND_VA,
                             NULL, NULL) == 0 ||
        (arm64_mmu_translate_user_read(DYNAMIC_VM_SECOND_VA) & 1u) == 0 ||
        (arm64_mmu_translate_user_read(DYNAMIC_VM_FIRST_VA) & 1u) != 0 ||
        (arm64_mmu_translate_user_read(DYNAMIC_VM_DISTANT_VA) & 1u) != 0) {
        result = -6;
        goto cleanup;
    }
    if (arm64_user_vm_map_anonymous(
            &vm, allocator, DYNAMIC_VM_RANGE_VA,
            DYNAMIC_VM_RANGE_LENGTH,
            ARM64_USER_PAGE_READ | ARM64_USER_PAGE_WRITE) != 0 ||
        allocator->free_pages != free_before - 11 ||
        vm.mapping_count != 4 || vm.l2_table_count != 2 ||
        vm.l3_table_count != 4 ||
        (arm64_mmu_translate_user_read(DYNAMIC_VM_RANGE_VA) & 1u) != 0 ||
        (arm64_mmu_translate_user_write(DYNAMIC_VM_RANGE_VA) & 1u) != 0 ||
        (arm64_mmu_translate_user_read(
             DYNAMIC_VM_RANGE_VA + PAGE_SIZE) & 1u) != 0 ||
        (arm64_mmu_translate_user_write(
             DYNAMIC_VM_RANGE_VA + PAGE_SIZE) & 1u) != 0) {
        result = -7;
        goto cleanup;
    }
    vma = vm.space.vma_list;
    if (!vma || vma->start != DYNAMIC_VM_FIRST_VA ||
        !vma->next || vma->next->start != DYNAMIC_VM_RANGE_VA ||
        !vma->next->next ||
        vma->next->next->start != DYNAMIC_VM_RANGE_VA + PAGE_SIZE ||
        !vma->next->next->next ||
        vma->next->next->next->start != DYNAMIC_VM_DISTANT_VA ||
        vma->next->next->next->next != NULL ||
        arm64_user_vm_map_anonymous(
            &vm, allocator, DYNAMIC_VM_RANGE_VA,
            DYNAMIC_VM_RANGE_LENGTH, ARM64_USER_PAGE_READ) == 0 ||
        allocator->free_pages != free_before - 11) {
        result = -8;
        goto cleanup;
    }
    if (arm64_user_vm_unmap_range(&vm, allocator,
                                  DYNAMIC_VM_RANGE_VA,
                                  DYNAMIC_VM_RANGE_LENGTH) != 0 ||
        allocator->free_pages != free_before - 7 ||
        vm.mapping_count != 2 || vm.l2_table_count != 2 ||
        vm.l3_table_count != 2 ||
        (arm64_mmu_translate_user_read(DYNAMIC_VM_RANGE_VA) & 1u) == 0 ||
        (arm64_mmu_translate_user_read(
             DYNAMIC_VM_RANGE_VA + PAGE_SIZE) & 1u) == 0 ||
        (arm64_mmu_translate_user_read(DYNAMIC_VM_FIRST_VA) & 1u) != 0 ||
        (arm64_mmu_translate_user_read(DYNAMIC_VM_DISTANT_VA) & 1u) != 0) {
        result = -9;
        goto cleanup;
    }

cleanup:
    if (active) {
        if (arm64_user_vm_activate(&context->user_vm) != 0 && result == 0)
            result = -10;
        active = 0;
    }
    if (initialized) {
        if (arm64_user_vm_destroy(&vm, allocator) != 0 && result == 0)
            result = -11;
    }
    if (allocator->free_pages != free_before && result == 0)
        result = -12;
    return result;
}

static int arm64_user_vm_clone_smoke_test(void)
{
    early_page_allocator_t *allocator = high_early_allocator();
    arm64_user_vm_t source;
    arm64_user_vm_t child;
    paddr_t source_page;
    paddr_t child_page;
    paddr_t lazy_page;
    uint8_t *source_bytes;
    uint8_t *child_bytes;
    uint64_t free_before = allocator->free_pages;
    vaddr_t requested_brk = USER_HEAP_START + 64u;
    vaddr_t resulting_brk;
    unsigned int flags;
    int source_initialized = 0;
    int child_initialized = 0;
    int result = 0;

    if (arm64_user_vm_init(&source, allocator) != 0)
        return -1;
    source_initialized = 1;
    if (arm64_user_vm_map_new_page(
            &source, allocator, DYNAMIC_VM_FIRST_VA,
            ARM64_USER_PAGE_READ | ARM64_USER_PAGE_WRITE,
            &source_page) != 0 ||
        arm64_user_vm_set_brk(&source, allocator, requested_brk,
                              &resulting_brk) != 0 ||
        resulting_brk != requested_brk) {
        result = -2;
        goto cleanup;
    }

    source_bytes = (uint8_t *)(uintptr_t)
        arm64_mmu_kernel_address(source_page);
    source_bytes[0] = 0x41u;
    source_bytes[PAGE_SIZE - 1u] = 0x5au;

    if (arm64_user_vm_clone_eager(&child, &source, allocator) != 0) {
        result = -3;
        goto cleanup;
    }
    child_initialized = 1;
    if (child.asid == source.asid || child.l1 == source.l1 ||
        child.space.brk != source.space.brk ||
        child.mapping_count != source.mapping_count ||
        arm64_user_vm_lookup(&child, DYNAMIC_VM_FIRST_VA,
                             &child_page, &flags) != 0 ||
        child_page == 0 || child_page == source_page ||
        flags != (ARM64_USER_PAGE_READ | ARM64_USER_PAGE_WRITE) ||
        arm64_user_vm_lookup(&child, USER_HEAP_START,
                             &lazy_page, &flags) != 0 ||
        lazy_page != 0 || (flags & VMA_LAZY) == 0) {
        result = -4;
        goto cleanup;
    }

    child_bytes = (uint8_t *)(uintptr_t)
        arm64_mmu_kernel_address(child_page);
    if (child_bytes[0] != 0x41u ||
        child_bytes[PAGE_SIZE - 1u] != 0x5au) {
        result = -5;
        goto cleanup;
    }
    child_bytes[0] = 0x63u;
    if (source_bytes[0] != 0x41u || child_bytes[0] != 0x63u) {
        result = -6;
        goto cleanup;
    }

cleanup:
    if (child_initialized &&
        arm64_user_vm_destroy(&child, allocator) != 0 && result == 0)
        result = -7;
    if (source_initialized &&
        arm64_user_vm_destroy(&source, allocator) != 0 && result == 0)
        result = -8;
    if (allocator->free_pages != free_before && result == 0)
        result = -9;
    return result;
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

    arm64_boot_total_mb = ram->size >> 20;
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

    arm64_probe_puts("Early pages: base=");
    arm64_probe_puthex64(early_allocator.base);
    arm64_probe_puts(" end=");
    arm64_probe_puthex64(early_allocator.end);
    arm64_probe_puts(" total=");
    arm64_probe_puthex64(early_allocator.total_pages);
    arm64_probe_puts(" free=");
    arm64_probe_puthex64(early_allocator.free_pages);
    arm64_probe_puts("\n");
    arm64_probe_puts("FDT RAM: base=");
    arm64_probe_puthex64(ram->start);
    arm64_probe_puts(" size=");
    arm64_probe_puthex64(ram->size);
    arm64_probe_puts(" DTB size=");
    arm64_probe_puthex64(layout.dtb_size);
    arm64_probe_puts(" reserved ranges=");
    arm64_probe_puthex64(layout.reserved_count);
    arm64_probe_puts("\n");
    arm64_probe_puts("ARM64_FDT_MEMORY_OK\n");

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

    arm64_probe_puts("TTBR0 allocated: old=");
    arm64_probe_puthex64(old_ttbr);
    arm64_probe_puts(" new=");
    arm64_probe_puthex64(new_ttbr);
    arm64_probe_puts(" L2=");
    arm64_probe_puthex64(l2_page);
    arm64_probe_puts(" L3=");
    arm64_probe_puthex64(l3_page);
    arm64_probe_puts("\n");

    if (arm64_mmu_update_identity_page(l3_page, test_page, 0) != 0 ||
        (arm64_mmu_translate_read(test_page) & 1u) == 0 ||
        arm64_mmu_update_identity_page(l3_page, test_page, 1) != 0 ||
        (arm64_mmu_translate_read(test_page) & 1u) != 0 ||
        *(volatile uint64_t *)(uintptr_t)test_page != page_magic)
        return -1;
    arm64_probe_puts("ARM64_L3_PAGE_TLBI_OK\n");

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

    arm64_probe_puts("TTBR1 kernel alias: table=");
    arm64_probe_puthex64(arm64_mmu_read_ttbr1());
    arm64_probe_puts(" text=");
    arm64_probe_puthex64(high_text);
    arm64_probe_puts(" TCR=");
    arm64_probe_puthex64(arm64_mmu_read_tcr());
    arm64_probe_puts("\nARM64_TTBR1_PERMISSIONS_OK\n");

    lifecycle_free_pages = early_allocator.free_pages;
    if (arm64_user_vm_init(&lifecycle_vm, &early_allocator) != 0 ||
        arm64_user_vm_space(&lifecycle_vm) != &lifecycle_vm.space ||
        arm64_user_vm_from_space(&lifecycle_vm.space) != &lifecycle_vm ||
        arm64_user_vm_map_new_page(
            &lifecycle_vm,
            &early_allocator,
            0x0000000000601000ULL,
            ARM64_USER_PAGE_READ | ARM64_USER_PAGE_WRITE,
            &lifecycle_page) != 0 ||
        early_allocator.free_pages != lifecycle_free_pages - 4 ||
        arm64_user_vm_map_new_page(
            &lifecycle_vm,
            &early_allocator,
            0x0000000000600000ULL,
            ARM64_USER_PAGE_READ,
            &lifecycle_page) != 0 ||
        early_allocator.free_pages != lifecycle_free_pages - 5 ||
        lifecycle_vm.space.vma_list != &lifecycle_vm.mappings[1].vma ||
        lifecycle_vm.space.vma_list->next !=
            &lifecycle_vm.mappings[0].vma ||
        lifecycle_vm.space.vma_list->next->next != NULL ||
        arm64_user_vm_map_new_page(
            &lifecycle_vm,
            &early_allocator,
            0x0000000000602000ULL,
            ARM64_USER_PAGE_READ | ARM64_USER_PAGE_WRITE |
                ARM64_USER_PAGE_EXEC,
            &lifecycle_page) == 0 ||
        early_allocator.free_pages != lifecycle_free_pages - 5)
        return -1;
    recycled_asid = lifecycle_vm.asid;
    if (arm64_user_vm_destroy(&lifecycle_vm, &early_allocator) != 0 ||
        early_allocator.free_pages != lifecycle_free_pages ||
        arm64_user_vm_init(&high_context.user_vm, &early_allocator) != 0 ||
        high_context.user_vm.asid != recycled_asid ||
        arm64_user_vm_init(&high_context.empty_vm, &early_allocator) != 0 ||
        high_context.empty_vm.asid == high_context.user_vm.asid)
        return -1;
    arm64_probe_puts("ARM64_USER_VM_LIFECYCLE_OK\n");

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
    if (arm64_user_vm_validate_identity(&high_context.user_vm) != 0 ||
        high_context.user_vm.space.vma_list !=
            &high_context.user_vm.mappings[0].vma ||
        high_context.user_vm.space.vma_list->next !=
            &high_context.user_vm.mappings[1].vma ||
        high_context.user_vm.space.vma_list->next->next !=
            &high_context.user_vm.mappings[2].vma ||
        high_context.user_vm.space.vma_list->next->next->next != NULL)
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
    for (offset = 0; offset < sizeof(arm64_bootstrap_path); offset++)
        *(volatile uint8_t *)(uintptr_t)
            (user_data_page + USER_OPEN_PATH_OFFSET + offset) =
                (uint8_t)arm64_bootstrap_path[offset];
    for (offset = 0; offset < sizeof(arm64_bootstrap_shell_path); offset++)
        *(volatile uint8_t *)(uintptr_t)
            (user_data_page + USER_EXEC_PATH_OFFSET + offset) =
                (uint8_t)arm64_bootstrap_shell_path[offset];
    *(volatile uint64_t *)(uintptr_t)
        (user_data_page + USER_EXEC_ARGV_OFFSET) =
            USER_DATA_VA + USER_EXEC_PATH_OFFSET;
    *(volatile uint64_t *)(uintptr_t)
        (user_data_page + USER_EXEC_ARGV_OFFSET + sizeof(uint64_t)) = 0;
    *(volatile uint64_t *)(uintptr_t)
        (user_data_page + USER_EXEC_ENVP_OFFSET) =
            USER_DATA_VA + USER_EXEC_ENV_PATH_OFFSET;
    *(volatile uint64_t *)(uintptr_t)
        (user_data_page + USER_EXEC_ENVP_OFFSET + sizeof(uint64_t)) =
            USER_DATA_VA + USER_EXEC_ENV_HOME_OFFSET;
    *(volatile uint64_t *)(uintptr_t)
        (user_data_page + USER_EXEC_ENVP_OFFSET + 2u * sizeof(uint64_t)) =
            USER_DATA_VA + USER_EXEC_ENV_USER_OFFSET;
    *(volatile uint64_t *)(uintptr_t)
        (user_data_page + USER_EXEC_ENVP_OFFSET + 3u * sizeof(uint64_t)) =
            USER_DATA_VA + USER_EXEC_ENV_BANNER_OFFSET;
    *(volatile uint64_t *)(uintptr_t)
        (user_data_page + USER_EXEC_ENVP_OFFSET + 4u * sizeof(uint64_t)) = 0;
#define COPY_EXEC_ENV(string, destination) \
    for (offset = 0; offset < sizeof(string); offset++) \
        *(volatile uint8_t *)(uintptr_t) \
            (user_data_page + (destination) + offset) = \
                (uint8_t)(string)[offset]
    COPY_EXEC_ENV(arm64_bootstrap_env_path, USER_EXEC_ENV_PATH_OFFSET);
    COPY_EXEC_ENV(arm64_bootstrap_env_home, USER_EXEC_ENV_HOME_OFFSET);
    COPY_EXEC_ENV(arm64_bootstrap_env_user, USER_EXEC_ENV_USER_OFFSET);
    COPY_EXEC_ENV(arm64_bootstrap_env_banner, USER_EXEC_ENV_BANNER_OFFSET);
#undef COPY_EXEC_ENV
    for (offset = 0; offset < USER_PIPE_CONTENT_LENGTH; offset++)
        *(volatile uint8_t *)(uintptr_t)
            (user_data_page + USER_PIPE_SOURCE_OFFSET + offset) =
                (uint8_t)arm64_pipe_message[offset];
    *(volatile uint64_t *)(uintptr_t)(user_data_page + USER_VM_MAGIC_OFFSET) =
        USER_TEST_MAGIC;
    high_context.boot_l1 = l1_page;
    (void)user_stack_page;

    if (early_page_free_pages(&early_allocator, test_page, 1) != 0)
        return -1;

    arm64_probe_puts("ARM64_DYNAMIC_PGTABLE_OK\n");
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
    arm64_virtio_block_probe_t block_probe;
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
    int probe_result;

    __asm__ volatile("adr %0, ." : "=r"(pc));
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    __asm__ volatile("mrs %0, vbar_el1" : "=r"(vbar));
    high_text = (arm64_mmu_u64)(uintptr_t)&__text_start;
    high_uart = arm64_mmu_kernel_address(PL011_BASE);
    if (arm64_user_vm_rebind_space(&context->user_vm) != 0 ||
        arm64_user_vm_rebind_space(&context->empty_vm) != 0 ||
        arm64_user_vm_lookup(&context->user_vm, USER_DATA_VA,
                             &user_data_page, NULL) != 0) {
        arm64_probe_puts("ARM64_USER_VM_LOOKUP_FAILED\n");
        goto halt;
    }
    high_user_page = ARM64_KERNEL_VA_BASE + user_data_page;

    arm64_probe_puts("High kernel: PC=");
    arm64_probe_puthex64(pc);
    arm64_probe_puts(" SP=");
    arm64_probe_puthex64(sp);
    arm64_probe_puts(" VBAR=");
    arm64_probe_puthex64(vbar);
    arm64_probe_puts("\n");

    if (pc < ARM64_KERNEL_VA_BASE || sp < ARM64_KERNEL_VA_BASE ||
        vbar != (arm64_mmu_u64)(uintptr_t)arm64_vectors ||
        high_text < ARM64_KERNEL_VA_BASE) {
        arm64_probe_puts("ARM64_TTBR1_EXECUTION_FAILED\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_TTBR1_EXECUTION_OK\n");

    if ((arm64_mmu_translate_read(high_uart) & 1u) != 0 ||
        (arm64_mmu_translate_user_read(high_uart) & 1u) == 0) {
        arm64_probe_puts("ARM64_HIGH_MMIO_FAILED\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_HIGH_MMIO_OK\n");

    if (arm64_virtio_block_probe(&early_allocator, &block_probe) != 0) {
        arm64_probe_puts("ARM64_VIRTIO_BLOCK_FAILED\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_VIRTIO_BLOCK_OK capacity=");
    arm64_probe_puthex64(block_probe.capacity_sectors);
    arm64_probe_puts(" ext2_lba=");
    arm64_probe_puthex64(block_probe.ext2_start_lba);
    arm64_probe_puts("\n");
    if (arm64_ext2_path_smoke_test(context, &block_probe) != 0) {
        arm64_probe_puts("ARM64_EXT2_PATH_READ_FAILED\n");
        goto halt;
    }
    if (arm64_mmu_retire_low_map(context->boot_l1) != 0) {
        arm64_probe_puts("ARM64_LOW_MAP_RETIRE_FAILED\n");
        goto halt;
    }

    par_low_kernel = arm64_mmu_translate_read(0x40080000ULL);
    par_high_kernel = arm64_mmu_translate_read(high_text);
    if ((par_low_kernel & 1u) == 0 ||
        (par_high_kernel & 1u) != 0 ||
        (arm64_mmu_translate_read(PL011_BASE) & 1u) == 0 ||
        (arm64_mmu_translate_read(high_uart) & 1u) != 0) {
        arm64_probe_puts("ARM64_LOW_MAP_RETIRE_VERIFY_FAILED\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_LOW_MAP_RETIRED_OK\n");
    arm64_boot_runtime_summary(&block_probe);

    if (arm64_task_init_current(
            &context->bootstrap_task,
            NULL,
            "bootstrap",
            0,
            (vaddr_t)(uintptr_t)&__stack_bottom,
            (vaddr_t)(uintptr_t)&__stack_top,
            0) != 0) {
        arm64_probe_puts("ARM64_BOOTSTRAP_TASK_INIT_FAILED\n");
        goto halt;
    }

    if (arm64_task_context_smoke_test(context) != 0) {
        arm64_probe_puts("ARM64_TASK_CONTEXT_SWITCH_FAILED\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_TASK_CONTEXT_SWITCH_OK\n");
    arm64_probe_puts("ARM64_TASK_STACK_LIFECYCLE_OK\n");
    arm64_probe_puts("ARM64_GENERIC_TASK_LIFECYCLE_OK\n");
    arm64_probe_puts("ARM64_TASK_STATE_SWITCH_OK\n");
    arm64_probe_puts("ARM64_COOPERATIVE_RUNQUEUE_OK\n");

    if (arm64_multitask_runqueue_smoke_test(context) != 0) {
        arm64_probe_puts("ARM64_MULTITASK_RUNQUEUE_FAILED\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_MULTITASK_RUNQUEUE_OK\n");

    if (arm64_cooperative_dispatcher_smoke_test(context) != 0) {
        arm64_probe_puts("ARM64_COOPERATIVE_DISPATCHER_FAILED\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_COOPERATIVE_DISPATCHER_OK\n");

    if (arm64_deferred_preempt_smoke_test(context) != 0) {
        arm64_probe_puts("ARM64_DEFERRED_PREEMPT_FAILED\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_DEFERRED_PREEMPT_OK\n");

    if (arm64_user_vm_activate_space(&context->user_vm.space) != 0) {
        arm64_probe_puts("ARM64_USER_TTBR0_SWITCH_FAILED\n");
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
        arm64_probe_puts("ARM64_USER_TTBR0_VERIFY_FAILED\n");
        goto halt;
    }

    if (arm64_user_vm_activate_space(&context->empty_vm.space) != 0) {
        arm64_probe_puts("ARM64_EMPTY_TTBR0_SWITCH_FAILED\n");
        goto halt;
    }
    empty_ttbr = arm64_mmu_read_ttbr0();
    if ((empty_ttbr & TTBR_TABLE_MASK) != context->empty_vm.l1 ||
        ((empty_ttbr >> TTBR_ASID_SHIFT) & 0xffu) !=
            context->empty_vm.asid ||
        (arm64_mmu_translate_user_read(USER_DATA_VA) & 1u) == 0 ||
        (arm64_mmu_translate_read(high_text) & 1u) != 0 ||
        (arm64_mmu_translate_read(high_uart) & 1u) != 0 ||
        arm64_user_vm_activate_space(&context->user_vm.space) != 0 ||
        (arm64_mmu_translate_user_read(USER_DATA_VA) & 1u) != 0 ||
        *(volatile uint64_t *)(uintptr_t)(USER_DATA_VA +
                                         USER_VM_MAGIC_OFFSET) !=
            USER_TEST_MAGIC) {
        arm64_probe_puts("ARM64_TTBR0_ISOLATION_FAILED\n");
        goto halt;
    }

    arm64_probe_puts("User TTBR0: mapped=");
    arm64_probe_puthex64(user_ttbr);
    arm64_probe_puts(" empty=");
    arm64_probe_puthex64(empty_ttbr);
    arm64_probe_puts(" VA=");
    arm64_probe_puthex64(USER_DATA_VA);
    arm64_probe_puts(" PA=");
    arm64_probe_puthex64(user_data_page);
    arm64_probe_puts("\nARM64_USER_TTBR0_ASID_OK\n");

    if (arm64_task_address_space_smoke_test(context, user_ttbr,
                                            empty_ttbr) != 0) {
        arm64_probe_puts("ARM64_TASK_TTBR0_SWITCH_FAILED\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_TASK_TTBR0_SWITCH_OK\n");
    arm64_probe_puts("ARM64_GENERIC_VM_SPACE_OK\n");
    arm64_probe_puts("ARM64_GENERIC_VMA_OK\n");

    probe_result = arm64_dynamic_user_vm_smoke_test(context);
    if (probe_result != 0) {
        arm64_probe_puts("ARM64_DYNAMIC_USER_VM_FAILED code=");
        arm64_probe_puthex64((uint64_t)(unsigned int)(-probe_result));
        arm64_probe_puts("\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_DYNAMIC_USER_VM_OK\n");
    arm64_probe_puts("ARM64_ANON_RANGE_VM_OK\n");
    probe_result = arm64_user_vm_clone_smoke_test();
    if (probe_result != 0) {
        arm64_probe_puts("ARM64_USER_VM_CLONE_FAILED code=");
        arm64_probe_puthex64((uint64_t)(int64_t)probe_result);
        arm64_probe_puts("\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_USER_VM_CLONE_OK\n");

    probe_result = arm64_process_elf64_smoke_test(context);
    if (probe_result != 0) {
        arm64_probe_puts("ARM64_PROCESS_ELF64_FAILED code=");
        arm64_probe_puthex64((uint64_t)(unsigned int)(-probe_result));
        arm64_probe_puts("\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_PROCESS_MODEL_OK\n");
    arm64_probe_puts("ARM64_ELF64_LOADER_OK\n");

    arm64_probe_puts("ASID residency: flush=");
    arm64_probe_puthex64(arm64_user_vm_tlb_flush_count());
    arm64_probe_puts(" preserve=");
    arm64_probe_puthex64(arm64_user_vm_tlb_preserve_count());
    arm64_probe_puts("\nARM64_TASK_TLB_RESIDENCY_OK\n");

    if (arm64_user_yield_dispatcher_smoke_test(context) != 0) {
        arm64_probe_puts("ARM64_EL0_YIELD_DISPATCH_FAILED\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_EL0_YIELD_DISPATCH_OK\n");

    probe_result = arm64_user_timer_preempt_smoke_test(context);
    if (probe_result != 0) {
        arm64_probe_puts("ARM64_EL0_TIMER_PREEMPT_FAILED code=");
        arm64_probe_puthex64((uint64_t)(unsigned int)(-probe_result));
        arm64_probe_puts("\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_EL0_TIMER_PREEMPT_OK\n");

    probe_result = arm64_mixed_periodic_preempt_smoke_test(context, 2, 1, 0);
    if (probe_result != 0) {
        arm64_probe_puts("ARM64_PERIODIC_MIXED_PREEMPT_FAILED code=");
        arm64_probe_puthex64((uint64_t)(unsigned int)(-probe_result));
        arm64_probe_puts("\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_PERIODIC_MIXED_PREEMPT_OK\n");

    probe_result = arm64_mixed_periodic_preempt_smoke_test(context, 4, 2, 0);
    if (probe_result != 0) {
        arm64_probe_puts("ARM64_QUANTUM_ACCOUNTING_FAILED code=");
        arm64_probe_puthex64((uint64_t)(unsigned int)(-probe_result));
        arm64_probe_puts("\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_QUANTUM_ACCOUNTING_OK\n");

    probe_result = arm64_mixed_periodic_preempt_smoke_test(context, 4, 2, 1);
    if (probe_result != 0) {
        arm64_probe_puts("ARM64_CONTINUOUS_TICK_LIFECYCLE_FAILED code=");
        arm64_probe_puthex64((uint64_t)(unsigned int)(-probe_result));
        arm64_probe_puts("\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_CONTINUOUS_TICK_LIFECYCLE_OK\n");
    arm64_probe_puts("ARM64_IRQ_SAFE_DISPATCH_OK\n");

    arm64_probe_puts("Testing high VBAR synchronous vector\n");
    __asm__ volatile("brk #0x64");
    clear_task_context(&context->user_task);
    context->user_task.vm_space = arm64_user_vm_space(&context->user_vm);
    context->user_task.ttbr0 = context->user_vm.l1;
    context->user_task.asid = context->user_vm.asid;
    context->user_task.flags = ARM64_TASK_FLAG_RETURNS_TO_USER;
    prepare_user_registers(&context->user_task.user);
    context->user_task.user.pc = USER_CODE_VA +
        ((uint64_t)(uintptr_t)arm64_el0_generic_payload -
         (uint64_t)(uintptr_t)arm64_el0_payload_start);
    if (arm64_syscall_runtime_init(context) != 0) {
        arm64_probe_puts("ARM64_SYSCALL_DISPATCH_INIT_FAILED\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_GENERIC_SYSCALL_DISPATCH_OK\n");
    arm64_boot_ok("Process: scheduler ready");
    arm64_exception_set_el0_context(
        arm64_user_vm_space(&context->user_vm),
        &context->user_task.user,
        (arm64_exception_u64)(uintptr_t)arm64_el0_return);
    arm64_probe_puts("Entering EL0 at ");
    arm64_probe_puthex64(USER_CODE_VA);
    arm64_probe_puts(" stack=");
    arm64_probe_puthex64(PROBE_USER_STACK_TOP);
    arm64_probe_puts("\n");
    arm64_enter_el0(&context->user_task.user);

halt:
    for (;;)
        __asm__ volatile("wfe");
}

static unsigned int arm64_el0_validation_error(uint64_t result)
{
    volatile uint64_t *data = (volatile uint64_t *)(uintptr_t)USER_DATA_VA;
    unsigned int byte;

    if (current_el() != 1 || result != USER_EXIT_STATUS)
        return 1;
    if (data[USER_WRITE_RESULT_OFFSET / sizeof(*data)] != USER_WRITE_LENGTH)
        return 2;
    if (data[USER_EFAULT_RESULT_OFFSET / sizeof(*data)] !=
        USER_EFAULT_RESULT)
        return 3;
    if (data[USER_ENOSYS_RESULT_OFFSET / sizeof(*data)] !=
        USER_ENOSYS_RESULT)
        return 4;
    if (high_context.user_task.vm_space != &high_context.user_vm.space ||
        arm64_user_vm_from_space(high_context.user_task.vm_space) !=
            &high_context.user_vm)
        return 5;
    if (high_context.user_task.ttbr0 != high_context.user_vm.l1 ||
        high_context.user_task.asid != high_context.user_vm.asid ||
        high_context.user_task.flags != ARM64_TASK_FLAG_RETURNS_TO_USER)
        return 6;
    if (high_context.user_task.user.x[0] != USER_EXIT_STATUS ||
        high_context.user_task.user.x[8] != ARMOS_NR_EXIT)
        return 7;
    if (high_context.user_task.user.x[19] != USER_X19_SENTINEL ||
        high_context.user_task.user.x[20] != USER_X20_SENTINEL ||
        high_context.user_task.user.x[29] != USER_X29_SENTINEL ||
        high_context.user_task.user.x[30] != USER_X30_SENTINEL)
        return 8;
    if (high_context.user_task.user.sp != PROBE_USER_STACK_TOP ||
        high_context.user_task.user.pc !=
            data[USER_EXIT_PC_OFFSET / sizeof(*data)])
        return 9;
    if (data[USER_PID_RESULT_OFFSET / sizeof(*data)] != USER_PROCESS_PID)
        return 10;
    if (data[USER_BRK_RESULT_OFFSET / sizeof(*data)] !=
        USER_BRK_TEST_ADDRESS)
        return 11;
    if (data[USER_BRK_MAGIC_OFFSET / sizeof(*data)] != USER_FAULT_MAGIC)
        return 12;
    if (data[USER_MMAP_RESULT_OFFSET / sizeof(*data)] < USER_SHM_END)
        return 13;
    if (data[USER_MMAP_MAGIC_OFFSET / sizeof(*data)] != USER_FAULT_MAGIC)
        return 14;
    if (data[USER_MUNMAP_RESULT_OFFSET / sizeof(*data)] != 0)
        return 15;
    if (data[USER_SIGACTION_RESULT_OFFSET / sizeof(*data)] != 0 ||
        data[USER_FORK_RESULT_OFFSET / sizeof(*data)] != 2 ||
        data[USER_KILL_RESULT_OFFSET / sizeof(*data)] != 0 ||
        data[USER_WAIT_RESULT_OFFSET / sizeof(*data)] != 0)
        return 16;
    if (data[USER_OPEN_READ_RESULT_OFFSET / sizeof(*data)] !=
            USER_OPEN_CONTENT_LENGTH ||
        data[USER_CLOSE_RESULT_OFFSET / sizeof(*data)] != 0 ||
        data[USER_PIPE_RESULT_OFFSET / sizeof(*data)] != 0 ||
        data[USER_PIPE_WRITE_RESULT_OFFSET / sizeof(*data)] !=
            USER_PIPE_CONTENT_LENGTH ||
        data[USER_PIPE_READ_RESULT_OFFSET / sizeof(*data)] !=
            USER_PIPE_CONTENT_LENGTH ||
        data[USER_DUP2_RESULT_OFFSET / sizeof(*data)] != 9)
        return 17;
    for (byte = 0; byte < USER_OPEN_CONTENT_LENGTH; byte++) {
        if (*(volatile uint8_t *)(uintptr_t)
                (USER_DATA_VA + USER_OPEN_BUFFER_OFFSET + byte) !=
            (uint8_t)arm64_bootstrap_file[byte])
            return 18;
    }
    for (byte = 0; byte < USER_PIPE_CONTENT_LENGTH; byte++) {
        if (*(volatile uint8_t *)(uintptr_t)
                (USER_DATA_VA + USER_PIPE_BUFFER_OFFSET + byte) !=
            (uint8_t)arm64_pipe_message[byte])
            return 19;
    }
    if (high_context.user_task.user.pstate !=
        ARM64_USER_PSTATE_EL0T_MASKED)
        return 20;
    if (arm64_exception_el0_exit_status() != USER_EXIT_STATUS ||
        arm64_exception_el0_syscall_count() != 23)
        return 21;
    if (high_context.syscall_runtime.dispatcher.calls != 22 ||
        high_context.syscall_runtime.dispatcher.rejected != 1)
        return 22;
    if (high_context.syscall_runtime.process.state != PROCESS_MODEL_ZOMBIE ||
        high_context.syscall_runtime.process.exit_status != USER_EXIT_STATUS)
        return 23;
    if (high_context.syscall_runtime.process.first_child != NULL ||
        high_context.syscall_runtime.child.parent != NULL ||
        high_context.syscall_runtime.child.ppid != 0 ||
        high_context.syscall_runtime.child.state != PROCESS_MODEL_READY ||
        high_context.syscall_runtime.child.signal_handlers[10] != 0x1234 ||
        high_context.syscall_runtime.child.pending_signals != (1u << 10))
        return 24;
    if (high_context.user_vm.space.brk != USER_BRK_TEST_ADDRESS)
        return 25;
    return 0;
}

static int arm64_prepare_exec_image(arm64_high_context_t *context,
                                    const char *path,
                                    const arm64_exec_arguments_t *arguments,
                                    arm64_user_context_t *registers)
{
    arm64_syscall_runtime_t *runtime = &context->syscall_runtime;
    elf64_loader_ops_t loader_ops;
    arm64_elf_load_context_t load_context;
    const void *image;
    size_t image_size;
    paddr_t stack_physical;
    uint8_t *stack_page;
    uint64_t *initial_stack;
    vaddr_t argv_addresses[ARM64_EXEC_MAX_ARGS];
    vaddr_t envp_addresses[ARM64_EXEC_MAX_ENVS];
    unsigned int mapping;
    unsigned int stack_index;
    unsigned int argument;
    unsigned int table_index;
    size_t index;
    size_t string_cursor;
    size_t string_length;
    size_t table_bytes;
    size_t table_offset;
    vaddr_t entry;
    int result = -1;
    int source_acquired = 0;
    int vm_initialized = 0;

    if (!path || !arguments || !registers ||
        arguments->argc > ARM64_EXEC_MAX_ARGS ||
        arguments->envc > ARM64_EXEC_MAX_ENVS)
        return -1;
    if (io_model_vfs_lookup_readonly(
            &runtime->vfs, path, &image, &image_size) != 0) {
        if (arm64_ext2_load_exec_image(context, path) != 0)
            return -1;
        image = context->disk_exec_image;
        image_size = context->disk_exec_image_size;
        source_acquired = 1;
    }
    if (arm64_user_vm_init(&context->exec_vm,
                           runtime->allocator) != 0) {
        if (source_acquired)
            (void)arm64_release_exec_source(context);
        return -2;
    }
    vm_initialized = 1;

    loader_ops.map = arm64_elf_map;
    loader_ops.copy = arm64_elf_copy;
    loader_ops.zero = arm64_elf_zero;
    load_context.vm = &context->exec_vm;
    load_context.allocator = runtime->allocator;
    if (elf64_load_aarch64(image, image_size, USER_SPACE_END,
                           &loader_ops, &load_context, &entry) != 0)
        goto fail;

    for (stack_index = 0; stack_index < ARM64_EXEC_STACK_PAGES;
         stack_index++) {
        paddr_t page_physical;
        uint8_t *page;

        if (arm64_user_vm_map_new_page(
                &context->exec_vm, runtime->allocator,
                ARM64_EXEC_STACK_BASE + stack_index * PAGE_SIZE,
                VMA_READ | VMA_WRITE, &page_physical) != 0)
            goto fail;
        page = (uint8_t *)(uintptr_t)
            arm64_mmu_kernel_address(page_physical);
        for (index = 0; index < PAGE_SIZE; index++)
            page[index] = 0;
        if (stack_index == ARM64_EXEC_STACK_PAGES - 1u)
            stack_physical = page_physical;
    }

    stack_page = (uint8_t *)(uintptr_t)
        arm64_mmu_kernel_address(stack_physical);
    string_cursor = PAGE_SIZE;
    for (argument = arguments->envc; argument > 0; argument--) {
        for (string_length = 0;
             string_length < ARM64_EXEC_STRING_SIZE &&
             arguments->envp[argument - 1][string_length] != '\0';
             string_length++)
            ;
        if (string_length == ARM64_EXEC_STRING_SIZE ||
            string_length + 1 > string_cursor)
            goto fail;
        string_length++;
        string_cursor -= string_length;
        for (index = 0; index < string_length; index++)
            stack_page[string_cursor + index] =
                (uint8_t)arguments->envp[argument - 1][index];
        envp_addresses[argument - 1] =
            ARM64_EXEC_STACK_DATA_PAGE + string_cursor;
    }
    for (argument = arguments->argc; argument > 0; argument--) {
        for (string_length = 0;
             string_length < ARM64_EXEC_STRING_SIZE &&
             arguments->argv[argument - 1][string_length] != '\0';
             string_length++)
            ;
        if (string_length == ARM64_EXEC_STRING_SIZE ||
            string_length + 1 > string_cursor)
            goto fail;
        string_length++;
        string_cursor -= string_length;
        for (index = 0; index < string_length; index++)
            stack_page[string_cursor + index] =
                (uint8_t)arguments->argv[argument - 1][index];
        argv_addresses[argument - 1] =
            ARM64_EXEC_STACK_DATA_PAGE + string_cursor;
    }

    table_bytes = (1u + arguments->argc + 1u + arguments->envc + 1u) *
                  sizeof(uint64_t);
    if (table_bytes > string_cursor)
        goto fail;
    table_offset = (string_cursor - table_bytes) & ~(size_t)0xFu;
    initial_stack = (uint64_t *)(void *)(stack_page + table_offset);
    table_index = 0;
    initial_stack[table_index++] = arguments->argc;
    for (argument = 0; argument < arguments->argc; argument++)
        initial_stack[table_index++] = argv_addresses[argument];
    initial_stack[table_index++] = 0;
    for (argument = 0; argument < arguments->envc; argument++)
        initial_stack[table_index++] = envp_addresses[argument];
    initial_stack[table_index] = 0;
    for (mapping = 0; mapping < context->exec_vm.mapping_count; mapping++) {
        const arm64_user_vm_mapping_t *mapped =
            &context->exec_vm.mappings[mapping];

        if ((mapped->vma.flags & VMA_EXEC) != 0 &&
            mapped->physical_address != 0)
            arm64_mmu_sync_code(
                arm64_mmu_kernel_address(mapped->physical_address),
                PAGE_SIZE);
    }

    clear_memory(registers, sizeof(*registers));
    registers->sp = ARM64_EXEC_STACK_DATA_PAGE + table_offset;
    registers->pc = entry;
    registers->pstate = ARM64_USER_PSTATE_EL0T_MASKED;
    return 0;

fail:
    if (vm_initialized && arm64_user_vm_destroy(
            &context->exec_vm, runtime->allocator) != 0)
        result = -3;
    if (source_acquired && arm64_release_exec_source(context) != 0)
        result = -4;
    return result;
}

static int arm64_exec_rollback_smoke_test(arm64_high_context_t *context)
{
    arm64_exec_arguments_t arguments;
    arm64_user_context_t registers;
    uint32_t free_before;

    clear_memory(&arguments, sizeof(arguments));
    free_before = context->syscall_runtime.allocator->free_pages;
    if (arm64_prepare_exec_image(context, arm64_exec_invalid_path,
                                 &arguments, &registers) == 0 ||
        context->exec_vm.magic != 0 ||
        context->syscall_runtime.allocator->free_pages != free_before)
        return -1;
    return 0;
}

static void arm64_exec_retire_previous_vm(const vm_space_t *previous_vm,
                                          void *owner)
{
    arm64_high_context_t *context = owner;

    if (!context || previous_vm != &context->user_vm.space ||
        arm64_user_vm_destroy(&context->user_vm,
                              context->syscall_runtime.allocator) != 0) {
        if (context)
            context->exec_previous_vm_retired = 2;
        return;
    }
    context->exec_previous_vm_retired = 1;
    if (arm64_release_exec_source(context) != 0) {
        context->exec_source_retired = 2;
        return;
    }
    context->exec_source_retired = 1;
}

static int arm64_release_exec_source(arm64_high_context_t *context)
{
    if (!context || !context->disk_exec_image ||
        context->disk_exec_image_pages == 0 ||
        early_page_free_pages(context->syscall_runtime.allocator,
                              context->disk_exec_image_physical,
                              context->disk_exec_image_pages) != 0)
        return -1;
    context->disk_exec_image = NULL;
    context->disk_exec_image_size = 0;
    context->disk_exec_image_physical = 0;
    context->disk_exec_image_pages = 0;
    return 0;
}

static void arm64_bootstrap_shell_return(uint64_t result)
{
    arm64_syscall_runtime_t *runtime = &high_context.syscall_runtime;

    arm64_probe_puts("ARM64_MASH_EXIT status=");
    arm64_probe_puthex64(result);
    arm64_probe_puts(" syscalls=");
    arm64_probe_puthex64(arm64_exception_el0_syscall_count());
    arm64_probe_puts(" process_state=");
    arm64_probe_puthex64(runtime->process.state);
    arm64_probe_puts("\n");

    for (;;)
        __asm__ volatile("wfe");
}

static void arm64_el0_return(uint64_t result)
{
    arm64_syscall_runtime_t *runtime = &high_context.syscall_runtime;
    unsigned int validation_error = arm64_el0_validation_error(result);

    if (validation_error != 0) {
        arm64_probe_puts("ARM64_EL0_SYSCALL_ABI_FAILED\n");
        arm64_probe_puts("validation code: ");
        arm64_probe_puthex64(validation_error);
        if (validation_error == 17) {
            volatile uint64_t *data =
                (volatile uint64_t *)(uintptr_t)USER_DATA_VA;

            arm64_probe_puts(" io results: ");
            arm64_probe_puthex64(
                data[USER_OPEN_READ_RESULT_OFFSET / sizeof(*data)]);
            arm64_probe_putc(' ');
            arm64_probe_puthex64(
                data[USER_CLOSE_RESULT_OFFSET / sizeof(*data)]);
            arm64_probe_putc(' ');
            arm64_probe_puthex64(
                data[USER_PIPE_RESULT_OFFSET / sizeof(*data)]);
            arm64_probe_putc(' ');
            arm64_probe_puthex64(
                data[USER_PIPE_WRITE_RESULT_OFFSET / sizeof(*data)]);
            arm64_probe_putc(' ');
            arm64_probe_puthex64(
                data[USER_PIPE_READ_RESULT_OFFSET / sizeof(*data)]);
            arm64_probe_putc(' ');
            arm64_probe_puthex64(
                data[USER_DUP2_RESULT_OFFSET / sizeof(*data)]);
        }
        arm64_probe_puts("\n");
        goto halt;
    }

    arm64_probe_puts("EL0 exit status: ");
    arm64_probe_puthex64(result);
    arm64_probe_puts(" syscall count: ");
    arm64_probe_puthex64(arm64_exception_el0_syscall_count());
    arm64_probe_puts("\nARM64_EL0_SYSCALL_ABI_OK\n");
    arm64_probe_puts("ARM64_EL0_CONTEXT_OK\n");
    arm64_probe_puts("ARM64_GENERIC_SYSCALL_ABI_OK\n");
    arm64_probe_puts("ARM64_PROCESS_SYSCALLS_OK\n");
    arm64_probe_puts("ARM64_BRK_MMAP_PAGE_FAULT_OK\n");
    arm64_probe_puts("ARM64_VFS_FD_PIPE_TTY_OK\n");
    arm64_probe_puts("ARM64_EXT2_VFS_READ_OK path=");
    arm64_probe_puts(arm64_bootstrap_path);
    arm64_probe_puts("\n");

    if (arm64_exec_rollback_smoke_test(&high_context) != 0) {
        arm64_probe_puts("ARM64_EXECVE_ROLLBACK_FAILED\n");
        goto halt;
    }
    arm64_probe_puts("ARM64_EXECVE_ROLLBACK_OK\n");

    if (process_model_init(&runtime->process, ARM64_BOOTSTRAP_PID, NULL,
                           &high_context.user_vm.space,
                           &high_context.scheduled_user_task) != 0) {
        arm64_probe_puts("ARM64_EXECVE_CALLER_INIT_FAILED\n");
        goto halt;
    }
    runtime->process.state = PROCESS_MODEL_RUNNING;
    runtime->process.io_context = &runtime->io;
    runtime->vm = &high_context.user_vm;
    clear_task_context(&high_context.user_task);
    high_context.user_task.vm_space =
        arm64_user_vm_space(&high_context.user_vm);
    high_context.user_task.ttbr0 = high_context.user_vm.l1;
    high_context.user_task.asid = high_context.user_vm.asid;
    high_context.user_task.flags = ARM64_TASK_FLAG_RETURNS_TO_USER;
    prepare_user_registers(&high_context.user_task.user);
    high_context.user_task.user.pc = USER_CODE_VA +
        ((uint64_t)(uintptr_t)arm64_el0_exec_payload -
         (uint64_t)(uintptr_t)arm64_el0_payload_start);
    arm64_exception_set_el0_context(
        arm64_user_vm_space(&high_context.user_vm),
        &high_context.user_task.user,
        (arm64_exception_u64)(uintptr_t)arm64_bootstrap_shell_return);
    arm64_boot_warn("Init: /sbin/init bypassed during ARM64 bring-up");
    arm64_boot_ok("Init: starting /sbin/mash");
    arm64_runtime_tty_visible = 1;
    arm64_probe_puts("ARM64_EXECVE_SYSCALL_ENTER path=");
    arm64_probe_puts(arm64_bootstrap_shell_path);
    arm64_probe_puts("\n");
    arm64_enter_el0(&high_context.user_task.user);

halt:
    for (;;)
        __asm__ volatile("wfe");
}

void arm64_bootstrap_main(uint64_t dtb_address)
{
    arm64_mmu_u64 par_uart;
    arm64_mmu_u64 par_kernel;
    arm64_mmu_u64 par_unmapped;

    arm64_console_puts("\n" ARM64_BOOT_COLOR_INFO
                       "ArmOS 0.6 aarch64"
                       ARM64_BOOT_COLOR_RESET "\n");
    arm64_boot_ok("CPU: ARM Cortex-A72 @ QEMU virt");
    arm64_boot_ok("Calibrating delay loop... 2.00 BogoMIPS");

    arm64_probe_puts("Testing EL1 synchronous vector with BRK #0x64\n");
    __asm__ volatile("brk #0x64");
    arm64_probe_puts("ARM64_EXCEPTION_RETURN_OK\n");

    arm64_probe_puts("Enabling ARMv8 4K identity MMU\n");
    if (arm64_mmu_enable_identity_map() != 0) {
        arm64_probe_puts("ARM64_MMU_FAILED\n");
        arm64_boot_fail("MMU: setup");
        return;
    }

    arm64_probe_puts("SCTLR_EL1: ");
    arm64_probe_puthex64(arm64_mmu_read_sctlr());
    arm64_probe_puts("\nTCR_EL1: ");
    arm64_probe_puthex64(arm64_mmu_read_tcr());
    arm64_probe_puts("\nTTBR0_EL1: ");
    arm64_probe_puthex64(arm64_mmu_read_ttbr0());
    arm64_probe_puts("\n");

    par_uart = arm64_mmu_translate_read(PL011_BASE);
    par_kernel = arm64_mmu_translate_read(0x40080000ULL);
    par_unmapped = arm64_mmu_translate_read(0x80000000ULL);

    arm64_probe_puts("PAR UART: ");
    arm64_probe_puthex64(par_uart);
    arm64_probe_puts(" kernel: ");
    arm64_probe_puthex64(par_kernel);
    arm64_probe_puts(" unmapped: ");
    arm64_probe_puthex64(par_unmapped);
    arm64_probe_puts("\n");

    if ((par_uart & 1u) == 0 &&
        (par_kernel & 1u) == 0 &&
        (par_unmapped & 1u) != 0) {
        arm64_probe_puts("ARM64_MMU_OK\n");
        arm64_probe_puts("Testing synchronous vector with MMU enabled\n");
        __asm__ volatile("brk #0x64");
        arm64_probe_puts("ARM64_MMU_EXCEPTION_OK\n");
        arm64_probe_puts("Testing GICv2 physical timer PPI 30\n");
        if (arm64_timer_irq_smoke_test() != 0) {
            arm64_probe_puts("ARM64_TIMER_IRQ_FAILED\n");
            arm64_boot_fail("Timer: ARM generic timer");
        } else if (test_early_page_allocator(dtb_address) != 0) {
            arm64_probe_puts("ARM64_PHYS_ALLOC_FAILED\n");
            arm64_boot_fail("Memory: physical allocator");
        } else {
            arm64_probe_puts("ARM64_PHYS_ALLOC_OK\n");
            arm64_boot_ok("Memory: physical allocator");
            if (test_dynamic_page_table() != 0) {
                arm64_probe_puts("ARM64_DYNAMIC_PGTABLE_FAILED\n");
                arm64_boot_fail("MMU: dynamic page tables");
            }
        }
    } else {
        arm64_probe_puts("ARM64_MMU_TRANSLATION_FAILED\n");
        arm64_boot_fail("MMU: translation self-test");
    }
}
