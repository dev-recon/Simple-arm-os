/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm64/user/userspace.c
 * Layer: ARM64 / user memory access
 *
 * Responsibilities:
 * - Validate user pointers against the current process vm_space_t.
 * - Copy data through resolved physical pages and the kernel direct map.
 * - Provide bounded string copies for architecture-neutral syscalls.
 *
 * Notes:
 * - Filesystem and syscall policy remain in the common kernel.
 * - Lazy mappings must be faulted by the VM backend before these helpers are
 *   asked to copy them.
 */

#include <asm/mmu.h>
#include <asm/user_vm.h>
#include <kernel/memory.h>
#include <kernel/string.h>
#include <kernel/task.h>
#include <kernel/userspace.h>

bool is_kernel_pointer(const void *ptr)
{
    return ptr && (uint64_t)(uintptr_t)ptr >= ARM64_KERNEL_VA_BASE;
}

static const arm64_user_vm_t *current_user_vm(void)
{
    task_t *task = task_current_local();
    const vm_space_t *space;

    if (!task || task->type != TASK_TYPE_PROCESS || !task->process ||
        !task->process->vm)
        return NULL;
    space = task->process->vm;
    return arm64_user_vm_from_space(space);
}

static int copy_user_pages(void *kernel_buffer, vaddr_t user_address,
                           size_t length, bool to_user)
{
    const arm64_user_vm_t *vm = current_user_vm();
    uint8_t *kernel_bytes = kernel_buffer;
    size_t copied = 0;

    if (!vm || !kernel_buffer || length == 0)
        return -1;
    if (arm64_user_vm_validate_range(
            vm, user_address, length,
            to_user ? VMA_WRITE : VMA_READ) != 0)
        return -1;

    while (copied < length) {
        vaddr_t current = user_address + copied;
        vaddr_t page = current & PAGE_MASK;
        size_t offset = (size_t)(current & PAGE_OFFSET_MASK);
        size_t chunk = PAGE_SIZE - offset;
        paddr_t physical;
        uint8_t *mapped;

        if (chunk > length - copied)
            chunk = length - copied;
        if (arm64_user_vm_lookup(vm, page, &physical, NULL) != 0 ||
            physical == 0)
            return -1;
        mapped = (uint8_t *)(uintptr_t)
            arm64_mmu_kernel_address(physical + offset);
        if (to_user)
            memcpy(mapped, kernel_bytes + copied, chunk);
        else
            memcpy(kernel_bytes + copied, mapped, chunk);
        copied += chunk;
    }
    return 0;
}

bool is_valid_user_ptr(const void *ptr)
{
    const arm64_user_vm_t *vm = current_user_vm();

    return vm && ptr && arm64_user_vm_validate_range(
        vm, (vaddr_t)(uintptr_t)ptr, 1, VMA_READ) == 0;
}

bool is_valid_user_range(const void *ptr, size_t size)
{
    const arm64_user_vm_t *vm = current_user_vm();

    return vm && ptr && size != 0 && arm64_user_vm_validate_range(
        vm, (vaddr_t)(uintptr_t)ptr, size, VMA_READ) == 0;
}

int copy_to_user(void *to, const void *from, size_t n)
{
    return copy_user_pages((void *)from, (vaddr_t)(uintptr_t)to, n, true);
}

int copy_from_user(void *to, const void *from, size_t n)
{
    return copy_user_pages(to, (vaddr_t)(uintptr_t)from, n, false);
}

int strncpy_from_user(char *to, const char *from, size_t max_len)
{
    size_t index;

    if (!to || !from || max_len == 0)
        return -1;
    for (index = 0; index < max_len; index++) {
        if (copy_from_user(&to[index], &from[index], 1) != 0)
            return -1;
        if (to[index] == '\0')
            return (int)index;
    }
    to[max_len - 1] = '\0';
    return -1;
}

int strnlen_user(const char *str, int maxlen)
{
    int index;
    char value;

    if (!str || maxlen <= 0)
        return -1;
    for (index = 0; index < maxlen; index++) {
        if (copy_from_user(&value, str + index, 1) != 0)
            return -1;
        if (value == '\0')
            return index;
    }
    return -1;
}

int copy_to_user_safe(void *to, const void *from, size_t n,
                      size_t max_size)
{
    return n <= max_size ? copy_to_user(to, from, n) : -1;
}

char *copy_string_from_user(const char *user_str)
{
    int length = strnlen_user(user_str, MAX_PATH);
    char *kernel_string;

    if (length < 0)
        return NULL;
    kernel_string = kmalloc((size_t)length + 1u);
    if (!kernel_string)
        return NULL;
    if (copy_from_user(kernel_string, user_str,
                       (size_t)length + 1u) != 0) {
        kfree(kernel_string);
        return NULL;
    }
    return kernel_string;
}
