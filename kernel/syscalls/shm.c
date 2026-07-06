/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/syscalls/shm.c
 * Layer: Kernel / syscall implementation
 *
 * Responsibilities:
 * - Validate user-facing syscall requests.
 * - Bridge user ABI arguments to kernel subsystems.
 *
 * Notes:
 * - Never trust user pointers; copy through checked helpers.
 */

#include <kernel/shm.h>
#include <kernel/memory.h>
#include <kernel/task.h>
#include <kernel/userspace.h>
#include <kernel/string.h>
#include <kernel/kprintf.h>
#include <kernel/spinlock.h>
#include <kernel/user_layout.h>

typedef struct shm_object {
    bool used;
    bool unlinked;
    uint32_t id;
    char name[SHM_NAME_MAX];
    size_t size;
    uint32_t pages;
    paddr_t phys[SHM_MAX_PAGES];
    uint32_t mappings;
} shm_object_t;

static shm_object_t shm_objects[SHM_MAX_OBJECTS];
static uint32_t shm_next_id = 1;
static spinlock_t shm_lock = SPINLOCK_INIT("shm");

static shm_object_t *shm_find_by_name(const char *name)
{
    for (uint32_t i = 0; i < SHM_MAX_OBJECTS; i++) {
        if (shm_objects[i].used && !shm_objects[i].unlinked &&
            strcmp(shm_objects[i].name, name) == 0) {
            return &shm_objects[i];
        }
    }
    return NULL;
}

static shm_object_t *shm_find_by_id(uint32_t id)
{
    for (uint32_t i = 0; i < SHM_MAX_OBJECTS; i++) {
        if (shm_objects[i].used && shm_objects[i].id == id)
            return &shm_objects[i];
    }
    return NULL;
}

static shm_object_t *shm_alloc_slot(void)
{
    for (uint32_t i = 0; i < SHM_MAX_OBJECTS; i++) {
        if (!shm_objects[i].used)
            return &shm_objects[i];
    }
    return NULL;
}

static void shm_free_object_pages(shm_object_t *obj)
{
    for (uint32_t i = 0; i < obj->pages; i++) {
        if (obj->phys[i]) {
            free_page((void *)obj->phys[i]);
            obj->phys[i] = 0;
        }
    }
}

static void shm_try_destroy_locked(shm_object_t *obj)
{
    if (!obj || !obj->used || !obj->unlinked || obj->mappings != 0)
        return;

    shm_free_object_pages(obj);
    memset(obj, 0, sizeof(*obj));
}

static vaddr_t shm_find_free_vaddr(vm_space_t *vm, size_t size)
{
    uint32_t aligned_size = ALIGN_UP(size, PAGE_SIZE);

    for (vaddr_t addr = USER_SHM_START; addr + aligned_size <= USER_SHM_END; addr += PAGE_SIZE) {
        bool overlaps = false;
        for (vma_t *vma = vm->vma_list; vma; vma = vma->next) {
            if (addr < vma->end && addr + aligned_size > vma->start) {
                overlaps = true;
                addr = ALIGN_UP(vma->end, PAGE_SIZE) - PAGE_SIZE;
                break;
            }
        }
        if (!overlaps)
            return addr;
    }

    return 0;
}

int sys_shm_open(const char *user_name, size_t size, int flags)
{
    char name[SHM_NAME_MAX];
    shm_object_t *obj;
    uint32_t pages;

    if (!user_name)
        return -EINVAL;
    if (strncpy_from_user(name, user_name, sizeof(name)) < 0)
        return -EFAULT;
    if (name[0] == '\0')
        return -EINVAL;

    size = ALIGN_UP(size, PAGE_SIZE);
    if (size == 0 || size > SHM_MAX_PAGES * PAGE_SIZE)
        return -EINVAL;
    pages = size / PAGE_SIZE;

    spin_lock(&shm_lock);

    obj = shm_find_by_name(name);
    if (obj) {
        if ((flags & SHM_O_CREAT) && (flags & SHM_O_EXCL)) {
            spin_unlock(&shm_lock);
            return -EEXIST;
        }
        if (size > obj->size) {
            spin_unlock(&shm_lock);
            return -EINVAL;
        }
        int id = (int)obj->id;
        spin_unlock(&shm_lock);
        return id;
    }

    if (!(flags & SHM_O_CREAT)) {
        spin_unlock(&shm_lock);
        return -ENOENT;
    }

    obj = shm_alloc_slot();
    if (!obj) {
        spin_unlock(&shm_lock);
        return -ENFILE;
    }

    memset(obj, 0, sizeof(*obj));
    obj->used = true;
    obj->id = shm_next_id++;
    if (shm_next_id == 0)
        shm_next_id = 1;
    obj->size = size;
    obj->pages = pages;
    strncpy(obj->name, name, sizeof(obj->name) - 1);

    for (uint32_t i = 0; i < pages; i++) {
        void *page = allocate_page();
        if (!page) {
            shm_free_object_pages(obj);
            memset(obj, 0, sizeof(*obj));
            spin_unlock(&shm_lock);
            return -ENOMEM;
        }
        obj->phys[i] = (paddr_t)page;
    }

    int id = (int)obj->id;
    spin_unlock(&shm_lock);
    return id;
}

int sys_shm_unlink(const char *user_name)
{
    char name[SHM_NAME_MAX];
    shm_object_t *obj;

    if (!user_name)
        return -EINVAL;
    if (strncpy_from_user(name, user_name, sizeof(name)) < 0)
        return -EFAULT;

    spin_lock(&shm_lock);
    obj = shm_find_by_name(name);
    if (!obj) {
        spin_unlock(&shm_lock);
        return -ENOENT;
    }

    obj->unlinked = true;
    obj->name[0] = '\0';
    shm_try_destroy_locked(obj);
    spin_unlock(&shm_lock);
    return 0;
}

void *sys_shm_map(int id, void *addr, int flags)
{
    task_t *task = task_current_local();
    shm_object_t *obj;
    vm_space_t *vm;
    vaddr_t vaddr;
    uint32_t vma_flags = VMA_READ | VMA_SHARED;
    vma_t *vma;

    if (!task || !task->process || !task->process->vm)
        return (void *)-EINVAL;
    vm = task->process->vm;

    if (flags & SHM_RDWR)
        vma_flags |= VMA_WRITE;

    spin_lock(&shm_lock);
    obj = shm_find_by_id((uint32_t)id);
    if (!obj || obj->unlinked) {
        spin_unlock(&shm_lock);
        return (void *)-ENOENT;
    }

    if (addr) {
        vaddr = (vaddr_t)addr;
        if ((vaddr & (PAGE_SIZE - 1)) || vaddr < USER_SHM_START ||
            vaddr + obj->size > USER_SHM_END) {
            spin_unlock(&shm_lock);
            return (void *)-EINVAL;
        }
    } else {
        vaddr = shm_find_free_vaddr(vm, obj->size);
        if (!vaddr) {
            spin_unlock(&shm_lock);
            return (void *)-ENOMEM;
        }
    }

    vma = create_vma(vm, vaddr, obj->size, vma_flags);
    if (!vma) {
        spin_unlock(&shm_lock);
        return (void *)-ENOMEM;
    }
    vma->shm_id = obj->id;

    for (uint32_t i = 0; i < obj->pages; i++) {
        if (page_ref_inc((void *)obj->phys[i]) < 0) {
            for (uint32_t j = 0; j < i; j++) {
                unmap_user_page(vm->pgdir, vaddr + j * PAGE_SIZE, vm->asid);
                free_page((void *)obj->phys[j]);
            }
            remove_vma(vm, vaddr, vaddr + obj->size);
            spin_unlock(&shm_lock);
            return (void *)-ENOMEM;
        }

        if (map_user_page(vm->pgdir, vaddr + i * PAGE_SIZE, obj->phys[i],
                          vma_flags, vm->asid) < 0) {
            free_page((void *)obj->phys[i]);
            for (uint32_t j = 0; j < i; j++) {
                unmap_user_page(vm->pgdir, vaddr + j * PAGE_SIZE, vm->asid);
                free_page((void *)obj->phys[j]);
            }
            remove_vma(vm, vaddr, vaddr + obj->size);
            spin_unlock(&shm_lock);
            return (void *)-ENOMEM;
        }
    }

    obj->mappings++;
    spin_unlock(&shm_lock);
    return (void *)vaddr;
}

int sys_shm_unmap(void *addr, size_t size)
{
    task_t *task = task_current_local();
    vm_space_t *vm;
    vma_t *vma;
    vaddr_t start = (vaddr_t)addr;
    vaddr_t end;

    if (!task || !task->process || !task->process->vm)
        return -EINVAL;
    if (!addr || (start & (PAGE_SIZE - 1)))
        return -EINVAL;

    vm = task->process->vm;
    size = ALIGN_UP(size, PAGE_SIZE);
    if (size == 0)
        return -EINVAL;
    end = start + size;

    vma = find_vma(vm, start);
    if (!vma || !(vma->flags & VMA_SHARED) || vma->start != start || vma->end != end)
        return -EINVAL;

    for (vaddr_t vaddr = start; vaddr < end; vaddr += PAGE_SIZE) {
        paddr_t phys = get_physical_address(vm->pgdir, vaddr);
        if (phys && unmap_user_page(vm->pgdir, vaddr, vm->asid) == 0)
            free_page((void *)phys);
    }

    shm_release_mapping(vma->shm_id);
    return remove_vma(vm, start, end);
}

void shm_retain_mapping(uint32_t shm_id)
{
    spin_lock(&shm_lock);
    shm_object_t *obj = shm_find_by_id(shm_id);
    if (obj)
        obj->mappings++;
    spin_unlock(&shm_lock);
}

void shm_release_mapping(uint32_t shm_id)
{
    spin_lock(&shm_lock);
    shm_object_t *obj = shm_find_by_id(shm_id);
    if (obj) {
        if (obj->mappings > 0)
            obj->mappings--;
        shm_try_destroy_locked(obj);
    }
    spin_unlock(&shm_lock);
}
