/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/mmu/virtual.c
 * Layer: ARM32 / user virtual memory and page-table mappings
 *
 * Responsibilities:
 * - Manage physical pages, virtual address spaces, MMU mappings, and ASIDs.
 * - Support user mappings, page faults, and copy-on-write.
 *
 * Notes:
 * - TLB, ASID, and TTBR changes are global stability concerns.
 */

#include <kernel/memory.h>
#include <kernel/address_space.h>
#include <kernel/kprintf.h>
#include <kernel/string.h>
#include <kernel/util.h>
#include <kernel/task.h>
#include <kernel/process.h>
#include <kernel/userspace.h>
#include <kernel/shm.h>
#include <asm/arm.h>
#include <asm/mmu.h>

/* Forward declarations de toutes les fonctions statiques */
static int cow_copy_vma(vm_space_t *parent_vm, vm_space_t *child_vm, vma_t *vma);
static pgdir_t allocate_pgdir(void);
static bool vm_l1_entry_is_coarse(uint32_t entry);
static paddr_t vm_l1_coarse_base(uint32_t entry);
static bool vm_phys_page_is_freeable(paddr_t phys_addr, const char* owner);

/* Fonctions ASID externes */
extern uint32_t vm_allocate_asid(void);
extern void vm_free_asid(uint32_t asid);
extern uint32_t vm_get_current_asid(void);
extern void switch_address_space_with_asid(pgdir_t pgdir, uint32_t asid);

static inline pgdir_cpu_t vm_pgdir_cpu_view(vm_space_t *vm)
{
    if (!vm || !vm->pgdir)
        return NULL;
    return (pgdir_cpu_t)phys_to_virt((paddr_t)vm->pgdir);
}

extern bool asid_map[]; /* Déclaré dans mmu.c */

#define PGDIR_SIZE 7

static void install_low_kernel_aliases(vm_space_t *vm)
{
    pgdir_cpu_t pgdir_v = vm_pgdir_cpu_view(vm);
    vaddr_t split = get_split_boundary();
    vaddr_t start = memory_low_kernel_alias_start();
    vaddr_t end = memory_low_kernel_alias_end();

    if (!pgdir_v || KERNEL_START >= split)
        return;

    if (end > split)
        end = split;

    /*
     * Low-linked platforms execute kernel text/data/heap below the TTBR split.
     * While a user process is active, exceptions keep TTBR0 selected, so those
     * sections must be visible in the process page directory as privileged-only
     * aliases. User mode still faults if it tries to touch them.
     */
    for (vaddr_t addr = start; addr < end; addr += 0x100000u) {
        uint32_t index = get_L1_index(addr);
        pgdir_v[index] = addr |
                         0x00000002u |  /* Section descriptor. */
                         0x00000400u |  /* AP[1:0] = 01: privileged RW. */
                         0x00000004u |  /* B: bufferable. */
                         0x00000008u |  /* C: cacheable. */
                         0x00010000u;   /* S: coherent across SMP CPUs. */
    }
}

vm_space_t *create_vm_space(void)
{
    vm_space_t *vm = kmalloc(sizeof(vm_space_t));
    if (!vm)
        return NULL;

    // KDEBUG("create_vm_space: allocating user page directory with ASID and %s\n", is_kernel_space ? "KERNEL" : "USER");

    /* Allouer un ASID unique pour ce processus */
    uint32_t asid = vm_allocate_asid();
    if (asid == 0)
    {
        KERROR("create_vm_space: Failed to allocate ASID\n");
        kfree(vm);
        return NULL;
    }

    /* Allouer le page directory utilisateur et garder sa base brute.
     * TTBR0 exige un alignement 16 KB ; vm->pgdir peut donc pointer plus loin
     * que la base retournee par l'allocateur.
     */
    vm->pgdir_alloc = allocate_pgdir();
    vm->pgdir = vm->pgdir_alloc;

    if (!vm->pgdir)
    {
        vm_free_asid(asid);
        kfree(vm);
        return NULL;
    }

    /* Diagnostic d'alignement pour TTBR0 */
    paddr_t pgdir_addr = (paddr_t)vm->pgdir;
    uint32_t alignment_check = pgdir_addr & 0x3FFF;

    if (alignment_check != 0)
    {
        // KWARN("create_vm_space: user pgdir NOT 16KB aligned!\n");

        /* Forcer l'alignement si nécessaire */
        paddr_t aligned_addr = (pgdir_addr + 0x3FFF) & ~0x3FFF;

        // KDEBUG("  Forced alignment: 0x%08X -> 0x%08X\n", pgdir_addr, aligned_addr);

        /* Vérifier que l'adresse alignée est dans la zone allouée */
        if (aligned_addr >= pgdir_addr && aligned_addr < pgdir_addr + (4 * PAGE_SIZE))
        {
            vm->pgdir = (pgdir_t)aligned_addr;
            // KINFO("create_vm_space: Using aligned address 0x%08X\n", aligned_addr);
        }
        else
        {
            KERROR("create_vm_space: Aligned address out of bounds!\n");
            vm_free_asid(asid);
            free_pages(vm->pgdir_alloc, PGDIR_SIZE);
            kfree(vm);
            return NULL;
        }
    }
    else
    {
        // KINFO("create_vm_space: user pgdir already 16KB aligned ✓\n");
    }

    /*
     * TTBCR.N=2 limite TTBR0 aux indices L1 0..1023, soit une table de 4 Kio.
     * vm->pgdir est aligne vers l'avant dans l'allocation PGDIR_SIZE; effacer
     * les 7 pages depuis cette adresse alignee pourrait depasser l'allocation.
     */
    memset(vm_pgdir_cpu_view(vm), 0, PAGE_SIZE);

    install_low_kernel_aliases(vm);

    vm->vma_list = NULL;
    vm->arch_private = NULL;
    vm->heap_start = USER_HEAP_START;
    vm->brk = USER_HEAP_START;
    vm->heap_end = USER_HEAP_END;
    vm->stack_start = USER_STACK_TOP;   // FIX IT
    vm->asid = asid; /* Nouveau champ ASID */

    // KDEBUG("create_vm_space: Created VM space with ASID %u\n", asid);
    return vm;
}

static pgdir_t allocate_pgdir(void)
{
    /* Allouer assez de pages pour pouvoir choisir une base TTBR0 alignee 16 KB. */
    pgdir_t pgdir = (pgdir_t)allocate_pages(PGDIR_SIZE);
    if (!pgdir)
    {
        KERROR("allocate_user_pgdir: Failed to allocate pages\n");
        return NULL;
    }

    return pgdir;
}

static bool vm_l1_entry_is_coarse(uint32_t entry)
{
    return (entry & 0x3) == 0x1;
}

static paddr_t vm_l1_coarse_base(uint32_t entry)
{
    return entry & 0xFFFFFC00;
}

static uint32_t vm_user_l1_entries(void)
{
    vaddr_t split = get_split_boundary();
    if (split == 0)
        return 0;
    return get_L1_index(split - 1) + 1;
}

uint32_t vm_virtual_kb(vm_space_t *vm)
{
    uint32_t bytes = 0;

    for (vma_t *vma = vm ? vm->vma_list : NULL; vma; vma = vma->next) {
        if (vma->end > vma->start)
            bytes += vma->end - vma->start;
    }

    return bytes / 1024;
}

uint32_t vm_resident_kb(vm_space_t *vm)
{
    uint32_t pages = 0;
    pgdir_cpu_t pgdir_v;
    uint32_t l1_entries;

    if (!vm || !vm->pgdir)
        return 0;

    pgdir_v = vm_pgdir_cpu_view(vm);
    if (!pgdir_v)
        return 0;

    l1_entries = vm_user_l1_entries();
    for (uint32_t i = 0; i < l1_entries; i++) {
        l1_entry_t l1_entry = pgdir_v[i];
        if (!vm_l1_entry_is_coarse(l1_entry))
            continue;

        l2_table_t l2_table = (l2_table_t)phys_to_virt(vm_l1_coarse_base(l1_entry));
        for (uint32_t j = 0; j < 256; j++) {
            if ((l2_table[j] & PTE_TYPE_MASK) != PTE_TYPE_FAULT)
                pages++;
        }
    }

    return (pages * PAGE_SIZE) / 1024;
}

uint32_t vm_page_table_count(vm_space_t *vm)
{
    uint32_t count = 0;
    pgdir_cpu_t pgdir_v;
    uint32_t l1_entries;

    if (!vm || !vm->pgdir)
        return 0;

    pgdir_v = vm_pgdir_cpu_view(vm);
    if (!pgdir_v)
        return 0;

    l1_entries = vm_user_l1_entries();
    for (uint32_t i = 0; i < l1_entries; i++) {
        if (vm_l1_entry_is_coarse(pgdir_v[i]))
            count++;
    }

    return count;
}

static bool vm_phys_page_is_freeable(paddr_t phys_addr, const char* owner)
{
    if (!phys_addr) {
        return false;
    }

    if (!IS_PAGE_ALIGNED(phys_addr) || !IS_VALID_RAM(phys_addr)) {
        KERROR("destroy_vm_space: refusing to free invalid %s page 0x%08X\n",
               owner, phys_addr);
        return false;
    }

    return true;
}

void destroy_vm_space(vm_space_t *vm)
{
    vma_t *vma;
    vma_t *next;
    vaddr_t vaddr;
    paddr_t phys_addr;

    if (!vm)
        return;

    //KDEBUG("destroy_vm_space: Destroying VM space 0x%08X , PGDIR = 0x%08X, with ASID %u\n", (uint32_t)vm, (uint32_t)vm->pgdir, vm->asid);

    /* Free all VMAs */
    vma = vm->vma_list;
    while (vma)
    {
        next = vma->next;

        /* Free pages in this VMA.
         *
         * VMAs may describe byte ranges, but the page tables map whole pages.
         * Always walk the page-aligned backing range; otherwise a non-aligned
         * VMA start would make get_physical_address() return phys+offset and
         * free_page() would correctly reject it as an invalid page address.
         */
        vaddr_t page_start = PAGE_ALIGN_DOWN(vma->start);
        vaddr_t page_end = PAGE_ALIGN_UP(vma->end);
        for (vaddr = page_start; vaddr < page_end; vaddr += PAGE_SIZE)
        {
            phys_addr = get_physical_address(vm->pgdir, vaddr);
            if (vm_phys_page_is_freeable(phys_addr, "user"))
            {
                //KDEBUG("destroy_vm_space: Freeing page 0x%08X\n", phys_addr);
                free_page((void *)phys_addr);
            }
        }

        if (vma->flags & VMA_SHARED)
            shm_release_mapping(vma->shm_id);
        kfree(vma);
        vma = next;
    }

    /* Les tables L2 sont des pages physiques distinctes des pages utilisateur. */
    pgdir_cpu_t pgdir_v = vm_pgdir_cpu_view(vm);
    for (uint32_t l1_index = 0; l1_index < 1024; l1_index++)
    {
        uint32_t l1_entry = pgdir_v[l1_index];
        if (vm_l1_entry_is_coarse(l1_entry))
        {
            paddr_t l2_phys = vm_l1_coarse_base(l1_entry);
            pgdir_v[l1_index] = 0;
            if (vm_phys_page_is_freeable(l2_phys, "L2 table")) {
                free_page((void *)l2_phys);
            }
        }
    }

    /* Libérer l'ASID avant de détruire le page directory */
    vm_free_asid(vm->asid);
    // KDEBUG("destroy_vm_space: Freed ASID %u\n", vm->asid);

    /* Free user page directory from the original allocation base. */
    free_pages(vm->pgdir_alloc ? vm->pgdir_alloc : vm->pgdir, PGDIR_SIZE);
    kfree(vm);
}

vma_t *create_vma(vm_space_t *vm, vaddr_t start, uint32_t size, uint32_t flags)
{
    vma_t *vma;
    vma_t *current;
    vaddr_t end;

    if (!vm || size == 0)
        return NULL;

    end = start + size;
    if (end < start || start >= get_split_boundary() || end > get_split_boundary())
    {
        KERROR("create_vma: Invalid range 0x%08X + 0x%08X\n", start, size);
        return NULL;
    }

    for (current = vm->vma_list; current; current = current->next)
    {
        if (start < current->end && end > current->start)
        {
            KERROR("create_vma: Range 0x%08X-0x%08X overlaps 0x%08X-0x%08X\n",
                   start, end, current->start, current->end);
            return NULL;
        }
    }

    vma = kmalloc(sizeof(vma_t));
    if (!vma)
        return NULL;

    vma->start = start;
    vma->end = end;
    vma->flags = flags;
    vma->shm_id = 0;
    vma->next = NULL;

    // KDEBUG("create_vma: Creating VMA 0x%08X-0x%08X (size=%u) in ASID %u\n",
    //        start, start + size, size, vm->asid);

    // debug_mmu_state();

    /* Insert into sorted list */
    if (!vm->vma_list || vma->start < vm->vma_list->start)
    {
        vma->next = vm->vma_list;
        vm->vma_list = vma;
    }
    else
    {
        current = vm->vma_list;
        while (current->next && current->next->start < vma->start)
        {
            current = current->next;
        }
        vma->next = current->next;
        current->next = vma;
    }

    // KDEBUG("create_vma: returning from VMA \n");

    return vma;
}

int remove_vma(vm_space_t *vm, vaddr_t start, vaddr_t end)
{
    vma_t *prev = NULL;
    vma_t *current;

    if (!vm)
        return -EINVAL;

    current = vm->vma_list;
    while (current) {
        if (current->start == start && current->end == end) {
            if (prev)
                prev->next = current->next;
            else
                vm->vma_list = current->next;
            kfree(current);
            return 0;
        }
        prev = current;
        current = current->next;
    }

    return -ENOENT;
}

static bool vm_range_overlaps(vma_t *vma, vaddr_t start, vaddr_t end)
{
    return vma && start < vma->end && end > vma->start;
}

vaddr_t vm_find_free_range(vm_space_t *vm, vaddr_t hint, uint32_t size,
                           vaddr_t base, vaddr_t limit)
{
    vaddr_t addr;
    vaddr_t end;
    vma_t *vma;

    if (!vm || size == 0 || (size & (PAGE_SIZE - 1)) ||
        (base & (PAGE_SIZE - 1)) || (limit & (PAGE_SIZE - 1)) ||
        base >= limit || size > limit - base) {
        return 0;
    }

    if (hint >= base && hint < limit && IS_PAGE_ALIGNED(hint) &&
        size <= limit - hint) {
        bool overlaps = false;
        end = hint + size;
        for (vma = vm->vma_list; vma; vma = vma->next) {
            if (vm_range_overlaps(vma, hint, end)) {
                overlaps = true;
                break;
            }
        }
        if (!overlaps)
            return hint;
    }

    addr = base;
    for (vma = vm->vma_list; vma; vma = vma->next) {
        if (vma->end <= addr || vma->end <= base)
            continue;
        if (vma->start >= limit)
            break;
        if (addr + size <= vma->start)
            return addr;
        if (vma->end > addr)
            addr = ALIGN_UP(vma->end, PAGE_SIZE);
        if (addr < base)
            addr = base;
        if (addr >= limit || size > limit - addr)
            return 0;
    }

    if (addr < limit && size <= limit - addr)
        return addr;
    return 0;
}

int vm_unmap_range(vm_space_t *vm, vaddr_t start, uint32_t size)
{
    vaddr_t end;
    vma_t *vma;
    vma_t *prev;

    if (!vm || size == 0 || !IS_PAGE_ALIGNED(start))
        return -EINVAL;

    size = ALIGN_UP(size, PAGE_SIZE);
    end = start + size;
    if (end <= start || end > get_split_boundary())
        return -EINVAL;

    /*
     * SHM mappings carry one mapping reference per VMA. Until the SHM layer
     * grows split-aware accounting, only allow munmap() to remove such VMAs
     * exactly. Anonymous mmap VMAs can be split freely below.
     */
    for (vma = vm->vma_list; vma; vma = vma->next) {
        vaddr_t cut_start;
        vaddr_t cut_end;

        if (!vm_range_overlaps(vma, start, end))
            continue;
        if (!(vma->flags & VMA_SHARED))
            continue;

        cut_start = (start > vma->start) ? start : vma->start;
        cut_end = (end < vma->end) ? end : vma->end;
        if (cut_start != vma->start || cut_end != vma->end)
            return -EINVAL;
    }

    prev = NULL;
    vma = vm->vma_list;
    while (vma) {
        vma_t *next = vma->next;
        vaddr_t cut_start;
        vaddr_t cut_end;

        if (vma->end <= start) {
            prev = vma;
            vma = next;
            continue;
        }
        if (vma->start >= end)
            break;

        cut_start = (start > vma->start) ? start : vma->start;
        cut_end = (end < vma->end) ? end : vma->end;
        if (cut_start >= cut_end) {
            prev = vma;
            vma = next;
            continue;
        }

        if (cut_start > vma->start && cut_end < vma->end) {
            vma_t *right = kmalloc(sizeof(vma_t));
            if (!right)
                return -ENOMEM;
            *right = *vma;
            right->start = cut_end;
            right->next = vma->next;

            for (vaddr_t addr = cut_start; addr < cut_end; addr += PAGE_SIZE) {
                paddr_t phys = get_physical_address(vm->pgdir, addr);
                if (phys && unmap_user_page(vm->pgdir, addr, vm->asid) == 0)
                    free_page((void *)phys);
            }

            vma->end = cut_start;
            vma->next = right;
            prev = right;
            vma = right->next;
            continue;
        }

        for (vaddr_t addr = cut_start; addr < cut_end; addr += PAGE_SIZE) {
            paddr_t phys = get_physical_address(vm->pgdir, addr);
            if (phys && unmap_user_page(vm->pgdir, addr, vm->asid) == 0)
                free_page((void *)phys);
        }

        if (cut_start == vma->start && cut_end == vma->end) {
            if (prev)
                prev->next = next;
            else
                vm->vma_list = next;
            if (vma->flags & VMA_SHARED)
                shm_release_mapping(vma->shm_id);
            kfree(vma);
            vma = next;
        } else if (cut_start == vma->start) {
            vma->start = cut_end;
            prev = vma;
            vma = next;
        } else {
            vma->end = cut_start;
            prev = vma;
            vma = next;
        }
    }

    return 0;
}

vm_space_t *fork_vm_space(vm_space_t *parent_vm)
{
    vm_space_t *child_vm = create_vm_space();
    vma_t *parent_vma;
    vma_t *child_vma;

    if (!child_vm)
        return NULL;

    // KDEBUG("fork_vm_space: Forking from ASID %u to ASID %u\n",
    //        parent_vm->asid, child_vm->asid);

    /* Copy all VMAs */
    // KDEBUG("fork_vm_space: About to copy all VMAs\n");
    parent_vma = parent_vm->vma_list;
    while (parent_vma)
    {
        if (parent_vma->end <= parent_vma->start) {
            parent_vma = parent_vma->next;
            continue;
        }

        child_vma = create_vma(child_vm,
                               parent_vma->start,
                               parent_vma->end - parent_vma->start,
                               parent_vma->flags);
        if (!child_vma)
        {
            destroy_vm_space(child_vm);
            return NULL;
        }
        child_vma->shm_id = parent_vma->shm_id;

        /* Copy pages with COW if writable */
        if (parent_vma->flags & VMA_WRITE)
        {
            // KDEBUG("fork_vm_space: COW VMA 0x%08X-0x%08X \n",
            //        parent_vma->start, parent_vma->end);
            if (cow_copy_vma(parent_vm, child_vm, parent_vma) < 0)
            {
                destroy_vm_space(child_vm);
                return NULL;
            }
            // KDEBUG(" DONE\n");
        }
        else
        {
            // KDEBUG("fork_vm_space: SHARE VMA 0x%08X-0x%08X \n",
            //        parent_vma->start, parent_vma->end);
            if (cow_copy_vma(parent_vm, child_vm, parent_vma) < 0)
            {
                destroy_vm_space(child_vm);
                return NULL;
            }
            // KDEBUG(" DONE\n");
        }

        parent_vma = parent_vma->next;
    }

    child_vm->heap_start = parent_vm->heap_start;
    child_vm->heap_end = parent_vm->heap_end;
    child_vm->stack_start = parent_vm->stack_start;
    child_vm->brk = parent_vm->brk;

     //KDEBUG("fork_vm_space: Fork completed - Child Heap Start 0x%08X, Child Heap End 0x%08X, Child Stack Start 0x%08X\n",
     //       child_vm->heap_start, child_vm->heap_end, child_vm->stack_start);

    return child_vm;
}

static int cow_copy_vma(vm_space_t *parent_vm, vm_space_t *child_vm, vma_t *vma)
{
    vaddr_t vaddr;

    for (vaddr = vma->start; vaddr < vma->end; vaddr += PAGE_SIZE)
    {
        paddr_t phys_addr = get_physical_address(parent_vm->pgdir, vaddr);
        if (!phys_addr) {
            continue;
        }

        if (page_ref_inc((void*)phys_addr) < 0) {
            KERROR("cow_copy_vma: failed to ref page 0x%08X\n", phys_addr);
            return -ENOMEM;
        }

        if ((vma->flags & VMA_WRITE) && !(vma->flags & VMA_SHARED)) {
            if (set_user_page_readonly(parent_vm->pgdir, vaddr, parent_vm->asid) < 0) {
                free_page((void*)phys_addr);
                return -EFAULT;
            }
        }

        int map_ret;
        if (vma->flags & VMA_SHARED) {
            map_ret = map_user_page(child_vm->pgdir, vaddr, phys_addr,
                                    vma->flags, child_vm->asid);
        } else {
            map_ret = map_user_page_readonly(child_vm->pgdir, vaddr, phys_addr,
                                             vma->flags, child_vm->asid);
        }

        if (map_ret < 0) {
            free_page((void*)phys_addr);
            if ((vma->flags & VMA_WRITE) && page_ref_count((void*)phys_addr) == 1) {
                set_user_page_writable(parent_vm->pgdir, vaddr, parent_vm->asid);
            }
            return -ENOMEM;
        }
    }

    if (vma->flags & VMA_SHARED)
        shm_retain_mapping(vma->shm_id);

    return 0;
}

int handle_cow_fault(vaddr_t fault_addr)
{
    task_t *task = task_current_local();

    if (!task || task->type != TASK_TYPE_PROCESS ||
        !task->process || !task->process->vm) {
        return -EINVAL;
    }

    vm_space_t* vm = task->process->vm;
    vaddr_t vaddr = fault_addr & ~(PAGE_SIZE - 1);
    vma_t* vma = find_vma(vm, fault_addr);
    if (!vma || !(vma->flags & VMA_WRITE)) {
        return -EACCES;
    }

    pte_ptr_t pte = get_user_pte(vm->pgdir, vaddr);
    if (!pte || ((*pte & PTE_TYPE_MASK) == PTE_TYPE_FAULT)) {
        return -EFAULT;
    }

    if ((*pte & PTE_AP_MASK) != PTE_AP_RW_RO) {
        return -EACCES;
    }

    paddr_t old_phys = *pte & PTE_SMALL_BASE;
    uint16_t refs = page_ref_count((void*)old_phys);
    if (refs == 0) {
        return -EFAULT;
    }

    if (refs == 1) {
        return set_user_page_writable(vm->pgdir, vaddr, vm->asid);
    }

    void* new_page = allocate_page();
    if (!new_page) {
        return -ENOMEM;
    }

    memcpy((void*)phys_to_virt((paddr_t)new_page),
           (void*)phys_to_virt(old_phys),
           PAGE_SIZE);

    int ret = remap_user_page(vm->pgdir, vaddr, (paddr_t)new_page,
                              vma->flags, vm->asid);
    if (ret < 0) {
        free_page(new_page);
        return ret;
    }

    free_page((void*)old_phys);
    return 0;
}

int handle_user_stack_fault(vaddr_t fault_addr)
{
    task_t *task = task_current_local();

    if (!task || task->type != TASK_TYPE_PROCESS ||
        !task->process || !task->process->vm) {
        return -EINVAL;
    }

    if (fault_addr < USER_STACK_BOTTOM || fault_addr >= USER_STACK_TOP) {
        return -EINVAL;
    }

    vm_space_t* vm = task->process->vm;
    vaddr_t vaddr = fault_addr & ~(PAGE_SIZE - 1);
    vma_t* vma = find_vma(vm, fault_addr);
    if (!vma || !(vma->flags & VMA_WRITE)) {
        return -EACCES;
    }

    if (get_physical_address(vm->pgdir, vaddr) != 0) {
        return -EEXIST;
    }

    void* page = allocate_page();
    if (!page) {
        return -ENOMEM;
    }

    if (map_user_page(vm->pgdir, vaddr, (paddr_t)page, vma->flags, vm->asid) < 0) {
        free_page(page);
        return -ENOMEM;
    }

    return 0;
}

int handle_lazy_anon_fault(vaddr_t fault_addr, bool is_write)
{
    task_t *task = task_current_local();
    vm_space_t *vm;
    vma_t *vma;
    vaddr_t vaddr;
    void *page;

    if (!task || task->type != TASK_TYPE_PROCESS ||
        !task->process || !task->process->vm) {
        return -EINVAL;
    }

    vm = task->process->vm;
    vma = find_vma(vm, fault_addr);
    if (!vma || !(vma->flags & VMA_LAZY)) {
        return -EINVAL;
    }
    if (is_write && !(vma->flags & VMA_WRITE)) {
        return -EACCES;
    }
    if (!is_write && !(vma->flags & VMA_READ)) {
        return -EACCES;
    }

    /*
     * Today one process has one schedulable user task, so this cannot race
     * with another CPU faulting the same address space. clone()/threads will
     * need a per-vm fault lock around the present-check + map sequence.
     */
    vaddr = fault_addr & PAGE_MASK;
    if (get_physical_address(vm->pgdir, vaddr) != 0) {
        return -EEXIST;
    }

    page = allocate_page();
    if (!page) {
        return -ENOMEM;
    }

    if (map_user_page(vm->pgdir, vaddr, (paddr_t)page, vma->flags, vm->asid) < 0) {
        free_page(page);
        return -ENOMEM;
    }

    return 0;
}

/* Nouvelle fonction: Switch vers un espace d'adressage avec ASID */
void switch_to_vm_space(vm_space_t *vm)
{
    if (!vm)
    {
        KERROR("switch_to_vm_space: NULL vm space\n");
        return;
    }

    // KDEBUG("switch_to_vm_space: Switching from TTBR0=0x%08X to ASID %u, pgdir 0x%08X\n", get_ttbr0(),
    //        vm->asid, (uint32_t)vm->pgdir);
    /* Lire l'instruction à l'adresse virtuelle 0x8000 */

    /* Utiliser la nouvelle fonction avec ASID */
    switch_address_space_with_asid(vm->pgdir, vm->asid);

    extern void check_instruction(vaddr_t test_vaddr, paddr_t phys_addr, uint32_t instruction);
    // check_instruction(0x00008000, 0x41235000, 0xEB000006);

    // KDEBUG("switch_to_vm_space: Switch completed to ASID %u TTBR0=0x%08X\n", vm->asid, get_ttbr0());
}

/* Nouvelle fonction: Obtenir l'ASID d'un VM space */
uint32_t get_vm_asid(vm_space_t *vm)
{
    if (!vm)
    {
        return 0; /* ASID 0 = noyau */
    }
    return vm->asid;
}

/* Helper functions */
vma_t *find_vma(vm_space_t *vm, vaddr_t addr)
{
    vma_t *vma = vm->vma_list;

    /* Vérifier que l'adresse est dans l'espace utilisateur */
    if (addr >= 0x40000000)
    {
        KERROR("find_vma: Address 0x%08X is in kernel space\n", addr);
        return NULL;
    }

    while (vma)
    {
        if (addr >= vma->start && addr < vma->end)
        {
             //KDEBUG("find_vma: Found VMA for addr 0x%08X in ASID %u\n", addr, vm->asid);
            return vma;
        }
        vma = vma->next;
    }

     //KDEBUG("find_vma: No VMA found for addr 0x%08X in ASID %u\n", addr, vm->asid);
    return NULL;
}

/* Nouvelle fonction: Statistiques ASID */
void debug_asid_usage(void)
{
    extern bool asid_map[]; /* Déclaré dans mmu.c */
    uint32_t used_count = 0;
    uint32_t current_asid = vm_get_current_asid();

    KDEBUG("=== ASID USAGE DEBUG ===\n");
    KDEBUG("Current ASID: cookie=%u hw=%u gen=%u\n",
           current_asid, current_asid & ASID_MAX, current_asid >> 8);

    for (uint32_t i = 0; i <= 255; i++)
    {
        if (asid_map[i])
        {
            used_count++;
            if (i < 16)
            { /* Afficher seulement les premiers pour éviter le spam */
                KDEBUG("ASID %u: USED\n", i);
            }
        }
    }

    /* Calcul du pourcentage en arithmétique entière */
    uint32_t percentage = (used_count * 100) / 256;
    uint32_t remainder = ((used_count * 100) % 256) * 10 / 256; /* Une décimale */

    KDEBUG("Total ASIDs used: %u/256 (%u.%u%%)\n",
           used_count, percentage, remainder);
    KDEBUG("========================\n");
}

/* Nouvelle fonction: Validation d'un VM space */
bool validate_vm_space(vm_space_t *vm)
{
    if (!vm)
    {
        KERROR("validate_vm_space: NULL vm\n");
        return false;
    }

    if (!vm->pgdir)
    {
        KERROR("validate_vm_space: NULL pgdir\n");
        return false;
    }

    if (((uint32_t)vm->pgdir & 0x3FFF) != 0)
    {
        KERROR("validate_vm_space: pgdir not 16KB aligned: 0x%08X\n", (uint32_t)vm->pgdir);
        return false;
    }

    uint32_t hw_asid = vm->asid & ASID_MAX;
    if (hw_asid == 0 || hw_asid == ASID_KERNEL)
    {
        KERROR("validate_vm_space: Invalid ASID: %u\n", vm->asid);
        return false;
    }

    /* Vérifier que les VMAs sont dans l'espace utilisateur */
    vma_t *vma = vm->vma_list;
    while (vma)
    {
        if (vma->start >= 0x40000000 || vma->end > 0x40000000)
        {
            KERROR("validate_vm_space: VMA 0x%08X-0x%08X extends into kernel space\n",
                   vma->start, vma->end);
            return false;
        }
        vma = vma->next;
    }

    // KDEBUG("validate_vm_space: VM space ASID %u validation passed\n", vm->asid);
    return true;
}
