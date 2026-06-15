#include <kernel/memory.h>
#include <kernel/kernel.h>
#include <kernel/kprintf.h>
#include <kernel/task.h>
#include <kernel/process.h>
#include <asm/arm.h>
#include <asm/mmu.h>

/* Forward declarations de toutes les fonctions statiques */
static int cow_copy_vma(vm_space_t *parent_vm, vm_space_t *child_vm, vma_t *vma);
static void share_vma_pages(vm_space_t *parent_vm, vm_space_t *child_vm, vma_t *vma);
static void make_page_readonly(uint32_t *pgdir, uint32_t vaddr);
static void map_user_page_cow(uint32_t *pgdir, uint32_t vaddr, uint32_t phys_addr, uint32_t vma_flags, uint32_t asid);
static void track_cow_page(uint32_t phys_addr);
static uint32_t *allocate_pgdir(void);
static bool vm_l1_entry_is_coarse(uint32_t entry);
static uint32_t vm_l1_coarse_base(uint32_t entry);
static bool vm_phys_page_is_freeable(uint32_t phys_addr, const char* owner);

/* Fonctions ASID externes */
extern uint32_t vm_allocate_asid(void);
extern void vm_free_asid(uint32_t asid);
extern uint32_t vm_get_current_asid(void);
extern void switch_address_space_with_asid(uint32_t *pgdir, uint32_t asid);
extern int copy_user_stack_pages(vm_space_t *parent_vm, vm_space_t *child_vm,
                                 uint32_t stack_start, uint32_t stack_size);

extern bool asid_map[]; /* Déclaré dans mmu.c */

#define PGDIR_SIZE 7

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

    /* Allouer le page directory utilisateur (TTBR0 - 8KB pour 2GB) */
    vm->pgdir = allocate_pgdir();

    if (!vm->pgdir)
    {
        vm_free_asid(asid);
        kfree(vm);
        return NULL;
    }

    /* Diagnostic d'alignement pour TTBR0 */
    uint32_t pgdir_addr = (uint32_t)vm->pgdir;
    uint32_t alignment_check = pgdir_addr & 0x3FFF;

    if (alignment_check != 0)
    {
        // KWARN("create_vm_space: user pgdir NOT 16KB aligned!\n");

        /* Forcer l'alignement si nécessaire */
        uint32_t aligned_addr = (pgdir_addr + 0x3FFF) & ~0x3FFF;

        // KDEBUG("  Forced alignment: 0x%08X -> 0x%08X\n", pgdir_addr, aligned_addr);

        /* Vérifier que l'adresse alignée est dans la zone allouée */
        if (aligned_addr >= pgdir_addr && aligned_addr < pgdir_addr + (4 * PAGE_SIZE))
        {
            vm->pgdir = (uint32_t *)aligned_addr;
            // KINFO("create_vm_space: Using aligned address 0x%08X\n", aligned_addr);
        }
        else
        {
            KERROR("create_vm_space: Aligned address out of bounds!\n");
            vm_free_asid(asid);
            free_pages(vm->pgdir, PGDIR_SIZE);
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
    memset(vm->pgdir, 0, PAGE_SIZE);

    /* Les mappings noyau sont dans TTBR1, pas besoin de les copier */
    /* TTBR0 ne contiendra que les mappings utilisateur */

    vm->vma_list = NULL;
    vm->heap_start = USER_HEAP_START;
    vm->brk = USER_HEAP_START;
    vm->heap_end = USER_HEAP_END;
    vm->stack_start = USER_STACK_TOP;   // FIX IT
    vm->asid = asid; /* Nouveau champ ASID */

    // KDEBUG("create_vm_space: Created VM space with ASID %u\n", asid);
    return vm;
}

static uint32_t *allocate_pgdir(void)
{
    /* Allouer 2 pages contiguës pour TTBR0 (couvre 0-2GB = 2048 entrées * 4 octets = 8KB) */
    uint32_t *pgdir = (uint32_t *)allocate_pages(PGDIR_SIZE);
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

static uint32_t vm_l1_coarse_base(uint32_t entry)
{
    return entry & 0xFFFFFC00;
}

static bool vm_phys_page_is_freeable(uint32_t phys_addr, const char* owner)
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
    uint32_t vaddr;
    uint32_t phys_addr;

    if (!vm)
        return;

    //KDEBUG("destroy_vm_space: Destroying VM space 0x%08X , PGDIR = 0x%08X, with ASID %u\n", (uint32_t)vm, (uint32_t)vm->pgdir, vm->asid);

    /* Free all VMAs */
    vma = vm->vma_list;
    while (vma)
    {
        next = vma->next;

        /* Free pages in this VMA */
        for (vaddr = vma->start; vaddr < vma->end; vaddr += PAGE_SIZE)
        {
            phys_addr = get_physical_address(vm->pgdir, vaddr);
            if (vm_phys_page_is_freeable(phys_addr, "user"))
            {
                //KDEBUG("destroy_vm_space: Freeing page 0x%08X\n", phys_addr);
                free_page((void *)phys_addr);
            }
        }

        kfree(vma);
        vma = next;
    }

    /* Les tables L2 sont des pages physiques distinctes des pages utilisateur. */
    for (uint32_t l1_index = 0; l1_index < 1024; l1_index++)
    {
        uint32_t l1_entry = vm->pgdir[l1_index];
        if (vm_l1_entry_is_coarse(l1_entry))
        {
            uint32_t l2_phys = vm_l1_coarse_base(l1_entry);
            vm->pgdir[l1_index] = 0;
            if (vm_phys_page_is_freeable(l2_phys, "L2 table")) {
                free_page((void *)l2_phys);
            }
        }
    }

    /* Libérer l'ASID avant de détruire le page directory */
    vm_free_asid(vm->asid);
    // KDEBUG("destroy_vm_space: Freed ASID %u\n", vm->asid);

    /* Free user page directory (2 pages pour TTBR0) */
    free_pages(vm->pgdir, PGDIR_SIZE);
    kfree(vm);
}

vma_t *create_vma(vm_space_t *vm, uint32_t start, uint32_t size, uint32_t flags)
{
    vma_t *vma;
    vma_t *current;
    uint32_t end;

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
        child_vma = create_vma(child_vm,
                               parent_vma->start,
                               parent_vma->end - parent_vma->start,
                               parent_vma->flags);
        if (!child_vma)
        {
            destroy_vm_space(child_vm);
            return NULL;
        }

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
            // share_vma_pages(parent_vm, child_vm, parent_vma);
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

    if (copy_user_stack_pages(parent_vm, child_vm,
                              (USER_STACK_TOP - PAGE_SIZE) & ~0xFFF, PAGE_SIZE) < 0)
    {
        destroy_vm_space(child_vm);
        return NULL;
    }
    //copy_user_stack_pages(parent_vm, child_vm, ALIGN_DOWN(USER_STACK_BOTTOM, PAGE_SIZE), USER_STACK_SIZE);

     //KDEBUG("fork_vm_space: Fork completed - Child Heap Start 0x%08X, Child Heap End 0x%08X, Child Stack Start 0x%08X\n",
     //       child_vm->heap_start, child_vm->heap_end, child_vm->stack_start);

    return child_vm;
}

static int cow_copy_vma(vm_space_t *parent_vm, vm_space_t *child_vm, vma_t *vma)
{
    uint32_t vaddr;

    for (vaddr = vma->start; vaddr < vma->end; vaddr += PAGE_SIZE)
    {
        if (vaddr == USER_STACK_TOP - PAGE_SIZE)
            continue;

        uint32_t phys_addr = get_physical_address(parent_vm->pgdir, vaddr);
        if (!phys_addr) {
            continue;
        }

        if (page_ref_inc((void*)phys_addr) < 0) {
            KERROR("cow_copy_vma: failed to ref page 0x%08X\n", phys_addr);
            return -ENOMEM;
        }

        if (vma->flags & VMA_WRITE) {
            if (set_user_page_readonly(parent_vm->pgdir, vaddr, parent_vm->asid) < 0) {
                free_page((void*)phys_addr);
                return -EFAULT;
            }
        }

        if (map_user_page_readonly(child_vm->pgdir, vaddr, phys_addr,
                                   vma->flags, child_vm->asid) < 0) {
            free_page((void*)phys_addr);
            if ((vma->flags & VMA_WRITE) && page_ref_count((void*)phys_addr) == 1) {
                set_user_page_writable(parent_vm->pgdir, vaddr, parent_vm->asid);
            }
            return -ENOMEM;
        }
    }

    return 0;
}

int handle_cow_fault(uint32_t fault_addr)
{
    if (!current_task || current_task->type != TASK_TYPE_PROCESS ||
        !current_task->process || !current_task->process->vm) {
        return -EINVAL;
    }

    vm_space_t* vm = current_task->process->vm;
    uint32_t vaddr = fault_addr & ~(PAGE_SIZE - 1);
    vma_t* vma = find_vma(vm, fault_addr);
    if (!vma || !(vma->flags & VMA_WRITE)) {
        return -EACCES;
    }

    uint32_t* pte = get_user_pte(vm->pgdir, vaddr);
    if (!pte || ((*pte & PTE_TYPE_MASK) == PTE_TYPE_FAULT)) {
        return -EFAULT;
    }

    if ((*pte & PTE_AP_MASK) != PTE_AP_RW_RO) {
        return -EACCES;
    }

    uint32_t old_phys = *pte & PTE_SMALL_BASE;
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

    memcpy(new_page, (void*)old_phys, PAGE_SIZE);

    int ret = remap_user_page(vm->pgdir, vaddr, (uint32_t)new_page,
                              vma->flags, vm->asid);
    if (ret < 0) {
        free_page(new_page);
        return ret;
    }

    free_page((void*)old_phys);
    return 0;
}

static inline void clean_dcache_line(void *addr)
{
    asm volatile(
        "mcr p15, 0, %0, c7, c10, 1" ::"r"(addr) : "memory");
}

static void share_vma_pages(vm_space_t *parent_vm, vm_space_t *child_vm, vma_t *vma)
{
    uint32_t vaddr;

    // IMPORTANT: Obtenir l'ASID du parent depuis le contexte actuel
    // uint32_t parent_asid = vm_get_current_asid();

    // KDEBUG("share_vma_pages: Parent ASID %u - Child ASID %u\n",
    //        parent_asid, child_vm->asid);

    // kernel_context_save_t save = switch_to_kernel_context();

    // KDEBUG("share_vma_pages: switched to kernel asid %u\n", vm_get_current_asid());

    for (vaddr = vma->start; vaddr < vma->end; vaddr += PAGE_SIZE)
    {
        uint32_t phys_addr = get_physical_address(parent_vm->pgdir, vaddr);

        if (phys_addr == 0)
        {
            KERROR("share_vma_pages: Failed to get physical address for vaddr 0x%08X\n", vaddr);
            continue;
        }

        // KDEBUG("share_vma_pages: Sharing vaddr 0x%08X -> phys 0x%08X\n", vaddr, phys_addr);

        // Index dans le L1 et L2
        uint32_t l1_index = get_L1_index(vaddr);
        uint32_t l2_index = L2_INDEX(vaddr);

        // Entrée L1
        uint32_t *l1_entry = &child_vm->pgdir[l1_index];
        uint32_t *l2_table;

        uint32_t l2_phys = 0;
        uint32_t l2_temp = 0;

        if (!(*l1_entry & 0x1))
        {
            // Allouer une nouvelle table L2
            void *l2_page = allocate_page();
            if (!l2_page)
            {
                KERROR("Failed to allocate L2 table for vaddr 0x%08X\n", vaddr);
                continue;
            }

            l2_phys = (uint32_t)l2_page;
            // VÉRIFICATION CRITIQUE : Alignement
            if (l2_phys & 0x3FF)
            {
                KERROR("L2 page not properly aligned: 0x%08X\n", l2_phys);
                free_page(l2_page);
                continue;
            }

            // l2_temp = map_temp_page(l2_phys);
            l2_temp = l2_phys;
            if (!l2_temp)
            {
                KERROR("Failed to map temp L2 page\n");
                free_page(l2_page);
                continue;
            }

            memset((void *)l2_temp, 0, PAGE_SIZE);

            *l1_entry = (l2_phys & 0xFFFFFC00) | 0x01; // coarse page table
        }
        else
        {
            // Accéder à la table L2 existante
            l2_phys = *l1_entry & 0xFFFFFC00;
            // l2_temp = map_temp_page(l2_phys);
            l2_temp = l2_phys;
            // l2_temp = map_temp_pages_contiguous(l2_phys, 1);
            if (!l2_temp)
            {
                KERROR("Failed to map L2 page\n");
                continue;
            }
        }

        l2_table = (uint32_t *)l2_temp;

        // KDEBUG("share_vma_pages: Mapped L2_temp = 0x%08X from l2_phys = 0x%08X\n", l2_temp, l2_phys);

        // Calcul des flags ARM
        uint32_t page_flags = 0x02; // small page

        page_flags |= 0x0C;

        if (vma->flags & VMA_WRITE)
            page_flags |= 0x30; // AP = 11 (user RW)
        else
            page_flags |= 0x20; // AP = 10 (user RO)

        if (!(vma->flags & VMA_EXEC))
        {
            page_flags |= 0x01; // XN bit
            sync_icache_for_exec();
        }

        if (vaddr >= VIRT_RAM_START && vaddr < VIRT_RAM_END)
            page_flags |= 0x0C; // cacheable + bufferable

        // Entrée L2
        l2_table[l2_index] = (phys_addr & 0xFFFFF000) | page_flags;
        // KDEBUG("share_vma_pages: Mapped child L2[%u] = 0x%08X\n", l2_index, l2_table[l2_index]);

        // unmap_temp_pages_contiguous(l2_temp,1);
        // unmap_temp_page((void *)l2_temp);

        // Invalider TLB dans le contexte du processus enfant
        invalidate_tlb_page_asid(vaddr, child_vm->asid);
    }

    // restore_from_kernel_context(save);
}

/* Fonctions helper (implementations basiques) */
static void make_page_readonly(uint32_t *pgdir, uint32_t vaddr)
{
    /* TODO: Implémenter la protection read-only avec invalidation TLB par ASID */
    // KDEBUG("make_page_readonly: Making 0x%08X read-only (TODO)\n", vaddr);
    (void)pgdir;
    (void)vaddr;
}

static void map_user_page_cow(uint32_t *pgdir, uint32_t vaddr, uint32_t phys_addr, uint32_t vma_flags, uint32_t asid)
{
    /* Pour l'instant, utiliser map_user_page normal */
    map_user_page(pgdir, vaddr, phys_addr, vma_flags, asid);
}

static void track_cow_page(uint32_t phys_addr)
{
    /* TODO: Implémenter le tracking COW */
    // KDEBUG("track_cow_page: Tracking COW for 0x%08X (TODO)\n", phys_addr);
    (void)phys_addr;
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

    extern void check_instruction(uint32_t test_vaddr, uint32_t phys_addr, uint32_t instruction);
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
vma_t *find_vma(vm_space_t *vm, uint32_t addr)
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
    KDEBUG("Current ASID: %u\n", current_asid);

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

    if (vm->asid == 0 || vm->asid > 255)
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
