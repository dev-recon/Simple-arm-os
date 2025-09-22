#include <kernel/memory.h>
#include <kernel/kernel.h>
#include <kernel/kprintf.h>
#include <asm/arm.h>
#include <asm/mmu.h>

/* Forward declarations de toutes les fonctions statiques */
static void copy_kernel_mappings(uint32_t *new_pgdir);
static void cow_copy_vma(vm_space_t *parent_vm, vm_space_t *child_vm, vma_t *vma);
static void share_vma_pages(vm_space_t *parent_vm, vm_space_t *child_vm, vma_t *vma);
static void make_page_readonly(uint32_t *pgdir, uint32_t vaddr);
static void map_user_page_cow(uint32_t *pgdir, uint32_t vaddr, uint32_t phys_addr, uint32_t vma_flags, uint32_t asid);
static void track_cow_page(uint32_t phys_addr);
static uint32_t *allocate_pgdir(void);

/* Fonctions ASID externes */
extern uint32_t vm_allocate_asid(void);
extern void vm_free_asid(uint32_t asid);
extern uint32_t vm_get_current_asid(void);
extern void switch_address_space_with_asid(uint32_t *pgdir, uint32_t asid);
extern int copy_user_stack_pages(vm_space_t *parent_vm, vm_space_t *child_vm,
                                 uint32_t stack_start, uint32_t stack_size);

extern bool asid_map[]; /* Déclaré dans mmu.c */

#define PGDIR_SIZE 7

#define L1_SECT 0x2 // [1:0] = 10
#define L1_SECT_B (1u << 2)
#define L1_SECT_C (1u << 3)
#define L1_SECT_DOMAIN(d) ((d) << 5) // d=0 si tu utilises DACR=0x55555555
#define L1_SECT_AP10 (1u << 10)      // AP[1:0] = 10 (ex RO user/RW priv) -> ajuste si besoin
#define L1_SECT_TEX(x) ((x) << 12)   // TEX
#define L1_SECT_APX (1u << 15)
#define L1_SECT_S (1u << 16)
#define L1_SECT_nG (1u << 17)

void map_bitmap_kernel_rw_only(uint32_t *pgdir)
{
    extern physical_allocator_t phys_alloc;
    uint32_t bitmap_addr = (uint32_t)phys_alloc.bitmap;
    uint32_t index = get_L1_index(bitmap_addr);

    // RW pour kernel, NO ACCESS pour user
    pgdir[index] = bitmap_addr |
                         0x00000002 | // Section entry
                         0x00000400 | // AP[2:1] = 01 : Kernel RW, User NO ACCESS
                         0x00000000 | // User bit = 0 (pas d'accès user)
                         0x00001000 | // TEX[0] = 1
                         0x00000008 | // C = 1
                         0x00000004;  // B = 1

    // KDEBUG("Mapped bitmap as kernel RW only: 0x%08x\n", bitmap_addr);
}

void map_kernel_readonly_in_user_space(uint32_t *pgdir)
{

    uint32_t kernel_start = (uint32_t)&__kernel_start;
    uint32_t kernel_end = (uint32_t)&__kernel_end;
    // uint32_t *ttbr0_table = (uint32_t *)get_ttbr0();

    // Aligner sur les sections 1MB
    uint32_t start_section = kernel_start & 0xFFF00000;
    uint32_t end_section = (kernel_end + 0xFFFFF) & 0xFFF00000;

    // KDEBUG("Mapping kernel RO: [kernel_start : kernel_end]= [0x%08x : 0x%08x] -------- [start_section : end_section]= [0x%08x : 0x%08x]\n", kernel_start, kernel_end, start_section, end_section);
    // KDEBUG("Mapping kernel RO: First kernel section index %u\n", get_L1_index(start_section));

    for (uint32_t vaddr = start_section; vaddr < end_section; vaddr += 0x100000)
    {
        uint32_t index = get_L1_index(vaddr); //[1024-4095]

        // Mapping 1:1 (virtual = physical) en lecture seule pour utilisateur
        pgdir[index] = vaddr |
                             0x00000002 | // Section entry
                             0x00000800 | // AP[2:1] = 10 : RO pour user, RW pour kernel
                             0x00000010 | // User accessible
                             0x00001000 | // TEX[0] = 1 (cacheable)
                             0x00000008 | // C = 1 (cacheable)
                             0x00000004;  // B = 1 (bufferable)

        // KDEBUG("  Section 0x%08x -> PTE 0x%08x\n", vaddr, ttbr0_table[index]);
    }

    map_bitmap_kernel_rw_only(pgdir);

    uint32_t split_boundary = get_split_boundary();

    /*     uint32_t flag = L1_SECT
                   | L1_SECT_B | L1_SECT_C
                   | L1_SECT_TEX(1)      // selon ta politique (WBWA)
                   | L1_SECT_S
                   | L1_SECT_nG;   */

    // for (uint32_t addr = 0x9000000; addr < split_boundary; addr += 0x100000) {
    for (uint32_t addr = 0x0; addr < split_boundary; addr += 0x100000)
    {
        uint32_t index = get_L1_index(addr); // Index 0-1023
        // kernel_page_dir[index] = addr | 0xC0E;
        pgdir[index] = (addr & 0xFFF00000) | 0xC0E | L1_SECT_DOMAIN(0) | L1_SECT_S | L1_SECT_nG;
    }

    for (uint32_t addr = DEVICE_START; addr < DEVICE_END; addr += 0x100000)
    {
        uint32_t index = get_L1_index(addr); // Index 0-1023
        pgdir[index] = addr | 0x00000002 | // Section descriptor
                                0x00000C00 | // AP[2:1] = 11 (full access)
                                0x00000004 | // TEX[0], C, B = 001 (device memory)
                                0x00000000 | // Domain 0
                                0x00000000 | // nG = 0 (global)
                                0x00000000; // S = 0 (non-shared, OK pour device)
    }

    // CRITIQUE: Vérifier que Domain 0 est accessible
    uint32_t dacr = get_dacr();
    if ((dacr & 0x3) == 0)
    {
        KDEBUG("Fixing DACR for Domain 0\n");
        set_dacr(dacr | 0x1); // Domain 0 = Client
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

    /* Zéroiser le pgdir utilisateur (seulement 8KB pour TTBR0) */
    memset(vm->pgdir, 0, PGDIR_SIZE);

    /* Les mappings noyau sont dans TTBR1, pas besoin de les copier */
    /* TTBR0 ne contiendra que les mappings utilisateur */

    vm->vma_list = NULL;
    vm->heap_start = USER_HEAP_START;
    vm->brk = USER_HEAP_START;
    vm->heap_end = USER_HEAP_END;
    vm->stack_start = USER_STACK_BOTTOM;
    vm->asid = asid; /* Nouveau champ ASID */

    map_kernel_readonly_in_user_space(vm->pgdir);

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

static void copy_kernel_mappings(uint32_t *new_pgdir)
{
    /* Avec split TTBR, les mappings noyau sont dans TTBR1 */
    /* TTBR0 (new_pgdir) ne contient QUE les mappings utilisateur */
    /* Cette fonction n'est plus nécessaire mais on la garde pour compatibilité */

    KDEBUG("copy_kernel_mappings: With split TTBR, kernel mappings are in TTBR1\n");
    KDEBUG("copy_kernel_mappings: TTBR0 pgdir 0x%08X contains only user mappings\n",
           (uint32_t)new_pgdir);

    /* Ne rien faire - les mappings noyau sont automatiquement disponibles via TTBR1 */
    (void)new_pgdir;
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
            if (phys_addr)
            {
                //KDEBUG("destroy_vm_space: Freeing page 0x%08X\n", phys_addr);
                free_page((void *)phys_addr);
            }
        }

        kfree(vma);
        vma = next;
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
    vma_t *vma = kmalloc(sizeof(vma_t));
    vma_t *current;

    if (!vma)
        return NULL;

    /* Vérifier que l'adresse est dans l'espace utilisateur TTBR0 (<2GB) */
    if (start >= 0x40000000)
    {
        KERROR("create_vma: Address 0x%08X is in kernel space (>=2GB)\n", start);
        kfree(vma);
        return NULL;
    }

    if (start + size > 0x40000000)
    {
        KERROR("create_vma: VMA extends into kernel space\n");
        kfree(vma);
        return NULL;
    }

    vma->start = start;
    vma->end = start + size;
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
            cow_copy_vma(parent_vm, child_vm, parent_vma);
            // KDEBUG(" DONE\n");
        }
        else
        {
            // KDEBUG("fork_vm_space: SHARE VMA 0x%08X-0x%08X \n",
            //        parent_vma->start, parent_vma->end);
            // share_vma_pages(parent_vm, child_vm, parent_vma);
            cow_copy_vma(parent_vm, child_vm, parent_vma);
            // KDEBUG(" DONE\n");
        }

        parent_vma = parent_vma->next;
    }

    child_vm->heap_start = parent_vm->heap_start;
    child_vm->heap_end = parent_vm->heap_end;
    child_vm->stack_start = parent_vm->stack_start;
    child_vm->brk = parent_vm->brk;

    copy_user_stack_pages(parent_vm, child_vm, (USER_STACK_TOP - PAGE_SIZE) & ~0xFFF, PAGE_SIZE);

     //KDEBUG("fork_vm_space: Fork completed - Child Heap Start 0x%08X, Child Heap End 0x%08X, Child Stack Start 0x%08X\n",
     //       child_vm->heap_start, child_vm->heap_end, child_vm->stack_start);

    return child_vm;
}

static void cow_copy_vma(vm_space_t *parent_vm, vm_space_t *child_vm, vma_t *vma)
{
    uint32_t vaddr;
    // uint32_t stack_start = USER_STACK_TOP;

    // KDEBUG("cow_copy_vma: parent ASID %u (pgdir 0x%08X) to child ASID %u (pgdir 0x%08X), VMA 0x%08X-0x%08X\n",
    //        parent_vm->asid, parent_vm->pgdir, child_vm->asid, child_vm->pgdir,
    //        vma->start, vma->end);

    for (vaddr = vma->start; vaddr < vma->end; vaddr += PAGE_SIZE)
    {
        if (vaddr == USER_STACK_TOP - PAGE_SIZE)
            continue;
        uint32_t phys_addr = get_physical_address(parent_vm->pgdir, vaddr);
        // uint32_t temp_ptr = map_temp_user_page(vaddr);
        uint32_t temp_ptr = phys_addr;
        if (!temp_ptr)
        {
            // KERROR("cow_copy_vma: Failed to temp-map vaddr 0x%08X\n", vaddr);
            continue;
        }

        // uint32_t phys_addr = get_phys_from_temp_mapping(temp_ptr);
        // KDEBUG("cow_copy_vma: Copying vaddr 0x%08X to phys_addr 0x%08X\n", vaddr, phys_addr);

        // unmap_temp_user_page();

        // make_page_readonly(parent_vm->pgdir, vaddr);

        uint32_t pte_flags = 0x02;
        pte_flags |= 0x0C;
        if (vma->flags & VMA_EXEC)
            pte_flags |= (2 << 4); // AP=2
        else
            pte_flags |= (2 << 4) | 0x1; // AP=2 + XN=1

        map_user_page(child_vm->pgdir, vaddr, phys_addr, vma->flags, child_vm->asid);

        // track_cow_page(phys_addr);
    }
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
             KDEBUG("find_vma: Found VMA for addr 0x%08X in ASID %u\n", addr, vm->asid);
            return vma;
        }
        vma = vma->next;
    }

     KDEBUG("find_vma: No VMA found for addr 0x%08X in ASID %u\n", addr, vm->asid);
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