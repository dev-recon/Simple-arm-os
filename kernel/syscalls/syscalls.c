#include <kernel/syscalls.h>
#include <kernel/process.h>
#include <kernel/vfs.h>
#include <kernel/kernel.h>
#include <kernel/kprintf.h>
#include <kernel/task.h>
#include <kernel/elf32.h>
#include <kernel/userspace.h>
#include <asm/mmu.h>
#include <asm/arm.h>
#include <kernel/timer.h>

/* Syscall table */
typedef int (*syscall_func_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"

static syscall_func_t syscall_table[256] = {
    [__NR_exit] = (syscall_func_t)sys_exit,
    [__NR_fork] = (syscall_func_t)sys_fork,
    [__NR_read] = (syscall_func_t)sys_read,
    [__NR_write] = (syscall_func_t)sys_write,
    [__NR_open] = (syscall_func_t)sys_open,
    [__NR_close] = (syscall_func_t)sys_close,
    [__NR_waitpid] = (syscall_func_t)sys_waitpid,
    [__NR_execve] = (syscall_func_t)sys_execve,
    [__NR_lseek] = (syscall_func_t)sys_lseek,
    [__NR_getpid] = (syscall_func_t)sys_getpid,
    [__NR_getppid] = (syscall_func_t)sys_getppid,
    [__NR_getuid] = (syscall_func_t)sys_getuid,
    [__NR_getgid] = (syscall_func_t)sys_getgid,
    [__NR_kill] = (syscall_func_t)sys_kill,
    [__NR_signal] = (syscall_func_t)sys_signal,
    [__NR_sigaction] = (syscall_func_t)sys_sigaction,
    [__NR_print] = (syscall_func_t)sys_print,
    [__NR_rt_sigreturn] = (syscall_func_t)sys_sigreturn,
    [__NR_brk] = (syscall_func_t)sys_brk,
    [__NR_mkdir] = (syscall_func_t)sys_mkdir,
    [__NR_rmdir] = (syscall_func_t)sys_rmdir,
    [__NR_unlink] = (syscall_func_t)sys_unlink,
    [__NR_dup2] = (syscall_func_t)sys_dup2,
    [__NR_dup] = (syscall_func_t)sys_dup,
    [__NR_getcwd] = (syscall_func_t)sys_getcwd,
    [__NR_chdir] = (syscall_func_t)sys_chdir,
    [__NR_pipe] = (syscall_func_t)sys_pipe,
    [__NR_stat] = (syscall_func_t)sys_stat,
    [__NR_fstat] = (syscall_func_t)sys_fstat,
};

#pragma GCC diagnostic pop

/* Forward declarations de toutes les fonctions statiques */
extern void cleanup_exec_args(char* filename, char** argv, char** envp);
extern int read_elf_header(inode_t* inode, elf32_ehdr_t* header);
extern bool validate_elf_header(elf32_ehdr_t* header);
extern int load_elf_segments(inode_t* inode, elf32_ehdr_t* elf_header, vm_space_t* vm);
extern int load_segment(inode_t* inode, elf32_phdr_t* phdr, vm_space_t* vm);
extern int setup_user_stack(vm_space_t* vm, char** argv, char** envp);
extern int count_strings(char** strings);
extern char** setup_stack_strings(char** strings, char** stack_ptr);
extern void copy_string_array(char** src, char** dest, int count);
extern void orphan_children(task_t* proc);
extern void switch_to_idle_stack(void);

extern void __task_switch_to_user(task_context_t* new_ctx);
extern void __task_switch(task_context_t* old_ctx, task_context_t* new_ctx);
extern void __task_switch(task_context_t* old_ctx, task_context_t* new_ctx);

extern int copy_user_stack_pages(vm_space_t *parent_vm, vm_space_t *child_vm, 
                          uint32_t stack_start, uint32_t stack_size);

void dump_svc_stack(task_t *task, uint32_t *sp) {
    kprintf("SVC stack @%08x:\n", (unsigned)sp);
    for (int i=0;i<12;i++) {
        kprintf(" +%02x: %08x\n", i*4, sp[i]);
    }
    kprintf("Offset of context = %d\n", (uint32_t)&(task->context) - (uint32_t)task );
}

void print_cpu_mode(void){
     uint32_t cpsr = get_cpsr();
     cpsr &= 0x1F;
    
    kprintf("\n\n**************************************\n");
    kprintf("Current CPU MODE = Mode: 0x%02X, -->: %s\n", 
            cpsr , cpsr == ARM_MODE_USR ? "USR" : cpsr == ARM_MODE_SVC ? "SVC" : "UNKNOWN" );
    kprintf("**************************************\n\n");

}

void check_instruction(uint32_t test_vaddr, uint32_t phys_addr, uint32_t instruction)
{
    uint32_t l1_index = get_L1_index(test_vaddr);  // 0 
    uint32_t l2_index = L2_INDEX(test_vaddr);  // 8 

    KDEBUG("  Testing user mapping 0x%08X:\n", test_vaddr);

        KDEBUG("    L1 index: %u, L2 index: %u\n", l1_index, l2_index);


    /* Lire depuis le pgdir actuel (maintenant 0x41538000) */
    uint32_t current_ttbr0;
    asm volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(current_ttbr0));
    uint32_t* active_pgdir = (uint32_t*)(current_ttbr0 & ~0x7F);

    uint32_t l1_entry = active_pgdir[l1_index];
    KDEBUG("Current TTBR0 = 0x%08X\n", (uint32_t)active_pgdir);
    //for (int i = 0 ; i < 16 ; i++) {
    //    uint32_t entry = active_pgdir[i];
    //    KDEBUG("    L1[%u] = 0x%08X\n", i, entry);
    //}

    if (l1_entry & 0x1) {  // Page table entry
        KDEBUG("    User area properly mapped via page table\n");
    } else {
        KERROR("    User area not mapped!\n");
    }

    KDEBUG("=== FINAL INSTRUCTION CHECK ===\n"); 

    uint32_t first_instruction; 
    uint32_t paddr = phys_addr;
    uint32_t* phys_code = (uint32_t*)paddr;
    first_instruction = *phys_code;

    KDEBUG("  First instruction at 0x8000: user code (phys 0x%08X): 0x%08X\n",
        paddr, first_instruction);
    KDEBUG("  Expected: 0x%08X\n", instruction);

    if (first_instruction == instruction) {
        KDEBUG("  Instruction correct, ready for execution\n");
    } else {
        KERROR("  Instruction mismatch!\n");
    }  

    /* Lire l'instruction à l'adresse virtuelle 0x8000 */
    uint32_t vaddr = test_vaddr;
    uint32_t* user_code = (uint32_t*)vaddr;
    KDEBUG("=== USER CODE OK === user code 0x%08X \n", *user_code); 
}


void dbg_dump_pte_0x8000(void){
    // L1 base (ttbr0_base_pa & ~0x3FFF)
    uint32_t *l1 = (uint32_t*)map_temp_page(get_ttbr0() & 0xFFFFC000u);
    uint32_t e1 = l1[0];
    kprintf("DBG L1[0]=0x%08X for TTBRO = 0x%08X\n", e1, get_ttbr0());
    //hexdump((void *)get_ttbr0(),32);
    //hexdump((void *)0x7F001000, 32);

    if ((e1 & 3u) == 1u){
        uint32_t l2_pa_1kb = e1 & 0xFFFFFC00u;
        uint32_t l2_page_pa = l2_pa_1kb & ~0x3FFu;
        uint32_t l2_off = l2_pa_1kb & 0x3FFu;

        uint8_t *l2p = (uint8_t*)map_temp_page(l2_page_pa);
        volatile uint32_t *l2 = (volatile uint32_t*)(l2p + l2_off);
        kprintf("DBG L2[8]=0x%08X (L2_page_pa=0x%08X)\n", l2[8], l2_page_pa);
        unmap_temp_page((void*)l2p);
    }
    unmap_temp_page((void*)l1);
}

/**
 * sys_execve - Executer un nouveau programme - ADAPTe
 */
int sys_execve(const char* filename, char* const argv[], char* const envp[])
{
    task_t* proc = current_task;
    char* kernel_filename;
    char** kernel_argv;
    char** kernel_envp;
    inode_t* exe_inode;
    elf32_ehdr_t elf_header;
    vm_space_t* old_vm;
    vm_space_t* new_vm;
    int len = 0 ;
    uint32_t argc = 0;
    uint32_t envpc = 0;
    
    /* Verification processus - ADAPTe */
    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process) {
        KERROR("sys_execve: Current task is not a process\n");
        KERROR("sys_execve: NULL Proc\n");
        return -EINVAL;
    }

        /* Verification processus - ADAPTe */
    if (!filename) {
        KERROR("sys_execve: filename is NULL\n");
        return -EINVAL;
    }

    len = strlen(filename);

    if(argv )
    while (argc < 32 && argv[argc]) {
        argc++;
    }

    if(envp )
    while (envpc < 32 && envp[envpc]) {
        envpc++;
    }

    uint32_t spsr = read_spsr();
    uint32_t caller_mode = spsr & 0x1f;   // 0x10 = USR

    bool from_user = (caller_mode == ARM_MODE_USR);  // tu n’utilises pas SYS ici

   if(from_user){

        kernel_filename = (char *)kmalloc(len+1);
        kernel_argv = (char **)kmalloc(sizeof(char*) * 5);
        kernel_envp = (char **)kmalloc(sizeof(char*) * 5);
        for(int i=0; i < 5; i++){
            if(kernel_argv)
                kernel_argv[i] = (char *)kmalloc(256);
            if(kernel_envp)
                kernel_envp[i] = (char *)kmalloc(256);
        }

        strcpy(kernel_filename, filename);
        strcpy(kernel_argv[0], argv[0]);

        kernel_argv[1] = argv[1];
        kernel_envp[0] = envp[0];
   }
   else {
        kernel_filename = (char *)kmalloc(len+1);
        kernel_argv = (char **)kmalloc(sizeof(char*) * 5);
        kernel_envp = (char **)kmalloc(sizeof(char*) * 5);
        for(int i=0; i < 5; i++){
            if(kernel_argv)
                kernel_argv[i] = (char *)kmalloc(256);
            if(kernel_envp)
                kernel_envp[i] = (char *)kmalloc(256);
        }

        strcpy(kernel_filename, filename);
        strcpy(kernel_argv[0], argv[0]);

        kernel_argv[1] = argv[1];
        kernel_envp[0] = envp[0];
   }

    /* Ouvrir le fichier executable */
    exe_inode = path_lookup(kernel_filename);
    if (!exe_inode) {
        KERROR("sys_execve: File not found: %s\n", kernel_filename);
        cleanup_exec_args(kernel_filename, kernel_argv, kernel_envp);
        return -ENOENT;
    }

    
    /* Valider l'en-tete ELF */
    if (read_elf_header(exe_inode, &elf_header) < 0) {
        KERROR("sys_execve: Failed to read ELF header\n");
        put_inode(exe_inode);
        cleanup_exec_args(kernel_filename, kernel_argv, kernel_envp);
        return -ENOEXEC;
    }
    
    /* Sauvegarder l'ancien espace memoire pour rollback - ACCeS CORRECT */
    old_vm = proc->process->vm;
    
    /* Creer un nouvel espace memoire */
    new_vm = create_vm_space();
    if (!new_vm) {
        KERROR("sys_execve: Failed to create new VM space\n");
        put_inode(exe_inode);
        cleanup_exec_args(kernel_filename, kernel_argv, kernel_envp);
        return -ENOMEM;
    }
    
    /* Configurer la pile utilisateur avec arguments */
    if (setup_user_stack(new_vm, kernel_argv, kernel_envp) < 0) {
        KERROR("sys_execve: Failed to setup user stack\n");
        destroy_vm_space(new_vm);
        put_inode(exe_inode);
        cleanup_exec_args(kernel_filename, kernel_argv, kernel_envp);
        return -ENOMEM;
    }

    /* Charger les segments ELF */
    if (load_elf_segments(exe_inode, &elf_header, new_vm) < 0) {
        KERROR("sys_execve: Failed to load ELF segments\n");
        destroy_vm_space(new_vm);
        put_inode(exe_inode);
        cleanup_exec_args(kernel_filename, kernel_argv, kernel_envp);
        return -ENOEXEC;
    }
    
    /* Remplacer l'espace memoire - ACCeS CORRECT */
    destroy_vm_space(old_vm);
    proc->process->vm = new_vm;
    
    /* Reinitialiser le contexte CPU - ADAPTe a VOTRE STRUCTURE */
    memset(&proc->context, 0, sizeof(task_context_t));

    //proc->context.pc = elf_header.e_entry;              /* Point d'entree */
    proc->context.is_first_run = 1;                     /* Pas la premiere fois */
    proc->context.ttbr0 = (uint32_t)new_vm->pgdir;
    proc->context.asid = new_vm->asid;
    proc->context.returns_to_user = 1;
    proc->context.cpsr = 0x60000010;                          /* Mode USER */

        /* Configuration KERNEL (pour les syscalls futurs) */
    proc->context.svc_sp_top = (uint32_t)proc->stack_top; /* Pile kernel pour cette tâche */
    proc->context.sp = proc->context.svc_sp_top - 512;             /* Stack pointer */
    proc->context.sp &= ~7;
    proc->context.svc_sp = proc->context.sp;


    /* Configuration USER - CORRECTION CRITIQUE */
    proc->context.usr_pc = elf_header.e_entry;         /* Point d'entrée USER */
    //proc->context.usr_sp = new_vm->stack_start + USER_STACK_SIZE - 512;        /* Stack USER */
    proc->context.usr_sp = new_vm->stack_start;        /* Stack USER */
    proc->context.usr_sp &= ~7;
    proc->context.usr_cpsr = 0x60000010;               /* MODE USER + IRQ enabled */

    /* Arguments initiaux (argc, argv, etc.) */
    proc->context.usr_r[0] = (uint32_t)kernel_filename;                     /* r0 = argc */
    proc->context.usr_r[1] = (uint32_t)kernel_argv;     /* r1 = argv */
    proc->context.usr_r[2] = (uint32_t)kernel_envp;     /* r2 = envp */
    proc->context.usr_r[3] = argc;     /* r2 = envp */

   /* Fermer tous les fichiers CLOEXEC - ACCeS CORRECT */
    close_cloexec_files(proc);

    switch_to_vm_space(new_vm);

    //tlb_flush_all_debug();
    data_memory_barrier();
    instruction_sync_barrier();

    /* Nettoyer les ressources temporaires */
    put_inode(exe_inode);
    cleanup_exec_args(kernel_filename, kernel_argv, kernel_envp);

    //__task_switch_to_user(&proc->context);
    __task_switch(NULL, &proc->context);

    /* Cette fonction ne retourne JAMAIS */
    __builtin_unreachable();
}


/**
 * sys_fork corrige - ACCeS CORRECT a la structure
 */
int sys_fork(void)
{
    task_t* parent = current_task;
    task_t* child;
    int i;

    uint32_t return_address;
    __asm__ volatile("mov %0, lr" : "=r"(return_address));

    uint32_t spsr = read_spsr();
    uint32_t caller_mode = spsr & 0x1f;   // 0x10 = USR

    bool from_user = (caller_mode == ARM_MODE_USR);  // tu n’utilises pas SYS ici
    
    if (!parent || parent->type != TASK_TYPE_PROCESS) {
        KERROR("sys_fork: Current task is not a process\n");
        KERROR("sys_fork: NULL Parent\n");
        return -EINVAL;
    }
    
    /* Creer le processus enfant en copiant le parent */
    child = task_create_copy(parent, from_user);
    if (!child) {
        KERROR("sys_fork: Failed to create child process\n");
        return -ENOMEM;
    }

    /* Configuration des relations parent-enfant - ACCeS CORRECT */
    child->process->parent = parent;
    child->process->sibling_next = parent->process->children;
    parent->process->children = child;
    
    /* Copier l'espace memoire avec COW - ACCeS CORRECT */
    if (child->process->vm) {
        destroy_vm_space(child->process->vm);
    }

    child->process->vm = fork_vm_space(parent->process->vm);
    if (!child->process->vm) {
        KERROR("sys_fork: Failed to copy VM space\n");
        destroy_process(child);
        return -ENOMEM;
    }
    
    /* Copier les descripteurs de fichiers - ACCeS CORRECT */
    for (i = 0; i < MAX_FILES; i++) {
        if (parent->process->files[i]) {
            child->process->files[i] = parent->process->files[i];
            parent->process->files[i]->ref_count++;
        }
    }

    init_process_signals(child);

    parent->context.usr_lr = return_address ;    /* Adresse après SWI */
    child->context.ttbr0 = (uint32_t)child->process->vm->pgdir;
    child->context.asid = child->process->vm->asid;

    if( from_user )
    {
        // Reprendre au même point utilisateur que le parent (après SVC)
        child->context.usr_pc   = parent->context.usr_pc;

        // Même pile utilisateur que le parent (copy-on-write dans ta VM)
        child->context.usr_sp   = parent->context.usr_sp;

        // Marquer premier run
        child->context.is_first_run = 1;
        child->context.returns_to_user = 1;

        /* CRITIQUE: Copier le contexte de reprise du parent */
        child->context.usr_lr = parent->context.usr_lr;    /*  Adresse après SWI */
        child->context.usr_cpsr = read_spsr_svc(); /*  Mode user */
        
        /* Copier tous les registres user SAUF r0 */
        memcpy(child->context.usr_r, parent->context.usr_r, sizeof(parent->context.usr_r));
        child->context.usr_r[0] = 0;            /*  Enfant retourne 0 */

        child->context.r0 = 0;
        child->context.lr = return_address;
        child->context.pc = return_address;
        child->context.usr_lr   = parent->context.usr_pc;
        child->context.usr_pc   = parent->context.usr_pc;

        child->context.spsr = read_spsr_svc();

    }
    else{
        /* L'enfant retourne 0 dans r0 */
        child->context.r0 = 0;
        child->context.is_first_run = 1;
        child->context.pc = return_address;       /* Après sys_fork() dans C */
        child->context.lr = return_address;       /* LR cohérent */
        child->context.returns_to_user = 0;
        child->context.spsr = read_spsr_svc();

        /* Copier tous les registres user SAUF r0 */
        memcpy(child->context.usr_r, parent->context.usr_r, sizeof(parent->context.usr_r));
        child->context.usr_r[0] = 0;            /*  Enfant retourne 0 */
    }

    add_to_ready_queue(child);
    
    return child->process->pid;
}


void sys_exit(int status)
{
    task_t* proc = current_task;

    if (!proc) {
        KERROR("sys_exit: No current task\n");
        KERROR("sys_exit: NULL Proc\n");
        return;
    }

    if (proc->type != TASK_TYPE_PROCESS || !proc->process) {
        KERROR("[EXIT] sys_exit called from non-process task! Name = %s\n", proc->name);
        return;
    }
    
    if (proc->type != TASK_TYPE_PROCESS) {
        //KDEBUG("sys_exit: Kernel task %s terminating\n", proc->name);
        task_destroy(proc);
        return;
    }

    int irq_flags = disable_interrupts_save();
    //set_critical_section();
    //KDEBUG("EXITING TASK %s - Status = %d, with state = %s\n", proc->name, status, task_state_string(proc->state));

    spin_lock(&task_lock);    
    /* CORRECTION: États cohérents avec sys_waitpid */
    proc->process->exit_code = status;
    //task_set_state(proc, TASK_ZOMBIE);
    proc->state = TASK_ZOMBIE;           /* Pas TASK_TERMINATED ! */
    proc->process->state = (proc_state_t)PROC_ZOMBIE;
    spin_unlock(&task_lock);

    /* Reveiller le parent s'il attend - ACCeS CORRECT */
    wakeup_parent(proc);

    /* Fermer tous les fichiers ouverts - ACCeS CORRECT */
    close_all_process_files(proc);
    
    /* Retirer le processus zombie de la ready queue */
    remove_from_ready_queue(proc);

    /* Orpheliner tous les enfants vers init (PID 1) - ACCeS CORRECT */
    orphan_children(proc);

    //KDEBUG("EXITING TASK %s, with state = %s-----\n", proc->name, task_state_string(proc->state));
    
    //unset_critical_section();
    restore_interrupts(irq_flags);
    /* Declencher une commutation de contexte */
    switch_to_idle();
    //schedule();

    
    //KDEBUG("EXITING TASK %s, with state = %s\n", proc->name, task_state_string(proc->state));

    /* Cette ligne ne devrait jamais s'executer */
    KERROR("sys_exit: FATAL - Zombie process PID=%u was rescheduled!\n", 
           proc->process->pid);
    
    /* Boucle d'urgence pour eviter la corruption */
    while (1) {
        __asm__ volatile("wfi");
    }
}



int kernel_waitpid(pid_t pid, int* status, int options, task_t* parent)
{
    task_t* zombie = NULL;
    
    (void)options;
    
    if (!parent || parent->type != TASK_TYPE_PROCESS || !parent->process) {
        KERROR("kernel_waitpid: NULL Proc\n");
        return -EINVAL;
    }
        
    //KDEBUG("ENTERING KERNEL WAITPID LOOP for %s...\n", parent->name);

    while (1) {
        /* Chercher un processus zombie - ACCeS CORRECT */
        zombie = find_zombie_child(parent, pid);

        //KDEBUG("SEEKING FOR ZOMBIE CHILD...\n");
        if (zombie) {
            /* Zombie trouve - ACCeS CORRECT */
            pid_t child_pid = zombie->process->pid;
            int exit_code = zombie->process->exit_code;
            
            /* Copier le statut de sortie */
            if (status) {
                *status = exit_code;
            }
            
            /* Retirer de la liste des enfants - ACCeS CORRECT */
            remove_child_from_parent(parent, zombie);
            
            /* Nettoyer le processus zombie */
            //task_set_state(zombie, TASK_TERMINATED);
            zombie->state = TASK_TERMINATED;
            zombie->process->state = (proc_state_t)PROC_DEAD;
            destroy_process(zombie);
            
            return child_pid;
        }
        
        //KDEBUG("NO ZOMBIE CHILD FOUND...\n");

        /* Verifier s'il y a encore des enfants eligibles - ACCeS CORRECT */
        if (!has_children(parent, pid)) {
            KDEBUG("kernel_waitpid: No eligible children\n");
            return -ECHILD;
        }
        
        /* Sauvegarder le contexte d'attente - ACCeS CORRECT */
        parent->process->waitpid_pid = pid;
        parent->process->waitpid_status = status;
        parent->process->waitpid_options = options;
        parent->process->waitpid_iteration++;
        
        /* Bloquer le parent en attente - ACCeS CORRECT */
        //task_set_state(parent, TASK_BLOCKED);
        parent->state = TASK_BLOCKED;
        parent->process->state = (proc_state_t)PROC_BLOCKED;

        remove_from_ready_queue(parent);

        yield();
        
        //KDEBUG("kernel_waitpid: Parent PID %u resumed\n", parent->process->pid);
    }
    
    /* Ne devrait jamais arriver, mais pour éviter warning */
    return -EINTR;
}



int sys_waitpid(pid_t pid, int* status, int options)
{

    task_sleep_ms(10000);
    //KDEBUG("sys_waitpid: called for = %d - &status = 0x%08X\n", pid, (uint32_t)status);

    task_t *parent = current_task;

    //debug_print_ctx(&parent->context, "--->>> SYS_WAITPID START");


    bool from_user = parent->context.returns_to_user ? true : false;
    if(from_user){
        //parent->context.returns_to_user = 0 ;  // FIX IT
        // Parent is temporarily restoring to kernel to not resuming too early to user 
               //yield();
    }

    int exit_code;
    pid_t result = kernel_waitpid(pid, &exit_code, options, parent);

    if (result > 0 && status) {
        /* copy_to_user pour les appels depuis l'espace utilisateur */
        if (copy_to_user(status, &exit_code, sizeof(int)) < 0) {
            return -EFAULT;
        }
    }

    //debug_print_ctx(&parent->context, "---->>> SYS_WAITPID AFTER KERNEL_WAITPID");

    if(from_user){
        parent->defer_return_to_user = 1 ;  // FIX IT
        //yield();
        // Parent is temporarily restoring to kernel to not resuming to user too early
    }

    //KDEBUG("sys_waitpid: returning to callee  = %d\n", sys_getppid());

    
    return result;
}

static inline void get_usr_regs(uint32_t usr_r[13]) {
    __asm__ volatile(
        "stmia %0, {r0-r12}"
        : //"=m" (*usr_r)   // sortie : écrit dans usr_r[0..12]
        : "r" (usr_r)    // entrée : adresse du tableau
        : "memory"
    );
}

static inline void read_user_sp_lr(uint32_t *usp, uint32_t *ulr)
{
    __asm__ volatile(
        "cps    #0x1F      \n"   /* SYSTEM */
        "mov    %0, sp     \n"
        "mov    %1, lr     \n"
        "cps    #0x13      \n"   /* SVC */
        : "=r"(*usp), "=r"(*ulr)
        :
        : "memory","cc"
    );
}

void store_usr_regs(task_context_t *ctx, uint32_t usr_r[13]) {

    ctx->r0 = usr_r[0];
    ctx->r1 = usr_r[1];
    ctx->r2 = usr_r[2];
    ctx->r3 = usr_r[3];
    ctx->r4 = usr_r[4];
    ctx->r5 = usr_r[5];
    ctx->r6 = usr_r[6];
    ctx->r7 = usr_r[7];
    ctx->r8 = usr_r[8];
    ctx->r9 = usr_r[9];
    ctx->r10 = usr_r[10];
    ctx->r11 = usr_r[11];
    ctx->r12 = usr_r[12];
}


void print_task_offsets(void) {
    KDEBUG("=== TASK STRUCTURE OFFSETS ===\n");
    KDEBUG("task_id: %zu\n", offsetof(task_t, task_id));
    KDEBUG("name: %zu\n", offsetof(task_t, name));
    KDEBUG("state: %zu\n", offsetof(task_t, state));
    KDEBUG("priority: %zu\n", offsetof(task_t, priority));
    KDEBUG("context: %zu\n", offsetof(task_t, context));
    KDEBUG("stack_base: %zu\n", offsetof(task_t, stack_base));
    KDEBUG("Total size: %zu\n", sizeof(task_t));
}


void print_context_offsets(void) {
    KDEBUG("\n=== CONTEXT STRUCTURE OFFSETS ===\n");
    KDEBUG("r0: %zu\n", offsetof(task_context_t, r0));
    KDEBUG("r1: %zu\n", offsetof(task_context_t, r1));
    KDEBUG("r2: %zu\n", offsetof(task_context_t, r2));
    KDEBUG("r3: %zu\n", offsetof(task_context_t, r3));
    KDEBUG("r4: %zu\n", offsetof(task_context_t, r4));
    KDEBUG("r5: %zu\n", offsetof(task_context_t, r5));
    KDEBUG("r6: %zu\n", offsetof(task_context_t, r6));
    KDEBUG("r7: %zu\n", offsetof(task_context_t, r7));
    KDEBUG("r8: %zu\n", offsetof(task_context_t, r8));
    KDEBUG("r9: %zu\n", offsetof(task_context_t, r9));
    KDEBUG("r10: %zu\n", offsetof(task_context_t, r10));
    KDEBUG("r11: %zu\n", offsetof(task_context_t, r11));
    KDEBUG("r12: %zu\n", offsetof(task_context_t, r12));

    //

    KDEBUG("sp: %zu\n", offsetof(task_context_t, sp));
    KDEBUG("lr: %zu\n", offsetof(task_context_t, lr));
    KDEBUG("pc: %zu\n", offsetof(task_context_t, pc));
    KDEBUG("cpsr: %zu\n", offsetof(task_context_t, cpsr));

    //

    KDEBUG("is_first_run: %zu\n", offsetof(task_context_t, is_first_run));
    KDEBUG("ttbr0: %zu\n", offsetof(task_context_t, ttbr0));
    KDEBUG("asid: %zu\n", offsetof(task_context_t, asid));
    KDEBUG("spsr: %zu\n", offsetof(task_context_t, spsr));
    KDEBUG("returns_to_user: %zu\n", offsetof(task_context_t, returns_to_user));

    KDEBUG("usr_r[0]: %zu\n", offsetof(task_context_t, usr_r[0]));
    KDEBUG("usr_r[1]: %zu\n", offsetof(task_context_t, usr_r[1]));
    KDEBUG("usr_r[2]: %zu\n", offsetof(task_context_t, usr_r[2]));
    KDEBUG("usr_r[3]: %zu\n", offsetof(task_context_t, usr_r[3]));
    KDEBUG("usr_r[4]: %zu\n", offsetof(task_context_t, usr_r[4]));
    KDEBUG("usr_r[5]: %zu\n", offsetof(task_context_t, usr_r[5]));
    KDEBUG("usr_r[6]: %zu\n", offsetof(task_context_t, usr_r[6]));
    KDEBUG("usr_r[7]: %zu\n", offsetof(task_context_t, usr_r[7]));
    KDEBUG("usr_r[8]: %zu\n", offsetof(task_context_t, usr_r[8]));
    KDEBUG("usr_r[9]: %zu\n", offsetof(task_context_t, usr_r[9]));
    KDEBUG("usr_r[10]: %zu\n", offsetof(task_context_t, usr_r[10]));
    KDEBUG("usr_r[11]: %zu\n", offsetof(task_context_t, usr_r[11]));
    KDEBUG("usr_r[12]: %zu\n", offsetof(task_context_t, usr_r[12]));


    KDEBUG("usr_sp: %zu\n", offsetof(task_context_t, usr_sp));
    KDEBUG("usr_lr: %zu\n", offsetof(task_context_t, usr_lr));
    KDEBUG("usr_pc: %zu\n", offsetof(task_context_t, usr_pc));
    KDEBUG("usr_cpsr: %zu\n", offsetof(task_context_t, usr_cpsr));
    KDEBUG("svc_sp_top: %zu\n", offsetof(task_context_t, svc_sp_top));
    KDEBUG("svc_sp: %zu\n", offsetof(task_context_t, svc_sp));
    KDEBUG("svc_lr_saved: %zu\n", offsetof(task_context_t, svc_lr_saved));


    KDEBUG("Total size: %zu\n", sizeof(task_context_t));
}

int syscall_handler(uint32_t syscall_num, uint32_t arg1, uint32_t arg2, 
                   uint32_t arg3, uint32_t arg4, uint32_t arg5)
{
    //KDEBUG("====== SYSCALL HANDLER ===========\n");
    //char str[100];

    if (syscall_num >= 256 || !syscall_table[syscall_num]) {
        return -ENOSYS;
    }

    task_t *proc = current_task;
    uint32_t usr_r11 = proc->context.usr_r[11];

    if(proc && proc->context.returns_to_user)
    {
        //proc->context.svc_sp = proc->context.sp;
    }

    //KDEBUG(" SYSCALL NUM == %u == %s\n", syscall_num, proc->name);


//print_task_offsets();
// print_context_offsets();

    /* Check pending signals before syscall */
    check_pending_signals();

    //uint32_t usr_r[13];
    //get_usr_regs(usr_r);
    //store_usr_regs(&proc->context, usr_r);

    //debug_print_ctx(&proc->context, "----->>>>>> ENTER SYSCALL HANDLER");
    
    /* Call syscall */
    int result = syscall_table[syscall_num](arg1, arg2, arg3, arg4, arg5);
   
    /* Check pending signals after syscall */
    check_pending_signals();

    if (need_resched /* && (syscall_num != __NR_waitpid) */) {
        need_resched = 0;
        bool from_user = proc->context.returns_to_user ? true : false;
        if(from_user){
            //proc->context.returns_to_user = 0 ;  // FIX IT
            proc->defer_return_to_user = 1;
            // Parent is temporarily restoring to kernel to not resuming too early to user 
        }

        //KDEBUG("RESCHEDULING SOME TASK: PROC %s\n", proc->name);



        //schedule_to(idle_task);  /* Ici on est en mode SVC, pas IRQ */
        yield();

        if(from_user){
            //proc->context.returns_to_user = 1 ;  // FIX IT
            proc->defer_return_to_user = 0;
            // Parent is temporarily restoring to kernel to not resuming too early to user 
            //yield();
        }

        //debug_print_ctx(&proc->context, str);

    }
    proc->context.usr_r[11] = usr_r11;
    //snprintf(str, 100, "PROC CONTEXT %s", proc->name);
    //KDEBUG(" SYSCALL %d RESULT == 0x%08X == %s\n", syscall_num, result, proc->name);
    //debug_print_ctx(&proc->context, str);
    //dump_svc_stack(proc , &proc->context.sp);
    //print_context_offsets();

    return result;
}

/**
 * Syscalls simples adaptes
 */
int sys_getpid(void)
{
    task_t *proc = current_task;

    if (proc && proc->type == TASK_TYPE_PROCESS && proc->process) {
        return proc->process->pid;
    }
    return 0;
}

int sys_getppid(void)
{
    task_t *proc = current_task;

    if (proc && proc->type == TASK_TYPE_PROCESS && proc->process) {
        return proc->process->ppid;
    }
    return 0;
}

int sys_getuid(void)
{
    /* Simple implementation - always return 0 (root) */
    task_t *proc = current_task;

    if (proc && proc->type == TASK_TYPE_PROCESS && proc->process) {
        return proc->process->uid;
    }

    return 0;
}

int sys_getgid(void)
{
    /* Simple implementation - always return 0 (root) */
    task_t *proc = current_task;

    if (proc && proc->type == TASK_TYPE_PROCESS && proc->process) {
        return proc->process->gid;
    }
    return 0;
}



int sys_print(const char* msg) {

    char *str = NULL;

    bool user_mode = IS_USER_ADDR((uint32_t)msg);

    if(user_mode){
        str = copy_string_from_user(msg);
    }
    else{
        str = kmalloc(strlen(msg)+1);
        strcpy(str, msg);
    }


    if(str) {
        kprintf("%s", msg);  // OK car valide
    }
    else {
        if(msg)
            KERROR("Invalid String from userspace %s\n", msg);
        else
            KERROR("Invalid String from userspace: NULL message\n");
        return -1;
    }

    return 0;
}
