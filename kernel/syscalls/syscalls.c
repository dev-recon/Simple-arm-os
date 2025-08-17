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


static char mock_user_space[4096] __attribute__((aligned(4096)));

static bool setup_mock_user_space(void) {
    // Marquer cette zone comme "espace utilisateur" pour les tests
    // Mapper mock_user_space dans l'espace utilisateur virtuel
    
    uint32_t virt_addr = USER_SPACE_START;  // Ex: 0x00400000
    map_kernel_page(virt_addr, (uint32_t)mock_user_space);
    
    return true;
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
    KDEBUG("Current TTBR0 = 0x%08X\n", active_pgdir);
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
    
    /* Verification processus - ADAPTe */
    if (!proc || proc->type != TASK_TYPE_PROCESS) {
        KERROR("sys_execve: Current task is not a process\n");
        return -EINVAL;
    }
    
    KDEBUG("sys_execve: Process PID=%u executing %s\n", proc->process->pid, filename);

    //setup_mock_user_space();
    
    /* Copier les arguments depuis l'espace utilisateur */
    //kernel_filename = copy_string_from_user(filename);
    //if (!kernel_filename) {
    //    KERROR("sys_execve: Failed to copy filename %s\n", filename);
    //    return -EFAULT;
    //}
    
    //kernel_argv = copy_argv_from_user(argv);
    //kernel_envp = copy_argv_from_user(envp);

    kernel_filename = (char *)kmalloc(256);
    kernel_argv = (char **)kmalloc(sizeof(char*) * 5);
    kernel_envp = (char **)kmalloc(sizeof(char*) * 5);
    for(int i=0; i < 5; i++){
        if(kernel_argv)
            kernel_argv[i] = (char *)kmalloc(256);
        if(kernel_envp)
            kernel_envp[i] = (char *)kmalloc(256);
    }
    
    //char* const argv[] = { "hello", NULL };
    //char* const envp[] = { NULL };

    strcpy(kernel_filename, filename);
    strcpy(kernel_argv[0], argv[0]);

    kernel_argv[1] = argv[1];
    kernel_envp[0] = envp[0];

    
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
    
    if (!validate_elf_header(&elf_header)) {
        KERROR("sys_execve: Invalid ELF header\n");
        put_inode(exe_inode);
        cleanup_exec_args(kernel_filename, kernel_argv, kernel_envp);
        return -ENOEXEC;
    }
    
    //KDEBUG("sys_execve: ELF entry point: 0x%08X\n", elf_header.e_entry);


/*     // Test direct de lecture du fichier ELF 
        KDEBUG("=== FILE CONTENT DIAGNOSTIC ===\n");
        KDEBUG("File inode: size=%u, blocks allocated=%u\n", exe_inode->size, exe_inode->blocks);

        // Test 1: Lire l'en-tête ELF (offset 0) 
        file_t debug_file = {
            .inode = exe_inode,
            .offset = 0,
            .flags = O_RDONLY,
            .f_op = exe_inode->f_op
        };

        char header_buffer[64];
        ssize_t header_read = debug_file.f_op->read(&debug_file, header_buffer, 64);
        KDEBUG("ELF header read: %d bytes\n", header_read);

        if (header_read > 0) {
            KDEBUG("ELF magic: %02X %02X %02X %02X ('%c%c%c%c')\n",
                header_buffer[0], header_buffer[1], header_buffer[2], header_buffer[3],
                header_buffer[1], header_buffer[2], header_buffer[3], header_buffer[0]);
            
            // Vérifier que c'est vraiment un ELF 
            if (header_buffer[0] == 0x7F && header_buffer[1] == 'E' && 
                header_buffer[2] == 'L' && header_buffer[3] == 'F') {
                KDEBUG("ELF magic is correct\n");
            } else {
                KERROR("ELF magic is wrong! File may be corrupted\n");
            }
        }

        // Test 2: Lire au début de la section de code (offset 0x1000)
        debug_file.offset = 0x1000;
        char code_buffer[32];
        ssize_t code_read = debug_file.f_op->read(&debug_file, code_buffer, 32);
        KDEBUG("Code section read: %d bytes from offset 0x1000\n", code_read);

        if (code_read > 0) {
            KDEBUG("Code bytes: ");
            for (int i = 0; i < MIN(code_read, 16); i++) {
                kprintf("%02X ", (uint8_t)code_buffer[i]);
            }
            kprintf("\n");
            
            // Vérifier la première instruction attendue 
            uint32_t first_instr = *(uint32_t*)code_buffer;
            KDEBUG("First instruction: 0x%08X (expected: 0xeb000006)\n", first_instr);
            
            if (first_instr == 0) {
                KERROR("Code section contains only zeros!\n");
            } else if (first_instr == 0xeb000006) {
                KINFO("Code section looks correct!\n");
            } else {
                KWARN("Code section has unexpected content\n");
            }
        }

        KDEBUG("=== END FILE DIAGNOSTIC ===\n"); */


    
    /* Sauvegarder l'ancien espace memoire pour rollback - ACCeS CORRECT */
    old_vm = proc->process->vm;
    
    /* Creer un nouvel espace memoire */
    new_vm = create_vm_space(false);
    if (!new_vm) {
        KERROR("sys_execve: Failed to create new VM space\n");
        put_inode(exe_inode);
        cleanup_exec_args(kernel_filename, kernel_argv, kernel_envp);
        return -ENOMEM;
    }

    //KDEBUG("Creer un nouvel espace memoire: Heap start %p, Heap end %p, Stack start %p\n", new_vm->heap_start, new_vm->heap_end, new_vm->stack_start);
    
    /* Charger les segments ELF */
    if (load_elf_segments(exe_inode, &elf_header, new_vm) < 0) {
        KERROR("sys_execve: Failed to load ELF segments\n");
        destroy_vm_space(new_vm);
        put_inode(exe_inode);
        cleanup_exec_args(kernel_filename, kernel_argv, kernel_envp);
        return -ENOEXEC;
    }

    //KDEBUG("Charger les segments ELF: size %u\n", exe_inode->size);
    
    /* Configurer la pile utilisateur avec arguments */
    if (setup_user_stack(new_vm, kernel_argv, kernel_envp) < 0) {
        KERROR("sys_execve: Failed to setup user stack\n");
        destroy_vm_space(new_vm);
        put_inode(exe_inode);
        cleanup_exec_args(kernel_filename, kernel_argv, kernel_envp);
        return -ENOMEM;
    }
    
    //KINFO("sys_execve: Point of no return - exec succeeds for PID=%u\n", proc->process->pid);
    
    /* === POINT DE NON-RETOUR - EXEC ReUSSIT === */
    
    /* Remplacer l'espace memoire - ACCeS CORRECT */
    destroy_vm_space(old_vm);
    proc->process->vm = new_vm;
    
    /* Reinitialiser le contexte CPU - ADAPTe a VOTRE STRUCTURE */
    memset(&proc->context, 0, sizeof(task_context_t));
    proc->context.pc = elf_header.e_entry;              /* Point d'entree */
    proc->context.sp = new_vm->stack_start;             /* Stack pointer */
    proc->context.cpsr = 0x10;                          /* Mode utilisateur */
    proc->context.is_first_run = 1;                     /* Pas la premiere fois */
    proc->context.ttbr0 = (uint32_t)new_vm->pgdir;
    proc->context.asid = new_vm->asid;
    
    /* Fermer tous les fichiers CLOEXEC - ACCeS CORRECT */
    close_cloexec_files(proc);
    
    /* Changer l'espace d'adressage */
    switch_to_vm_space(new_vm);
    
    /* Nettoyer les ressources temporaires */
    put_inode(exe_inode);
    cleanup_exec_args(kernel_filename, kernel_argv, kernel_envp);

    __task_switch_to_user(&proc->context);

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
    //KDEBUG("sys_fork: Return address in C code: 0x%08X\n", return_address);
    
    if (!parent || parent->type != TASK_TYPE_PROCESS) {
        KERROR("sys_fork: Current task is not a process\n");
        return -EINVAL;
    }

    kernel_context_save_t save = switch_to_kernel_context();
    
    /* Creer le processus enfant en copiant le parent */
    child = task_create_copy(parent);
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

    KDEBUG("sys_fork: before fork_vm_space - Parent PID=%u, Child PID=%u\n", 
          parent->process->pid, child->process->pid);

    child->process->vm = fork_vm_space(parent->process->vm);
    if (!child->process->vm) {
        KERROR("sys_fork: Failed to copy VM space\n");
        destroy_process(child);
        return -ENOMEM;
    }

    KDEBUG("sys_fork: after fork_vm_space - Parent PID=%u, Child PID=%u\n", 
          parent->process->pid, child->process->pid);
    
    /* Copier les descripteurs de fichiers - ACCeS CORRECT */
    for (i = 0; i < MAX_FILES; i++) {
        if (parent->process->files[i]) {
            child->process->files[i] = parent->process->files[i];
            parent->process->files[i]->ref_count++;
        }
    }
    
    /* Copier le contexte CPU complet du parent */
    //uint32_t child_sp = child->context.sp;  // Sauvegarder
    //memcpy(&child->context, &parent->context, sizeof(task_context_t));
    //child->context.sp = child_sp;  // Restaurer
    
    /* L'enfant retourne 0 dans r0 */
    child->context.r0 = 0;
    child->context.is_first_run = 1;
    child->context.pc = return_address;       /* Après sys_fork() dans C */
    child->context.lr = return_address;       /* LR cohérent */

    restore_from_kernel_context(save);
    
    /* Ajouter l'enfant a la liste des taches pretes */
    add_to_ready_queue(child);
    
    /* ACCeS CORRECT */
    KINFO("sys_fork: Success - Parent PID=%u, Child PID=%u\n", 
          parent->process->pid, child->process->pid);
    
    /* Ne devrait jamais arriver */
    return child->process->pid;
}


void sys_exit(int status)
{
    task_t* proc = current_task;

    if (!proc) {
        KERROR("sys_exit: No current task\n");
        return;
    }

    if (!current_task || current_task->type != TASK_TYPE_PROCESS) {
        KERROR("[EXIT] sys_exit called from non-process task! Name = %s\n", proc->name);
        return;
    }
    
    if (proc->type != TASK_TYPE_PROCESS) {
        //KDEBUG("sys_exit: Kernel task %s terminating\n", proc->name);
        task_destroy(proc);
        return;
    }

    //KINFO("[EXIT] *** PROCESS EXITING ***\n");
    //KINFO("[EXIT] PID=%u exiting with code %d\n", 
    //      current_task ? current_task->process->pid : 0, status);


    //if (current_task->process->parent) {
    //    KINFO("[EXIT] Parent PID=%u state=%d\n", 
    //          current_task->process->parent->process->pid,
    //          current_task->process->parent->state);
    //}
    
    //KINFO("sys_exit: Process PID=%u (%s) exiting with status %d\n", 
    //      proc->process->pid, proc->name, status);
    
    /* CORRECTION: États cohérents avec sys_waitpid */
    proc->process->exit_code = status;
    proc->state = TASK_ZOMBIE;           /* Pas TASK_TERMINATED ! */
    proc->process->state = (proc_state_t)PROC_ZOMBIE;
    
    /* Fermer tous les fichiers ouverts - ACCeS CORRECT */
    close_all_process_files(proc);
    
    /* Reveiller le parent s'il attend - ACCeS CORRECT */
    wakeup_parent(proc);
    
    /* Orpheliner tous les enfants vers init (PID 1) - ACCeS CORRECT */
    orphan_children(proc);

    /* Retirer le processus zombie de la ready queue */
    remove_from_ready_queue(proc);
    
    /* Declencher une commutation de contexte */
    //KDEBUG("sys_exit: Process PID=%u now zombie, scheduling next task\n", 
    //       proc->process->pid);

    schedule();
    
    /* Cette ligne ne devrait jamais s'executer */
    KERROR("sys_exit: FATAL - Zombie process PID=%u was rescheduled!\n", 
           proc->process->pid);
    
    /* Boucle d'urgence pour eviter la corruption */
    while (1) {
        __asm__ volatile("wfi");
    }
}



int kernel_waitpid(pid_t pid, int* status, int options)
{
    task_t* parent = current_task;
    task_t* zombie = NULL;
    //task_t* child = NULL;
    //task_t* prev;
    
    (void)options;
    
    if (!parent || parent->type != TASK_TYPE_PROCESS) {
        return -EINVAL;
    }
    
    /* DEBUG AU DÉBUT */
    //KDEBUG("kernel_waitpid: Called by PID=%u\n", parent->process->pid);
    //if (current_task && strstr(current_task->name, "child")) {
    //    KERROR("BUG: Child PID=%u is calling kernel_waitpid()!\n", parent->process->pid);
    //}
    
    //KDEBUG("kernel_waitpid: Parent PID=%u waiting for PID=%d\n", 
    //       parent->process->pid, pid);
    
    while (1) {
        /* Chercher un processus zombie - ACCeS CORRECT */
        //child = parent->process->children;
        zombie = find_zombie_child(parent, pid);
        
        if (zombie) {
            /* Zombie trouve - ACCeS CORRECT */
            pid_t child_pid = zombie->process->pid;
            int exit_code = zombie->process->exit_code;
            
            //KINFO("kernel_waitpid: Found zombie PID %u with exit code %d\n", 
            //      child_pid, exit_code);
            
            /* Copier le statut de sortie */
            if (status) {
                *status = exit_code;
            }
            
            /* Retirer de la liste des enfants - ACCeS CORRECT */
            remove_child_from_parent(parent, zombie);
            
            /* Nettoyer le processus zombie */
            zombie->state = TASK_TERMINATED;
            zombie->process->state = (proc_state_t)PROC_DEAD;
            destroy_process(zombie);
            
            /* DEBUG QUAND ON RETOURNE */
            //KDEBUG("kernel_waitpid: Parent PID=%u returning child_pid=%u\n", 
            //       parent->process->pid, child_pid);
            return child_pid;
        }
        
        /* Verifier s'il y a encore des enfants eligibles - ACCeS CORRECT */
        if (!has_children(parent, pid)) {
            //KDEBUG("kernel_waitpid: No eligible children\n");
            return -ECHILD;
        }
        
        /* Sauvegarder le contexte d'attente - ACCeS CORRECT */
        parent->process->waitpid_pid = pid;
        parent->process->waitpid_status = status;
        parent->process->waitpid_options = options;
        parent->process->waitpid_iteration++;
        
        /* Bloquer le parent en attente - ACCeS CORRECT */
        //KDEBUG("kernel_waitpid: Blocking parent PID %u\n", parent->process->pid);
        parent->state = TASK_BLOCKED;
        parent->process->state = (proc_state_t)PROC_BLOCKED;

        //if (current_task && strstr(current_task->name, "child")) {
        //    KDEBUG("[CHILD] kernel_waitpid() - about to yield()\n");
       // }
        
        yield();

        //if (current_task && strstr(current_task->name, "child")) {
        //    KDEBUG("[CHILD] kernel_waitpid() - returned from yield()\n");
       // }
        
        //KDEBUG("kernel_waitpid: Parent PID %u resumed\n", parent->process->pid);
    }
    
    /* Ne devrait jamais arriver, mais pour éviter warning */
    return -EINTR;
}



int sys_waitpid(pid_t pid, int* status, int options)
{
    int exit_code;
    pid_t result = kernel_waitpid(pid, &exit_code, options);
    
    if (result > 0 && status) {
        /* copy_to_user pour les appels depuis l'espace utilisateur */
        if (copy_to_user(status, &exit_code, sizeof(int)) < 0) {
            return -EFAULT;
        }
    }
    
    return result;
}



int syscall_handler(uint32_t syscall_num, uint32_t arg1, uint32_t arg2, 
                   uint32_t arg3, uint32_t arg4, uint32_t arg5)
{
    if (syscall_num >= 256 || !syscall_table[syscall_num]) {
        return -ENOSYS;
    }

    //KDEBUG("=== SYSCALL HANDLER ===\n");
    //KDEBUG("  syscall_num: %u\n", syscall_num);
    //KDEBUG("  arg1: %u (0x%08X)\n", arg1, arg1);
    //KDEBUG("  arg2: %u (0x%08X)\n", arg2, arg2);
    //KDEBUG("  arg3: %u (0x%08X)\n", arg3, arg3);
    
    /* Check pending signals before syscall */
    check_pending_signals();
    
    /* Call syscall */
    int result = syscall_table[syscall_num](arg1, arg2, arg3, arg4, arg5);
    
    /* Check pending signals after syscall */
    check_pending_signals();
    
    return result;
}

/**
 * Syscalls simples adaptes
 */
int sys_getpid(void)
{
    if (current_task && current_task->type == TASK_TYPE_PROCESS) {
        return current_task->process->pid;
    }
    return 0;
}

int sys_getppid(void)
{
    if (current_task && current_task->type == TASK_TYPE_PROCESS) {
        return current_task->process->ppid;
    }
    return 0;
}

int sys_getuid(void)
{
    /* Simple implementation - always return 0 (root) */
    return 0;
}

int sys_getgid(void)
{
    /* Simple implementation - always return 0 (root) */
    return 0;
}



int sys_print(const char* msg) {

    char *str = copy_string_from_user(msg);

    if(str) {
        kprintf("%s", msg);  // OK car validé
    }
    else {
        if(msg)
            KERROR("Invalid String frum userspace %s\n", msg);
        else
            KERROR("Invalid String from userspace: NULL message\n");
        return -1;
    }

    return 0;
}
