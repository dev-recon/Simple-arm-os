/* kernel/process/process.c */
#include <kernel/process.h>
#include <kernel/memory.h>
#include <kernel/kernel.h>
#include <kernel/vfs.h>
#include <kernel/syscalls.h>
#include <asm/arm.h>
#include <kernel/uart.h>
#include <kernel/kprintf.h>
#include <kernel/fat32.h>
#include <kernel/task.h>
#include <kernel/signal.h>
#include <kernel/timer.h>



/* Variables globales - reutilisant vos declarations */
extern task_t* current_task;      /* Defini dans votre task.c */
extern task_t* task_list_head;    /* Defini dans votre task.c */
extern uint32_t task_count;       /* Defini dans votre task.c */
extern spinlock_t task_lock; /* Defini dans votre task.c */
extern task_t* idle_task;         /* Defini dans votre task.c */
extern task_t* init_process;      /* Defini dans votre task.c */
extern void switch_to_idle_stack(void);

/**
 * Point d'entree principal du kernel - adapte a votre architecture
 */
void init_main(void)
{
    KINFO("=== UNIFIED KERNEL INITIALIZATION ===\n");
    
    /* Initialiser le systeme unifie process/task */
    init_process_system();
    
    /* Demarrer le scheduler avec votre fonction existante */
    KINFO("Starting scheduler with unified system...\n");
    print_signal_stack_stats();
    
    /* Lancer votre scheduler existant */
    sched_start(); 
    
    /* Ne devrait jamais arriver ici */
    panic("Returned from unified scheduler!");
}

/**
 * Initialiser le systeme unifie process/task
 */
void init_process_system(void)
{
    KINFO("Initializing unified process/task system...\n");

    /* Initialiser le gestionnaire de signal stacks */
    init_signal_stack_allocator();
    
    /* Initialiser d'abord votre systeme de taches de base existant */
    init_task_system();

    /* Creer le processus init (PID 1) */
    init_process = task_create_process("init", init_process_main, NULL, 10, TASK_TYPE_PROCESS);
    //init_process = create_process("init");
    if (!init_process) {
        panic("Failed to create init process");
    }
    
    /* Forcer PID 1 pour init */
    //init_process->process.pid = 1;
    //next_pid = 2;  /* Prochain PID sera 2 */
    
    //init_process->process.ppid = 0;
    //init_process->process.parent = NULL;
    //init_process->entry_point = init_process_main;
    //init_process->entry_arg = NULL;

    //init_process->context.sp = new_vm->stack_start;             /* Stack pointer */
    init_process->context.is_first_run = 1;                     /* Pas la premiere fois */
    //init_process->context.ttbr0 = (uint32_t)ttbr0_pgdir;
    //init_process->context.asid = ASID_KERNEL;
    init_process->context.returns_to_user = 0;

    //KDEBUG("[INIT] SCV STACK TOP = 0x%08X\n", init_process->context.svc_sp_top);
    //KDEBUG("[INIT] SCV STACK SP = 0x%08X\n", init_process->context.svc_sp);
     
    /* Configurer le contexte d'init avec votre fonction existante */
    //setup_task_context(init_process);

    extern void idle_task_func(void* arg);
    /* Creer la tache idle */
    //idle_task = task_create("idle", idle_task_func, NULL, 255); /* Priorite la plus basse */
    idle_task = task_create_process("idle", idle_task_func, NULL, 255, TASK_TYPE_KERNEL);
    if (!idle_task) {
        panic("Failed to create idle task");
    }

    idle_task->context.is_first_run = 1;                     /* Pas la premiere fois */
    idle_task->context.ttbr0 = (uint32_t)ttbr0_pgdir;
    idle_task->context.asid = ASID_KERNEL;
    idle_task->context.returns_to_user = 0;


    /* Mettre init dans la liste des taches pretes */
    add_to_ready_queue(init_process);
    add_to_ready_queue(idle_task);

    
    KINFO("Process system initialized successfully\n");
    KINFO("  - init process: PID=%u\n", init_process->process->pid);
    KINFO("  - Total tasks: %u\n", task_count);
}

/**
 * Fonction principale du processus init - adaptee a votre structure
 */
void init_process_main(void* arg)
{
    (void)arg;
    
    KINFO("=== INIT PROCESS (PID 1) STARTED ===\n");
    
    /* Initialiser les sous-systemes utilisateur */
    KINFO("[INIT] Initializing subsystems...\n");
    
    /* TODO: Initialiser VFS, drivers, etc. */
    
    KINFO("[INIT] Creating initial processes...\n");
    
    /* Creer le shell de demonstration */
    task_t* shell_proc  = task_create_process("shell", simple_shell_task, NULL, 10, TASK_TYPE_PROCESS);
    //init_process = create_process("init");
    if (!shell_proc) {
        panic("Failed to create init process");
    }

    shell_proc->context.is_first_run = 1;                    
    shell_proc->context.returns_to_user = 0;

    //KDEBUG("[SHELL PROC] SCV STACK TOP = 0x%08X\n", shell_proc->context.svc_sp_top);
    //KDEBUG("[SHELL PROC] SCV STACK SP = 0x%08X\n", shell_proc->context.svc_sp);

    add_to_ready_queue(shell_proc);
    
    KINFO("[INIT] System initialization complete\n");
    KINFO("[INIT] Init entering main reaper loop...\n");
    
    /* Boucle principale d'init : recolter les processus zombies */
    int reaped_count = 0;

    while (1) {
        /* Verifier les signaux */
        check_pending_signals();

        bool has_children = (init_process->process->children != NULL);
        
        if (has_children) {
            /* Attendre n'importe quel enfant */
            int status;
            pid_t child_pid = kernel_waitpid(-1, &status, 0, init_process);
            
            if (child_pid > 0) {
                reaped_count++;
                KINFO("[INIT] Reaped orphan child PID=%d (status=%d) [total=%d]\n", 
                      child_pid, status, reaped_count);
            } else if (child_pid == -ECHILD) {
                KDEBUG("[INIT] No children to reap anymore\n");
            }
        } else {
            /* PAS D'ENFANTS : Ne pas faire waitpid */
            //KDEBUG("[INIT] No children, sleeping...\n");
            task_sleep_ms(1000);  /* Dormir au lieu de waitpid */
        }
        
        /* Status periodique */
        static int status_counter = 0;
        if (++status_counter % 500 == 0) {
            KINFO("[INIT] Status: %d children reaped, system running\n", reaped_count);
            //list_all_processes();
        }
        
        /* Pause courte */
        task_sleep_ms(200);
        yield();
    }
}



/**
 * Creer un processus - CORRIGe
 */
task_t* create_process(const char* name)
{
    task_t* process;
    
    /* Creer la tache de base avec votre fonction existante */
    extern task_t* task_create_process(const char* name, void (*entry)(void* arg), 
                                  void* arg, uint32_t priority, task_type_t type);

    process = task_create_process(name, NULL, NULL, 10, TASK_TYPE_PROCESS);
    if (!process) {
        KERROR("create_process: NULL PROC\n");
        return NULL;
    }
    
    return process;
}

/**
 * Detruire un processus - CORRIGe
 */
void destroy_process(task_t* process)
{
    int i;
    
    if (!process || process->type != TASK_TYPE_PROCESS || !process->process) {
        KERROR("destroy_process: Invalid process\n");
        KERROR("destroy_process: NULL PROC\n");
        return;
    }
    
    //KDEBUG("destroy_process: Destroying process %s (PID=%u)\n", process->name, process->process->pid);
    
    /* Fermer tous les fichiers - ACCeS CORRECT */
    for (i = 0; i < MAX_FILES; i++) {
        if (process->process->files[i]) {
            close_file(process->process->files[i]); 
            process->process->files[i] = NULL;
        }
    }

     /* Nettoyer les signaux */
    cleanup_process_signals(process);
    
    /* Liberer l'espace memoire virtuel - ACCeS CORRECT */
    if (process->process->vm) {
        destroy_vm_space(process->process->vm);
        process->process->vm = NULL;
    }
    
    /* Utiliser votre fonction de destruction de tache existante */
    task_destroy(process);
}

/**
 * Trouver un processus par PID - CORRIGe
 */
task_t* find_process_by_pid(pid_t pid)
{
    task_t* task = task_list_head;
    int count = 0;
    
    if (!task_list_head) return NULL;
    
    spin_lock(&task_lock);
    
    do {
        /* ACCeS CORRECT via l'union */
        if (task->type == TASK_TYPE_PROCESS && task->process->pid == pid) {
            spin_unlock(&task_lock);
            return task;
        }
        task = task->next;
        count++;
    } while (task != task_list_head && count < MAX_TASKS);
    
    spin_unlock(&task_lock);
    return NULL;
}

/**
 * Obtenir la tache courante
 */
task_t* get_current_task(void)
{
    if (current_task) {
        return current_task;
    }
    KERROR("get_current_task: current task is NULL");
    return NULL;
}

/**
 * Obtenir le processus courant
 */
process_t* get_current_process(void)
{
    if (current_task && current_task->type == TASK_TYPE_PROCESS && current_task->process) {
        return current_task->process;
    }
    return NULL;
}



