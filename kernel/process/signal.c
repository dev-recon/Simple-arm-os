/* kernel/process/signal.c - COMPLET avec declarations forward */
#include <kernel/signal.h>
#include <kernel/process.h>
#include <kernel/memory.h>
#include <kernel/kernel.h>
#include <kernel/syscalls.h>
#include <kernel/uart.h>
#include <kernel/kprintf.h>

/* Configuration signal stack */
//#define DEFAULT_SIGNAL_STACK_SIZE   (16*1024)     /* 16KB par processus */
#define MIN_SIGNAL_STACK_SIZE       (8*1024)      /* 8KB minimum */
//#define MAX_SIGNAL_STACK_SIZE       (64*1024)     /* 64KB maximum */


/* Forward declarations de TOUTES les fonctions */
void wake_up_process_for_signal(task_t* proc);
signal_check_result_t deliver_signal(task_t* proc, int sig);
static int find_highest_priority_signal(uint32_t signal_mask);
static signal_check_result_t handle_default_signal_action(task_t* proc, int sig);
static bool setup_signal_handler(task_t* proc, int sig, sigaction_t* action);
static bool setup_signal_frame(task_t* proc, int sig, sigaction_t* action,
                               uint32_t signal_sp, uint32_t old_blocked);
static void terminate_process(task_t* proc, int sig);
static void dump_core(task_t* proc);
static void stop_process(task_t* proc);
static void continue_process(task_t* proc);

/* Actions par defaut pour chaque signal */
static sig_default_action_t default_signal_actions[MAX_SIGNALS] = {
    [0] = SIG_ACT_IGN,
    [SIGHUP] = SIG_ACT_TERM,
    [SIGINT] = SIG_ACT_TERM,
    [SIGQUIT] = SIG_ACT_CORE,
    [SIGILL] = SIG_ACT_CORE,
    [SIGTRAP] = SIG_ACT_CORE,
    [SIGABRT] = SIG_ACT_CORE,
    [SIGBUS] = SIG_ACT_CORE,
    [SIGFPE] = SIG_ACT_CORE,
    [SIGKILL] = SIG_ACT_TERM,
    [SIGUSR1] = SIG_ACT_TERM,
    [SIGSEGV] = SIG_ACT_CORE,
    [SIGUSR2] = SIG_ACT_TERM,
    [SIGPIPE] = SIG_ACT_TERM,
    [SIGALRM] = SIG_ACT_TERM,
    [SIGTERM] = SIG_ACT_TERM,
    [SIGCHLD] = SIG_ACT_IGN,
    [SIGCONT] = SIG_ACT_CONT,
    [SIGSTOP] = SIG_ACT_STOP,
    [SIGTSTP] = SIG_ACT_STOP,
};

extern void signal_return_trampoline(void);

typedef struct {
    uint32_t r[13];
    uint32_t sp;
    uint32_t lr;
    uint32_t pc;
    uint32_t cpsr;
    uint32_t old_blocked;
    uint32_t sig;
} user_signal_frame_t;

/* Gestionnaire global des signal stacks */
typedef struct {
    uint32_t next_base;                           /* Prochaine adresse disponible */
    uint32_t total_allocated;                     /* Total alloue */
    uint32_t max_processes;                       /* Nombre max de processus */
    bool initialized;                             /* Gestionnaire initialise */
} signal_stack_allocator_t;

static signal_stack_allocator_t sig_allocator = {0};

/**
 * Initialise le gestionnaire de signal stacks (a appeler au demarrage)
 */
void init_signal_stack_allocator(void)
{
    sig_allocator.next_base = USER_SIGNAL_REGION_START;
    sig_allocator.total_allocated = 0;
    sig_allocator.max_processes = USER_SIGNAL_REGION_SIZE / DEFAULT_SIGNAL_STACK_SIZE;
    sig_allocator.initialized = true;
    
    KINFO("[SIGNAL] Allocator initialized:\n");
    KINFO("[SIGNAL]   Region: 0x%08X - 0x%08X (%u MB)\n",
          USER_SIGNAL_REGION_START, USER_SIGNAL_REGION_END,
          USER_SIGNAL_REGION_SIZE / (1024*1024));
    KINFO("[SIGNAL]   Max processes: %u\n", sig_allocator.max_processes);
    KINFO("[SIGNAL]   Stack size per process: %u KB\n", 
          DEFAULT_SIGNAL_STACK_SIZE / 1024);
}

/**
 * Alloue une adresse de signal stack pour un processus
 */
static uint32_t allocate_signal_stack_address(uint32_t size)
{
    if (!sig_allocator.initialized) {
        KERROR("[SIGNAL] Allocator not initialized!\n");
        return 0;
    }
    
    /* Aligner la taille sur les pages */
    size = PAGE_ALIGN_UP(size);
    
    /* Verifier les limites */
    if (size < MIN_SIGNAL_STACK_SIZE || size > MAX_SIGNAL_STACK_SIZE) {
        KERROR("[SIGNAL] Invalid stack size: %u (min: %u, max: %u)\n",
               size, MIN_SIGNAL_STACK_SIZE, MAX_SIGNAL_STACK_SIZE);
        return 0;
    }

    /*
     * Chaque processus a son propre TTBR0: la meme adresse virtuelle peut donc
     * servir de signal stack pour tous les processus. L'ancien allocateur
     * monotone epuisait USER_SIGNAL_REGION_START..END apres beaucoup de fork/exec
     * alors que les piles des anciens processus etaient deja liberees.
     */
    if (USER_SIGNAL_REGION_START + size > USER_SIGNAL_REGION_END) {
        KERROR("[SIGNAL] Signal stack does not fit in reserved user region\n");
        return 0;
    }

    return USER_SIGNAL_REGION_START;
}

/**
 * Initialise les signaux pour un processus - CORRIGe
 */
void init_process_signals(task_t* proc)
{
    signal_state_t* sig;
    int i;
    
    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process) {
        KERROR("[SIGNAL] Invalid process\n");
        KERROR("[SIGNAL]: NULL PROC\n");
        return;
    }
    
    /* ACCeS CORRECT a la structure process via l'union */
    if (!proc->process->vm) {
        KERROR("[SIGNAL] No VM space\n");
        return;
    }
    
    sig = &proc->process->signals;
    
    /* Initialiser les handlers par defaut */
    for (i = 0; i < MAX_SIGNALS; i++) {
        sig->actions[i].sa_handler = SIG_DFL;
        sig->actions[i].sa_mask = 0;
        sig->actions[i].sa_flags = 0;
    }
    
    sig->pending = 0;
    sig->blocked = 0;
    sig->in_handler = 0;
    sig->return_override = 0;
    
    /* Allouer l'adresse de la signal stack - ACCeS CORRECT */
    proc->process->signal_stack_size = DEFAULT_SIGNAL_STACK_SIZE;
    proc->process->signal_stack_base = allocate_signal_stack_address(proc->process->signal_stack_size);
    
    if (proc->process->signal_stack_base == 0) {
        KERROR("[SIGNAL] Failed to allocate signal stack for process %u\n", 
               proc->process->pid);
        proc->process->signal_stack_size = 0;
        return;
    }
    
    /* Allouer et mapper les pages physiques */
    uint32_t pages_needed = (proc->process->signal_stack_size + PAGE_SIZE - 1) / PAGE_SIZE;
    //KDEBUG("[SIGNAL] Pages needed %u for signal stack\n",pages_needed);

    
    for (uint32_t i = 0; i < pages_needed; i++) {
        void* stack_page = allocate_page();
        if (!stack_page) {
            KERROR("[SIGNAL] Failed to allocate physical page %u\n", i);
            proc->process->signal_stack_base = 0;
            proc->process->signal_stack_size = 0;
            return;
        }

        //KDEBUG("[SIGNAL] Physical pages allocated at 0x%08X\n", (uint32_t)stack_page);

        uint32_t vaddr = proc->process->signal_stack_base + (i * PAGE_SIZE);

        uint32_t flags = VMA_READ | VMA_WRITE;

        //KDEBUG("SIGNAL FLAGS = 0x%04X at 0x%08X\n", proc->process->vm->vma_list->flags, flags);
        
        //proc->process->vm->vma_list->flags = flags ;

        //KDEBUG("SIGNAL NEW FLAGS = 0x%04X\n", proc->process->vm->vma_list->flags);


        if (map_user_page(proc->process->vm->pgdir, vaddr, (uint32_t)stack_page,
                          flags, proc->process->vm->asid) < 0) {
            free_page(stack_page);
            proc->process->signal_stack_base = 0;
            proc->process->signal_stack_size = 0;
            return;
        }
    }
    
    /* ACCeS CORRECT */
    //KINFO("[SIGNAL] Process %u signal stack: 0x%08X - 0x%08X (%u KB)\n",
    //      proc->process->pid,
    //      proc->process->signal_stack_base, 
    //      proc->process->signal_stack_base + proc->process->signal_stack_size,
    //      proc->process->signal_stack_size / 1024);
}


/**
 * Libere la signal stack d'un processus - CORRIGe
 */
void cleanup_process_signals(task_t* proc)
{
    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process )
    {
        KERROR("cleanup_process_signals: NULL PROC\n");
        return;
    }
    
    /* ACCeS CORRECT */
    if (proc->process->signal_stack_base == 0) return;
    
    uint32_t pages_to_free = (proc->process->signal_stack_size + PAGE_SIZE - 1) / PAGE_SIZE;
    
    for (uint32_t i = 0; i < pages_to_free; i++) {
        uint32_t vaddr = proc->process->signal_stack_base + (i * PAGE_SIZE);
        
        uint32_t phys_addr = get_physical_address(proc->process->vm->pgdir, vaddr);
        if (phys_addr != 0) {
            //map_user_page(proc->process->vm->pgdir, vaddr, 0,proc->process->vm->vma_list->flags,proc->process->vm->asid);
            free_page((void*)phys_addr);
        }
    }
    
    /* ACCeS CORRECT */
    //KDEBUG("[SIGNAL] Freed signal stack for process %u\n", proc->process->pid);
    
    proc->process->signal_stack_base = 0;
    proc->process->signal_stack_size = 0;
}

/**
 * Statistiques du gestionnaire de signal stacks (utilitaire de debug)
 */
void print_signal_stack_stats(void)
{
    if (!sig_allocator.initialized) {
        KINFO("[SIGNAL] Allocator not initialized\n");
        return;
    }
    
    uint32_t used_stacks = sig_allocator.total_allocated / DEFAULT_SIGNAL_STACK_SIZE;
    uint32_t available_stacks = sig_allocator.max_processes - used_stacks;
    uint32_t used_mb = sig_allocator.total_allocated / (1024*1024);
    uint32_t available_mb = (USER_SIGNAL_REGION_SIZE - sig_allocator.total_allocated) / (1024*1024);
    
    KINFO("[SIGNAL] Signal Stack Statistics:\n");
    KINFO("[SIGNAL]   Used stacks:      %u / %u\n", used_stacks, sig_allocator.max_processes);
    KINFO("[SIGNAL]   Available stacks: %u\n", available_stacks);
    KINFO("[SIGNAL]   Used memory:      %u MB\n", used_mb);
    KINFO("[SIGNAL]   Available memory: %u MB\n", available_mb);
    KINFO("[SIGNAL]   Next allocation:  0x%08X\n", sig_allocator.next_base);
}


int send_signal(task_t* target, int sig)
{
    if (sig <= 0 || sig >= MAX_SIGNALS) return -1;
    if (!target || target->type != TASK_TYPE_PROCESS || target->state == TASK_TERMINATED) return -1;
    
    //KDEBUG("[SIGNAL] Sending signal %d to process PID=%u\n", sig, target->process->pid);
    
    /* SIGKILL et SIGSTOP ne peuvent pas etre bloques */
    if (sig == SIGKILL || sig == SIGSTOP) {
        target->process->signals.pending |= (1 << sig);
        wake_up_process_for_signal(target);
        return 0;
    }
    
    /* Verifier si le signal est bloque */
    if (target->process->signals.blocked & (1 << sig)) {
        target->process->signals.pending |= (1 << sig);
        KDEBUG("[SIGNAL] Signal %d blocked, added to pending for PID=%u\n", sig, target->process->pid);
        return 0;
    }
    
    /* Signal non bloque */
    target->process->signals.pending |= (1 << sig);
    wake_up_process_for_signal(target);
    
    //KDEBUG("[SIGNAL] Signal %d delivered to PID=%u\n", sig, target->process->pid);
    return 0;
}

/*
 * Reveiller un processus pour traiter un signal - CORRIGe
 */
void wake_up_process_for_signal(task_t* proc)
{
    //KDEBUG("wake_up_process_for_signal: %s - PID %d\n", proc->name, proc->process->pid);
    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process) {
        KERROR("wake_up_process_for_signal: NULL PROC\n");
        return;
    }
    
    if (proc->state == TASK_BLOCKED) {
        KDEBUG("[SIGNAL] Waking up blocked process PID=%u for signal\n", proc->process->pid);
        proc->state = TASK_READY;
        add_to_ready_queue(proc);
    } else if (proc->state == TASK_INTERRUPTIBLE) {
        proc->state = TASK_READY;
        proc->wakeup_time = 0;
    }
    //KDEBUG("wake_up_process_for_signal: state %s\n", task_state_string(proc->state));
}


/**
 * Verifier si un processus a des signaux en attente - CORRIGe
 */
bool has_pending_signals(task_t* proc)
{
    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process){
        KERROR("has_pending_signals: NULL PROC\n");
         return false;
    }
    
    /* ACCeS CORRECT */
    return (proc->process->signals.pending & ~proc->process->signals.blocked) != 0;
}



/**
 * Delivrer un signal a un processus - CORRIGe
 */
signal_check_result_t deliver_signal(task_t* proc, int sig)
{
    signal_state_t* sig_state;
    sigaction_t* action;
    
    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process){
        KERROR("deliver_signal: NULL PROC\n");
        return SIGNAL_CHECK_DEFERRED;
    }

    sig_state = &proc->process->signals;
    action = &sig_state->actions[sig];
    
    //KDEBUG("[SIGNAL] Delivering signal %d to process PID=%u\n", sig, proc->process->pid);
    
    /* Verifier si le signal est ignore */
    if (action->sa_handler == SIG_IGN) {
        KDEBUG("[SIGNAL] Signal %d ignored by PID=%u\n", sig, proc->process->pid);
        return SIGNAL_CHECK_IGNORED;
    }
    
    if (action->sa_handler == SIG_DFL) {
        /* Action par defaut */
        //KDEBUG("[SIGNAL] Proc %s Using default action for signal %d\n", proc->name, sig);
        return handle_default_signal_action(proc, sig);
    }
    
    /* Handler utilisateur */
    //KDEBUG("[SIGNAL] Calling user handler 0x%08X for signal %d\n", 
    //       (uint32_t)action->sa_handler, sig);
    if (!setup_signal_handler(proc, sig, action)) {
        sig_state->pending |= (1u << sig);
        return SIGNAL_CHECK_DEFERRED;
    }

    return SIGNAL_CHECK_USER_FRAME;
}

/**
 * Gerer l'action par defaut d'un signal - CORRIGe
 */
static signal_check_result_t handle_default_signal_action(task_t* proc, int sig)
{
    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process) {
        KERROR("handle_default_signal_action: NULL PROC\n");
        return SIGNAL_CHECK_DEFERRED;
    }
     
    //KDEBUG("[SIGNAL] Default action for signal %d: %d\n", sig, default_signal_actions[sig]);
    
    switch (default_signal_actions[sig]) {
        case SIG_ACT_TERM:
            terminate_process(proc, sig);
            return SIGNAL_CHECK_EXITED;
            
        case SIG_ACT_CORE:
            dump_core(proc);
            terminate_process(proc, sig);
            return SIGNAL_CHECK_EXITED;
            
        case SIG_ACT_STOP:
            stop_process(proc);
            return SIGNAL_CHECK_STOPPED;
            
        case SIG_ACT_CONT:
            continue_process(proc);
            return SIGNAL_CHECK_NONE;
            
        case SIG_ACT_IGN:
            /* Ne rien faire */
            KDEBUG("[SIGNAL] Signal %d ignored by default\n", sig);
            return SIGNAL_CHECK_IGNORED;
    }

    return SIGNAL_CHECK_NONE;
}

/**
 * Configurer un handler de signal utilisateur - CORRIGe
 */
static bool setup_signal_handler(task_t* proc, int sig, sigaction_t* action)
{
    signal_state_t* sig_state;
    uint32_t old_blocked;
    uint32_t signal_sp;
    
    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process)  {
        KERROR("setup_signal_handler: NULL PROC\n");
         return false;
    }
    
    sig_state = &proc->process->signals;
    
    old_blocked = sig_state->blocked;
    signal_sp = proc->process->signal_stack_base + proc->process->signal_stack_size - 16;

    if (!setup_signal_frame(proc, sig, action, signal_sp, old_blocked)) {
        return false;
    }

    sig_state->in_handler |= (1u << sig);
    sig_state->blocked |= action->sa_mask;
    if (!(action->sa_flags & SA_NODEFER)) {
        sig_state->blocked |= (1u << sig);
    }
    if (action->sa_flags & SA_RESETHAND) {
        action->sa_handler = SIG_DFL;
    }
    sig_state->return_override = 1;
    return true;
}

/**
 * Configurer la frame signal sur la pile - CORRIGe
 */
static bool setup_signal_frame(task_t* proc, int sig, sigaction_t* action,
                               uint32_t signal_sp, uint32_t old_blocked)
{
    user_signal_frame_t frame;
    uint32_t final_sp;
    
    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process)  {
        KERROR("setup_signal_frame: NULL PROC\n");
        return false;
    }

    if (!action->sa_restorer) {
        KERROR("[SIGNAL] No user restorer for signal %d\n", sig);
        return false;
    }

    final_sp = (signal_sp - sizeof(frame)) & ~7u;
    if (final_sp < proc->process->signal_stack_base) {
        KERROR("[SIGNAL] Signal frame does not fit on signal stack\n");
        return false;
    }

    memcpy(frame.r, proc->context.usr_r, sizeof(frame.r));
    frame.sp = proc->context.usr_sp;
    frame.lr = proc->context.usr_lr;
    frame.pc = proc->context.usr_pc;
    frame.cpsr = proc->context.usr_cpsr;
    frame.old_blocked = old_blocked;
    frame.sig = (uint32_t)sig;

    if (copy_to_user((void *)final_sp, &frame, sizeof(frame)) < 0) {
        KERROR("[SIGNAL] Failed to copy signal frame to user stack\n");
        return false;
    }

    proc->context.usr_r[0] = (uint32_t)sig;
    proc->context.usr_sp = final_sp;
    proc->context.usr_lr = (uint32_t)action->sa_restorer;
    proc->context.usr_pc = (uint32_t)action->sa_handler;
    proc->context.usr_cpsr = (frame.cpsr & ~0x1fu) | 0x10u;
    proc->context.returns_to_user = 1;
    return true;
}

/**
 * Syscall kill - CORRIGe
 */
int sys_kill(pid_t pid, int sig)
{
    task_t* target;
    int delivered = 0;
    
    if (sig < 0 || sig >= MAX_SIGNALS) return -EINVAL;
    
    //KDEBUG("[SYSCALL] sys_kill: pid=%d, sig=%d\n", pid, sig);
    
    if (pid > 0) {
        target = find_process_by_pid(pid);
        if (!target) {
            KDEBUG("[SYSCALL] sys_kill: Process PID=%d not found\n", pid);
            return -ESRCH;
        }
        
        /* TODO: Verifier les permissions (uid, gid) */
        return send_signal(target, sig);
        
    } else if (pid == 0) {
        pid_t pgid;

        if (!current_task || current_task->type != TASK_TYPE_PROCESS || !current_task->process)
            return -EINVAL;

        pgid = current_task->process->pgid;
        target = task_list_head;
        if (!target) return -ESRCH;

        do {
            if (target->type == TASK_TYPE_PROCESS && target->process &&
                target->process->pgid == pgid &&
                target->state != TASK_ZOMBIE &&
                target->state != TASK_TERMINATED) {
                if (send_signal(target, sig) == 0)
                    delivered++;
            }
            target = target->next;
        } while (target && target != task_list_head);

        return delivered ? 0 : -ESRCH;
        
    } else {
        pid_t pgid = -pid;

        target = task_list_head;
        if (!target) return -ESRCH;

        do {
            if (target->type == TASK_TYPE_PROCESS && target->process &&
                target->process->pgid == pgid &&
                target->state != TASK_ZOMBIE &&
                target->state != TASK_TERMINATED) {
                if (send_signal(target, sig) == 0)
                    delivered++;
            }
            target = target->next;
        } while (target && target != task_list_head);

        return delivered ? 0 : -ESRCH;
    }
}

/**
 * Syscall signal - CORRIGe
 */
int sys_signal(int sig, sig_handler_t handler)
{
    signal_state_t* sig_state;
    sig_handler_t old_handler;
    
    if (sig <= 0 || sig >= MAX_SIGNALS) return -EINVAL;
    if (sig == SIGKILL || sig == SIGSTOP) return -EINVAL;
    
    if (!current_task || current_task->type != TASK_TYPE_PROCESS) {
        return -EINVAL;
    }
    
    sig_state = &current_task->process->signals;
    old_handler = sig_state->actions[sig].sa_handler;
    
    sig_state->actions[sig].sa_handler = handler;
    sig_state->actions[sig].sa_mask = 0;
    sig_state->actions[sig].sa_flags = SA_RESTART;
    
    //KDEBUG("[SYSCALL] sys_signal: sig=%d, handler=0x%08X, old=0x%08X\n", 
    //       sig, (uint32_t)handler, (uint32_t)old_handler);
    
    return (int)old_handler;
}

/**
 * Syscall sigaction - CORRIGe
 */
int sys_sigaction(int sig, const sigaction_t* act, sigaction_t* oldact)
{
    signal_state_t* sig_state;
    sigaction_t new_action;
    
    if (sig <= 0 || sig >= MAX_SIGNALS) return -EINVAL;
    if (sig == SIGKILL || sig == SIGSTOP) return -EINVAL;
    
    if (!current_task || current_task->type != TASK_TYPE_PROCESS) {
        return -EINVAL;
    }
    
    sig_state = &current_task->process->signals;
    
    /* Sauvegarder l'ancienne action */
    if (oldact) {
        if (copy_to_user(oldact, &sig_state->actions[sig], sizeof(sigaction_t)) < 0) {
            return -EFAULT;
        }
    }
    
    /* Installer la nouvelle action */
    if (act) {
        if (copy_from_user(&new_action, act, sizeof(sigaction_t)) < 0) {
            return -EFAULT;
        }
        
        sig_state->actions[sig] = new_action;
        
        //KDEBUG("[SYSCALL] sys_sigaction: sig=%d, handler=0x%08X, mask=0x%08X, flags=0x%08X\n", 
        //       sig, (uint32_t)new_action.sa_handler, new_action.sa_mask, new_action.sa_flags);
    }
    
    return 0;
}

/**
 * Syscall sigreturn - CORRIGe
 */
void sys_sigreturn(void)
{
    task_t* proc = current_task;
    signal_state_t* sig_state;
    user_signal_frame_t frame;
    
    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process) {
        KERROR("[SIGNAL] sys_sigreturn: Invalid process\n");
        return;
    }
    
    sig_state = &proc->process->signals;

    if (copy_from_user(&frame, (void *)proc->context.usr_sp, sizeof(frame)) < 0) {
        KERROR("[SIGNAL] sys_sigreturn: Invalid signal frame\n");
        return;
    }

    memcpy(proc->context.usr_r, frame.r, sizeof(frame.r));
    proc->context.usr_sp = frame.sp;
    proc->context.usr_lr = frame.lr;
    proc->context.usr_pc = frame.pc;
    proc->context.usr_cpsr = (frame.cpsr & ~0x1fu) | 0x10u;
    proc->context.returns_to_user = 1;

    sig_state->blocked = frame.old_blocked;
    sig_state->in_handler &= ~(1u << frame.sig);
    sig_state->return_override = 1;
}

/**
 * Verifier les signaux en attente - CORRIGe
 */
signal_check_result_t check_pending_signals(void)
{
    task_t* proc = current_task;
    signal_state_t* sig;
    uint32_t deliverable;
    int signal_num;
    
    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process)
        return SIGNAL_CHECK_NONE;

    //KDEBUG("[SIGNAL] entered check_pending_signals PID=%u - TTBR0 = 0x%08X\n", proc->process->pid, (uint32_t)proc->process->vm->pgdir);

    if( proc->state == TASK_UNINTERRUPTIBLE ){
        //KDEBUG("[SIGNAL] process in TASK_UNINTERRUPTIBLE PID=%u - skipping\n", proc->process->pid);
        return SIGNAL_CHECK_DEFERRED;
    }
    
    sig = &proc->process->signals;

    /* Une seule frame est supportee pour l'instant: pas de signal imbrique. */
    if (sig->in_handler != 0) return SIGNAL_CHECK_DEFERRED;
    
    /* Trouver les signaux delivrables */
    deliverable = sig->pending & ~sig->blocked;
    if (!deliverable) return SIGNAL_CHECK_NONE;

    //KDEBUG("[SIGNAL] Deliverable signals found %u PID=%u\n", deliverable, proc->process->pid);

    /* Trouver le signal de plus haute priorite */
    signal_num = find_highest_priority_signal(deliverable);
    if (signal_num == 0) return SIGNAL_CHECK_NONE;
    
     //KDEBUG("[SIGNAL] find_highest_priority_signal found %d PID=%u\n", signal_num, proc->process->pid);

    /* Effacer le bit pending */
    sig->pending &= ~(1 << signal_num);
    
    //KDEBUG("[SIGNAL] Processing pending signal %d for PID=%u\n", 
    //       signal_num, proc->process->pid);
    
    return deliver_signal(proc, signal_num);
}

int signal_consume_user_return_override(void)
{
    task_t* proc = current_task;

    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process) {
        return 0;
    }
    if (!proc->process->signals.return_override) {
        return 0;
    }

    proc->process->signals.return_override = 0;
    return 1;
}

/**
 * Trouver le signal de plus haute priorite
 */
static int find_highest_priority_signal(uint32_t signal_mask)
{
    int i;
    
    /* SIGKILL et SIGSTOP ont la plus haute priorite */
    if (signal_mask & (1 << SIGKILL)) return SIGKILL;
    if (signal_mask & (1 << SIGSTOP)) return SIGSTOP;
    
    /* Autres signaux par ordre numerique */
    for (i = 1; i < MAX_SIGNALS; i++) {
        if (signal_mask & (1 << i)) return i;
    }
    return 0;
}


/* ========================================================================= */
/* Fonctions helper - CORRIGeES */
/* ========================================================================= */

/**
 * Terminer un processus - CORRIGe
 */
static void terminate_process(task_t* proc, int sig)
{
    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process) return;
    
    //KINFO("[SIGNAL] Terminating process PID=%u with signal %d\n", proc->process->pid, sig);
    
    proc->process->exit_code = sig;
    sys_exit(sig);  /* Utiliser la version corrigee */
}

/**
 * Dumper le core - CORRIGe
 */
static void dump_core(task_t* proc)
{
    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process) return;
    
    KINFO("[SIGNAL] Core dump for process PID=%u (not implemented)\n", proc->process->pid);
    /* TODO: Implementer le core dump reel */
}

/**
 * Arreter un processus - CORRIGe
 */
static void stop_process(task_t* proc)
{
    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process) return;
    
    KINFO("[SIGNAL] Stopping process PID=%u\n", proc->process->pid);
    proc->state = TASK_BLOCKED;
    proc->process->state = (proc_state_t)PROC_BLOCKED;
}

/**
 * Continuer un processus - CORRIGe
 */
static void continue_process(task_t* proc)
{
    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process) return;
    
    KINFO("[SIGNAL] Continuing process PID=%u\n", proc->process->pid);
    
    if (proc->state == TASK_BLOCKED) {
        proc->state = TASK_READY;
        proc->process->state = (proc_state_t)PROC_READY;
        add_to_ready_queue(proc);
    }
}
