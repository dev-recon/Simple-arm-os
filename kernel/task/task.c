/* kernel/task/task.c - Version de base simple */
#include <kernel/task.h>
#include <kernel/memory.h>
#include <kernel/kernel.h>
#include <kernel/kprintf.h>
#include <kernel/string.h>
#include <kernel/uart.h>
#include <kernel/syscalls.h>
#include <kernel/signal.h>
#include <kernel/timer.h>
#include <kernel/process.h>


//const uint32_t TASK_CONTEXT_OFF = offsetof(task_t, context);

/* Variables globales du scheduler */
task_t* current_task = NULL;
task_t* task_list_head = NULL;
static uint32_t next_task_id = 1;
static uint32_t next_pid = 1;
uint32_t task_count = 0;
static bool scheduler_initialized = false;
DEFINE_SPINLOCK(task_lock);

//static spinlock_t task_lock = {0};

/* Tache idle et processus init */
task_t* idle_task = NULL;
task_t* init_process = NULL;
//static int yield_count = 0;

/* === NOUVELLES VARIABLES POUR PROCESSUS === */
//task_t* current_process = NULL;  /* Alias vers current_task */

/* Forward declarations */
void idle_task_func(void* arg);
void init_process_main(void* arg);
static task_t* schedule_next_task(void);
void add_task_to_list(task_t* task);
static void remove_task_from_list(task_t* task);
void setup_task_context(task_t* task);
static task_t* schedule_next_task2(void);
bool is_in_ready_queue(task_t* task);

void debug_context_switch_entry(void);
void debug_context_switch_middle(void);
void debug_context_switch_first_exec(void);
void debug_context_switch_restore(void);
void debug_null_old_ctx(void);
void debug_null_new_ctx(void);
void debug_context_registers(task_context_t* ctx, const char* moment);
void debug_task_detailed(task_t *current_task);

void debug_print_ctx(task_context_t *context);
void debug_return_snapshot(task_context_t *ctx, uint32_t spsr, uint32_t usr_pc, uint32_t tracer);


/* Fonctions assembleur externes */
extern void __task_first_switch_v2(task_context_t* new_ctx);
extern void __task_switch_asm_debug(task_context_t* old_ctx, task_context_t* new_ctx);
extern void __task_switch(task_context_t* old_ctx, task_context_t* new_ctx);
extern void print_system_stats(void);


// Prototypes utiles
static inline void *kstack_alloc(size_t sz) { void *p = kmalloc(sz); memset(p, 0, sz); return p; }

// Construit une pile noyau "propre" pour un PROCESS (utile pour from_user=true)
static void build_clean_kernel_stack(task_t *t)
{
    if(!t->stack_base)
        t->stack_base = kstack_alloc(KERNEL_TASK_STACK_SIZE);
    t->stack_size = KERNEL_TASK_STACK_SIZE;
    t->stack_top  = (uint8_t*)t->stack_base + t->stack_size;

    // SP noyau posé près du top (garde 512B pour sentinelles/debug si tu veux)
    t->context.svc_sp_top = (uint32_t)t->stack_top;
    t->context.svc_sp     = ((uint32_t)t->stack_top - 512) & ~7u;
    t->context.sp         = t->context.svc_sp;  // sp = SP_svc dans ton design
}


task_t* set_process_stack(task_t* parent, task_t* child, bool from_user)
{
        /* Allouer une nouvelle pile */
    child->stack_base = kmalloc(KERNEL_TASK_STACK_SIZE);
    if (!child->stack_base) {
        KERROR("task_create_copy: Failed to allocate child stack\n");
        //kfree(child);
        return NULL;
    }
    
    child->stack_size = KERNEL_TASK_STACK_SIZE;
    child->stack_top = (uint8_t*)child->stack_base + KERNEL_TASK_STACK_SIZE;
    memset(child->stack_base, 0, KERNEL_TASK_STACK_SIZE);

    //bool parent_is_user_process = (parent->context.sp < 0x40000000);  /* Espace user */
    //bool parent_is_user_process = false;  /* FIX IT Espace user */

    //KDEBUG("task_create_copy: parent_is_user_process=%s\n", 
    //   from_user ? "YES" : "NO");
    //KDEBUG("  Parent SP: 0x%08X\n", parent->context.sp);
    //KDEBUG("  Parent Stack Base: 0x%08X\n", parent->stack_base);
    //KDEBUG("  Parent Stack Top : 0x%08X\n", parent->stack_top);


    if (from_user) {
        /* Pour les processus utilisateur, ne pas copier la stack kernel */
        /* Créer une stack kernel propre pour l'enfant */
        
        //KDEBUG("Creating clean kernel stack for user process child\n");
        
        /* Stack kernel propre */
        //memset(child->stack_base, 0, KERNEL_TASK_STACK_SIZE);
        //child->context.sp = (uint32_t)child->stack_top - 512;

        build_clean_kernel_stack(child);

        // Marqueur pour le scheduler/retour en user
        child->context.returns_to_user = 1;
        
        /* IMPORTANT : Copier l'espace mémoire utilisateur séparément */
        /* Ceci sera fait dans la partie VM space copy */
        
        //KDEBUG("  Child kernel stack: %p - %p\n", 
        //    child->stack_base, child->stack_top);
        //KDEBUG("  Child kernel SP: 0x%08X\n", child->context.sp);
    
    } else {
        /*  COPIE DE PILE AVEC AJUSTEMENT SP */
        if (parent->stack_base && parent->stack_size > 0) {
            /*  Calculer l'offset DEPUIS LE HAUT de la pile parent */
            uint32_t parent_stack_top = (uint32_t)parent->stack_base + parent->stack_size;
            uint32_t parent_sp_offset_from_top = parent_stack_top - parent->context.sp;
            
            KDEBUG("Parent stack analysis:\n");
            KDEBUG("  Parent stack: %p - %p\n", parent->stack_base, (uint8_t*)parent->stack_base + parent->stack_size);
            KDEBUG("  Parent SP: 0x%08X\n", parent->context.sp);
            KDEBUG("  Offset from top: %u bytes\n", parent_sp_offset_from_top);
            
            /* Verifier que le SP parent est valide AVANT de copier */
            if (parent->context.sp < (uint32_t)parent->stack_base || 
                parent->context.sp >= parent_stack_top) {
                KERROR("task_create_copy: Parent SP invalid! Cannot copy stack\n");
                KERROR("  Parent SP: 0x%08X, Range: %p - 0x%08X\n", 
                    parent->context.sp, parent->stack_base, parent_stack_top);
                
                /* Utiliser pile propre au lieu d'echouer */
                memset(child->stack_base, 0, KERNEL_TASK_STACK_SIZE);
                child->context.sp = (uint32_t)child->stack_top - 512;
            } else {
                /*  Copier le contenu de la pile */
                memcpy(child->stack_base, parent->stack_base, KERNEL_TASK_STACK_SIZE);
                
                /*  Calculer le nouveau SP avec le MeME offset depuis le haut */
                child->context.sp = (uint32_t)child->stack_top - parent_sp_offset_from_top;

                /* NOUVEAU : Corriger les adresses dans le contenu copié */
                uint32_t parent_stack_base = (uint32_t)parent->stack_base;
                uint32_t child_stack_base = (uint32_t)child->stack_base;
                uint32_t stack_offset = child_stack_base - parent_stack_base;

                //KDEBUG("Fixing stack addresses: offset=%d bytes\n", stack_offset);
            
                /* Parcourir la pile et corriger les pointeurs vers pile parent */
                uint32_t* stack_words = (uint32_t*)child->stack_base;
                uint32_t stack_size_words = KERNEL_TASK_STACK_SIZE / sizeof(uint32_t);
                uint32_t corrections = 0;
                
                for (uint32_t i = 0; i < stack_size_words; i++) {
                    uint32_t value = stack_words[i];
                    
                    /* Si cette valeur pointe dans la pile du parent, la corriger */
                    if (value >= parent_stack_base && value < parent_stack_top) {
                        uint32_t new_value = value + stack_offset;
                        stack_words[i] = new_value;
                        corrections++;
                        
                        if (corrections <= 5) {  /* Limiter les logs */
                            //KDEBUG("  Fix [+%u]: 0x%08X -> 0x%08X\n", 
                            //    i * 4, value, new_value);
                        }
                    }
                }

                KDEBUG("Stack address corrections: %u pointers fixed\n", corrections);
                
                KDEBUG("Child stack analysis:\n");
                KDEBUG("  Child stack: %p - %p\n", child->stack_base, child->stack_top);
                KDEBUG("  Child SP: 0x%08X\n", child->context.sp);
                KDEBUG("  Copied stack with SP offset %u from top\n", parent_sp_offset_from_top);
            }
        } else {
            /* Pile propre si parent invalide */
            KWARN("Parent has no valid stack, creating clean stack\n");
            memset(child->stack_base, 0, KERNEL_TASK_STACK_SIZE);
            child->context.sp = (uint32_t)child->stack_top - 512;
        }

        child->context.sp &= ~7; 
        child->context.svc_sp_top = (uint32_t)child->stack_top;
        child->context.svc_sp     = child->context.sp;
        // Ce child reprendra en SVC (kthread), pas de retour user implicite
        child->context.returns_to_user = 0;
    }
    
    /*  Alignement final */
    child->context.sp &= ~7;  /* Alignement 8-bytes */
    child->context.svc_sp &= ~7u;

    return child;

}

/**
 * Creer une copie d'une tache pour fork()
 */
task_t* task_create_copy(task_t* parent, bool from_user)
{
    task_t* child;
    char *child_name = NULL;
    
    if (!parent || !parent->process) {
        KERROR("task_create_copy: parent NULL\n");
        KERROR("task_create_copy: Parent NULL Proc\n");
        return NULL;
    }
    
    /* Allouer la structure de tache */
    child = (task_t*)kmalloc(sizeof(task_t));
    if (!child) {
        KERROR("task_create_copy: Failed to allocate child task\n");
        return NULL;
    }

    /* Copier la structure parent */
    memcpy(child, parent, sizeof(task_t));

    child_name = (char *)kmalloc(TASK_NAME_MAX);
    if(!child_name){
        KERROR("task_create_copy: Failed to allocate child name\n");
        return NULL;
    }

    /* Generer un nom pour l'enfant */
    snprintf(child_name, TASK_NAME_MAX, "%s-child", parent->name);
    
    /* Reinitialiser les champs specifiques a l'enfant */
    child->task_id = next_task_id++;
    strncpy(child->name, child_name, TASK_NAME_MAX - 1);
    child->name[TASK_NAME_MAX - 1] = '\0';
    
    if(!set_process_stack(parent,child, from_user))
        return NULL;

    //KDEBUG("CHILD SP = 0x%08X\n", child->context.sp);
    //KDEBUG("CHILD Stack Base = 0x%08X\n", child->stack_base);
    //KDEBUG("CHILD Stack Top = 0x%08X\n", child->stack_top);
        
    //KDEBUG("CHILD Stack Top = 0x%08X\n", child->stack_top);

    /* Copier le contenu de la pile parent */
    //memcpy(child->stack_base, parent->stack_base, KERNEL_TASK_STACK_SIZE);
    

    /* Stack configuration corrigee */
    //uint32_t stack_top = (uint32_t)child->stack_top;
    //uint32_t stack_reserve = 512; /*512 avant*/
    //child->context.sp = stack_top - stack_reserve;
    //child->context.sp &= ~7;  /* Alignement 8-bytes */

        //  VeRIFICATION IMMeDIATE
    //if (child->context.sp < (uint32_t)child->stack_base || 
    //    child->context.sp >= (uint32_t)child->stack_top) {
    //    KERROR("task_create_copy: Child SP calculation failed!\n");
    //    KERROR("  Child: %s\n", child->name);
    //    KERROR("  Stack: %p - %p (%u bytes)\n", 
    //           child->stack_base, child->stack_top, child->stack_size);
    //    KERROR("  SP: 0x%08X (invalid!)\n", child->context.sp);
        
        /* Correction d'urgence */
    //   child->context.sp = (uint32_t)child->stack_top - 512;
    //    child->context.sp &= ~7;
        
    //    KWARN("Emergency SP correction: 0x%08X\n", child->context.sp);
    //}

    //uint32_t sp_offset = parent->context.sp - (uint32_t)parent->stack_base;
    //child->context.sp = (uint32_t)child->stack_base + sp_offset;

    
    /* Configuration processus pour l'enfant */
    if (parent->type == TASK_TYPE_PROCESS) {

        child->process = (process_t *)kmalloc(sizeof(process_t));
        if(child->process){
            child->type = TASK_TYPE_PROCESS;
            child->process->pid = next_pid++;
            child->process->ppid = parent->process->pid;
            child->process->parent = parent;
            child->process->children = NULL;
            child->process->sibling_next = NULL;
            child->process->exit_code = 0;
            child->process->uid = parent->process->uid;
            child->process->gid = parent->process->gid;
            
            /* Initialiser la table des fichiers (sera copiee plus tard) */
            memset(child->process->files, 0, sizeof(child->process->files));
            
            /* La VM sera copiee avec COW dans sys_fork() */
            child->process->vm = NULL;
        }
        else panic("Task Create Copy - cannot allocate Process Structure");
    } else {
        /* Pour les threads kernel, garder le meme type */
        child->type = parent->type;
    }
    
    /* etat initial */
    child->state = TASK_READY;
    child->next = NULL;
    child->prev = NULL;
    
    /* Statistiques */
    child->created_time = get_system_ticks();
    child->total_runtime = 0;
    child->switch_count = 0;
    child->context.is_first_run = 1;
    child->context.r0 = 0;
    // Initialiser le reste à zéro
    //memset(&child->context.r0, 0, sizeof(uint32_t) * 13);  // r0-r12 = 0
    
    //KDEBUG("task_create_copy: Created child task %s (ID=%u, PID=%u) - PC=%p - LR=%p\n", 
    //       child->name, child->task_id, 
    //       (child->type == TASK_TYPE_PROCESS) ? child->process->pid : 0, child->context.pc, child->context.lr);
    

    return child;
}



/* Ajout des fonctions de gestion des interruptions ARM */
static inline uint32_t disable_interrupts_save(void)
{
    uint32_t cpsr;
    __asm__ volatile(
        "mrs %0, cpsr\n"      /* Lire CPSR actuel */
        "cpsid if"            /* Desactiver IRQ et FIQ */
        : "=r" (cpsr)
        :
        : "memory"
    );
    return cpsr;
}

static inline void restore_interrupts(uint32_t cpsr)
{
    __asm__ volatile(
        "msr cpsr_c, %0"      /* Restaurer seulement les bits de controle */
        :
        : "r" (cpsr)
        : "memory"
    );
}

void validate_task_list(const char* location)
{
    task_t* task = task_list_head;
    int count = 0;
    
    KDEBUG("=== TASK LIST VALIDATION [%s] ===\n", location);
    
    if (!task_list_head) {
        KDEBUG("Empty task list\n");
        return;
    }
    
    do {
        KDEBUG("Task %d: %s (next=%p, prev=%p)\n", 
               count, task->name, task->next, task->prev);
        
        // Verifications de base
        if (!task->next) {
            KERROR("KO Task %s has NULL next pointer!\n", task->name);
            break;
        }
        
        if (count > 0 && task->next->prev != task) {
            KERROR("KO Task list integrity broken at %s!\n", task->name);
            break;
        }
        
        task = task->next;
        count++;
        
        if (count > MAX_TASKS) {
            KERROR("KO Task list loop detected!\n");
            break;
        }
        
    } while (task != task_list_head);
    
    KDEBUG("Task list OK: %d tasks\n", count);
}


void switch_to_idle_stack(void)
{
    if (!idle_task) {
        panic("No idle task for stack switch");
    }
    
    //KINFO("Switching to idle stack...\n");
    
    uint32_t current_sp;
    __asm__ volatile("mov %0, sp" : "=r"(current_sp));
    //KINFO("Current SP (kernel): 0x%08X\n", current_sp);
    //KINFO("Target SP (idle): 0x%08X\n", idle_task->context.sp);
    
    /* Copier quelques données importantes sur la nouvelle pile */
    uint32_t new_sp = idle_task->context.sp;
    
    /* Réserver de l'espace sur la pile idle pour les variables locales */
    new_sp -= 64;  /* 64 bytes de marge */
    new_sp &= ~7;  /* Alignement 8-bytes */
    
    /* CRITIQUE: Switcher vers la pile idle */
    __asm__ volatile(
        "mov sp, %0  \n"     /* Charger le nouveau SP */
        :
        : "r"(new_sp)
        : "memory"
    );
    
    /* Mettre à jour le SP d'idle */
    idle_task->context.sp = new_sp;
    
    /* Vérification */
    __asm__ volatile("mov %0, sp" : "=r"(current_sp));
    //KINFO("New SP: 0x%08X\n", current_sp);
    
    if (current_sp < (uint32_t)idle_task->stack_base || 
        current_sp >= (uint32_t)idle_task->stack_top) {
        panic("Failed to switch to idle stack");
    }
    
    //KINFO("Successfully switched to idle stack\n");
}


/**
 * Initialiser le systeme de taches
 */
void init_task_system(void)
{
    if (scheduler_initialized) {
        KWARN("Task system already initialized\n");
        return;
    }
    
    KINFO("Initializing task system...\n");
    
    /* Initialiser les variables globales */
    current_task = NULL;
    task_list_head = NULL;
    next_task_id = 1;
    task_count = 0;
    
  
    scheduler_initialized = true;
    
    //KINFO("Task system initialized. Current task: %s (ID=%u)\n", 
    //      current_task->name, current_task->task_id);
}

/**
 * Nettoyer le systeme de taches
 */
void cleanup_task_system(void)
{
    if (!scheduler_initialized) return;
    
    spin_lock(&task_lock);
    
    /* Detruire toutes les taches sauf idle */
    task_t* task = task_list_head;
    task_t* next;
    
    while (task) {
        next = task->next;
        if (task != idle_task) {
            task_destroy(task);
        }
        task = (next == task_list_head) ? NULL : next;
    }
    
    /* Detruire idle en dernier */
    if (idle_task) {
        task_destroy(idle_task);
        idle_task = NULL;
    }
    
    /* Reinitialiser les variables */
    current_task = NULL;
    task_list_head = NULL;
    next_task_id = 1;
    task_count = 0;
    scheduler_initialized = false;
    
    spin_unlock(&task_lock);
    
    KINFO("Task system cleaned up\n");
}

/* Fonction de validation a ajouter */
bool validate_task_stack_safe(task_t* task)
{
    if (!task || !task->stack_base || !task->stack_top) {
        KERROR("validate_task_stack: Invalid task or stack pointers\n");
        return false;
    }
    
    uint32_t base = (uint32_t)task->stack_base;
    uint32_t top = (uint32_t)task->stack_top;
    uint32_t sp = task->context.sp;
    
    /* Verification fondamentale */
    if (base >= top) {
        KERROR("Task %s: Invalid stack layout (base >= top)\n", task->name);
        return false;
    }
    
    /* SP dans les limites */
    if (sp <= base || sp >= top) {
        KERROR("Task %s: SP out of bounds (SP=0x%08X, base=0x%08X, top=0x%08X)\n", 
               task->name, sp, base, top);
        return false;
    }
    
    /* Marges de securite */
    if (sp - base < 256) {
        KERROR("Task %s: SP too close to base (margin=%u bytes)\n", 
               task->name, sp - base);
        return false;
    }
    
    if (top - sp < 256) {
        KERROR("Task %s: SP too close to top (margin=%u bytes)\n", 
               task->name, top - sp);
        return false;
    }
    
    /* Alignement */
    if (sp & 7) {
        KERROR("Task %s: SP not aligned (SP=0x%08X)\n", task->name, sp);
        return false;
    }
    
    return true;
}

const char* task_type_to_string(task_type_t type)
{
    switch( type ){
        case TASK_TYPE_KERNEL : return "KERNEL" ;
        case TASK_TYPE_PROCESS : return "PROCESS" ;
        case TASK_TYPE_THREAD : return "THREAD" ;
        default : return "NO TYPE SET";
    }
}

/* Version amelioree de task_dump_stacks() pour diagnostic */
void task_dump_stacks_detailed(void)
{
    task_t* task;
    task_t* start_task;
    int count = 0;
    int valid_stacks = 0;
    int invalid_stacks = 0;
    
    KINFO("=== DETAILED Stack Analysis ===\n");
    
    if (!task_list_head) {
        KINFO("No tasks in list\n");
        return;
    }
    
    task = task_list_head;
    start_task = task_list_head;
    
    do {
        if (task && task->stack_base && task->stack_top) {
            count++;
            
            uint32_t base = (uint32_t)task->stack_base;
            uint32_t top = (uint32_t)task->stack_top;
            uint32_t sp = task->context.sp;
            uint32_t size = task->stack_size;

            print_cpu_mode();
            
            KINFO("Task %u (%s):\n", task->task_id, task->name);
            KINFO("  Stack range: 0x%08X - 0x%08X (%u bytes)\n", base, top, size);
            KINFO("  Current SP:  0x%08X\n", sp);
            
            /* Calculs detailles */
            if (sp > base && sp < top) {
                uint32_t used_from_top = top - sp;
                uint32_t available_below = sp - base;
                
                KINFO("  Space used from top: %u bytes\n", used_from_top);
                KINFO("  Space available below: %u bytes\n", available_below);
                KINFO("  Stack utilization: %u%%\n", 
                      used_from_top / size * 100);
                
                /* etat de la stack */
                if (validate_task_stack_safe(task)) {
                    KINFO("  Status: OK VALID\n");
                    valid_stacks++;
                } else {
                    KINFO("  Status: KO INVALID\n");
                    invalid_stacks++;
                }
                
                /* Alertes */
                if (used_from_top > size * 8 / 10) {
                    KWARN("  WARNING WARNING: Stack >80%% used!\n");
                }
                
                if (available_below < 512) {
                    KWARN("  WARNING WARNING: <512 bytes to stack base!\n");
                }
                
            } else {
                KERROR("  Status: KO CRITICAL - SP out of bounds!\n");
                invalid_stacks++;
            }
            
            /* Alignement */
            KINFO("  SP alignment: %s\n", (sp & 7) ? "KO Misaligned" : "OK Aligned");
            KINFO("  Task Type : %s\n", task_type_to_string(task->type) );
            KINFO("  Task State : %s\n", task_state_string(task->state) );
            KINFO("  Task Context LR : 0x%08X\n", task->context.lr );
            KINFO("  Task Context PC : 0x%08X\n", task->context.pc );
            KINFO("  Task Context CPSR : 0x%08X\n", task->context.cpsr );
            KINFO("  Task Context IS FIRST RUN : %u\n", task->context.is_first_run );
            KINFO("  Task Context NEXT : 0x%08X\n", (uint32_t)task->next );
            KINFO("  Task Context PREVIOUS : 0x%08X\n", (uint32_t)task->prev );
            if(task->process){
                KINFO("  Task Context Process VM Stack Start : 0x%08X\n", task->process->vm->stack_start );
                KINFO("  Task Context Process VM Heap Start : 0x%08X\n", task->process->vm->heap_start );
                KINFO("  Task Context Process PID : %d\n", task->process->pid );
                KINFO("  Task Context Process PPID : %d\n", task->process->ppid );
                KINFO("  Task Context Process WAIT PID : %d\n", task->process->waitpid_pid );
                KINFO("  Task Context Process WAIT PID CALLER LR : 0x%08X\n", task->process->waitpid_caller_lr );
            }

            KINFO("\n");
        }
        
        task = task->next;
        
        if (count > 10) {
            KWARN("*** Loop protection activated ***\n");
            break;
        }
        
    } while (task && task != start_task);
    
    /* Resume */
    KINFO("=== Stack Analysis Summary ===\n");
    KINFO("Total tasks analyzed: %d\n", count);
    KINFO("Valid stacks:        %d\n", valid_stacks);
    KINFO("Invalid stacks:      %d\n", invalid_stacks);
    
    if (invalid_stacks > 0) {
        KERROR("DONE CRITICAL: %d tasks have invalid stacks!\n", invalid_stacks);
    } else {
        KINFO("OK All stacks are valid\n");
    }
}


/**
 * Creer une nouvelle tache
 */
task_t* task_create(const char* name, void (*entry)(void* arg), void* arg, uint32_t priority)
{
    task_t* task;
    
    /*if (!entry) {
        KERROR("task_create: NULL entry point\n");
        return NULL;
    }*/
    
    if (task_count >= MAX_TASKS) {
        KERROR("task_create: Maximum task count reached (%d)\n", MAX_TASKS);
        return NULL;
    }
    
    /* Allouer la structure de tache */
    task = (task_t*)kmalloc(sizeof(task_t));
    if (!task) {
        KERROR("task_create: Failed to allocate task structure\n");
        return NULL;
    }
    
    /* Allouer la stack */
    task->stack_base = kmalloc(KERNEL_TASK_STACK_SIZE);
    if (!task->stack_base) {
        KERROR("task_create: Failed to allocate stack\n");
        kfree(task);
        return NULL;
    }
    
    /* CORRECTION : Verifier l'alignement de la stack */
    if (((uint32_t)task->stack_base & 7) != 0) {
        KWARN("Stack base not aligned for task %s, adjusting...\n", name ? name : "unnamed");
        /* Note: Dans un vrai systeme, on devrait reallouer avec un allocateur aligne */
    }
    
    /* Initialiser la structure */
    task->task_id = next_task_id++;
    strncpy(task->name, name ? name : "unnamed", TASK_NAME_MAX - 1);
    task->name[TASK_NAME_MAX - 1] = '\0';
    
    task->state = TASK_READY;
    task->priority = priority;
    
    task->stack_size = KERNEL_TASK_STACK_SIZE;
    task->stack_top = (uint8_t*)task->stack_base + KERNEL_TASK_STACK_SIZE;
    
    task->entry_point = entry;
    task->entry_arg = arg;
    
    task->next = NULL;
    task->prev = NULL;
    
    /* Statistiques */
    task->created_time = 0;
    task->total_runtime = 0;
    task->switch_count = 0;

    task->type = TASK_TYPE_PROCESS;  /* Nouvelle ligne */
    //task->process->pid = task->task_id;  /* Nouvelle ligne */
    task->context.is_first_run = 1;
    
    /* === CONFIGURATION CORRIGeE DU CONTEXTE === */
    setup_task_context(task);

    task->context.svc_sp_top = (uint32_t)task->stack_top;
    task->context.svc_sp = ((uint32_t)task->stack_top - 512) & ~7u;
    task->context.sp = task->context.svc_sp;


    //debug_context_registers(&task->context, "AFTER_setup_task_context");
    
    /* === VALIDATION CRITIQUE === */
    if (!validate_task_stack_safe(task)) {
        KERROR("KO Stack validation failed for task %s\n", task->name);
        kfree(task->stack_base);
        kfree(task);
        return NULL;
    }
    
    /* Ajouter a la liste des taches */
    add_task_to_list(task);
    
    KINFO("OK Created task '%s' (ID=%u, priority=%u) - Stack validated\n", 
          task->name, task->task_id, task->priority);
    
    return task;
}

void init_standard_files(process_t* process) {
    // stdin (fd = 0) - lecture UART
    process->files[STDIN_FILENO] = create_uart_console_file("stdin", O_RDONLY);
    
    // stdout (fd = 1) - écriture UART
    process->files[STDOUT_FILENO] = create_uart_console_file("stdout", O_WRONLY);
    
    // stderr (fd = 2) - écriture UART (même que stdout)
    process->files[STDERR_FILENO] = create_uart_console_file("stderr", O_WRONLY);
}


/**
 * Adapter task_create pour supporter les processus
 */
task_t* task_create_process(const char* name, void (*entry)(void* arg), 
                                  void* arg, uint32_t priority, task_type_t type)
{
    task_t* task = task_create(name, entry, arg, priority);
    if (!task) return NULL;
    
    /* Configurer le type */
    task->type = type;
    
    if (type == TASK_TYPE_PROCESS) {

        task->process = (process_t *)kmalloc(sizeof(process_t));
        if (!task->process) {
            KERROR("Task Crete Copy : cannot allocate process structure...");
            task_destroy(task);
            return NULL;
        }

        /* Initialiser les champs processus */
        task->process->pid = next_pid++;
        task->process->ppid = (current_task && current_task->type == TASK_TYPE_PROCESS) ? 
                             current_task->process->pid : 0;
        task->process->parent = (current_task && current_task->type == TASK_TYPE_PROCESS) ? 
                               current_task : NULL;
        task->process->children = NULL;
        task->process->sibling_next = NULL;
        task->process->exit_code = 0;
        task->process->uid = 0;
        task->process->gid = 0;
        task->process->state = (proc_state_t)PROC_READY;
        
        /* Creer l'espace memoire */
        if(task->process->pid == 1){
            task->process->vm = create_vm_space(false); //INIT PROCESS IS KERNEL PROCESS
        }
        else{
            task->process->vm = create_vm_space(false);
        }

        if (!task->process->vm) {
            task_destroy(task);
            return NULL;
        }

        task->context.ttbr0 = (uint32_t)task->process->vm->pgdir;
        task->context.asid = task->process->vm->asid;
        
        /* Initialiser les fichiers */
        memset(task->process->files, 0, sizeof(task->process->files));

        init_standard_files(task->process);



        /* Initialiser les champs waitpid */
        task->process->waitpid_pid = 0;
        task->process->waitpid_status = NULL;
        task->process->waitpid_options = 0;
        task->process->waitpid_iteration = 0;
        task->process->waitpid_caller_lr = 0;
        
        /* Initialiser les signaux */
        init_process_signals(task);
        
        //KINFO("Created process %s (PID=%u)\n", name, task->process->pid);
        //KDEBUG(" SCV STACK TOP = 0x%08X\n", task->context.svc_sp_top);
        //KDEBUG(" SCV STACK SP = 0x%08X\n", task->context.svc_sp);
        //KDEBUG(" TTBR0 = 0x%08X\n", task->context.ttbr0);
        //KDEBUG(" ASID = %u\n", task->context.asid);
    } else {
        // Mettre toute la structure process à zéro
        task->process = NULL; // KERNEL TASK
    
        //KINFO("Created kernel task %s (ID=%u)\n", name, task->task_id);
    }
    
    return task;
}


/**
 * Configurer le contexte initial d'une tache
 */
void setup_task_context(task_t* task)
{
    memset(&task->context, 0, sizeof(task_context_t));
    
    /* Configuration des registres */
    task->context.r0 = (uint32_t)task->entry_arg;
    
    /* Stack configuration corrigee */
    uint32_t stack_top = (uint32_t)task->stack_top;
    uint32_t stack_reserve = 512; /*512 avant*/
    task->context.sp = stack_top - stack_reserve;
    task->context.sp &= ~7;  /* Alignement 8-bytes */
    
    /* Autres registres */
    task->context.lr = 0;
    //task->context.lr = (uint32_t)task_destroy;
    task->context.pc = (uint32_t)task->entry_point;
    task->context.cpsr = 0x13;  /* Mode SVC, IRQ enabled */
    
    /* NOUVEAU: Marquer comme premiere execution */
    task->context.is_first_run = 1;
    
    /* Debug */
    //KINFO("OK Task %s context configured:\n", task->name);
    //KINFO("   SP:           0x%08X\n", task->context.sp);
    //KINFO("   PC:           0x%08X\n", task->context.pc);
    //KINFO("   LR:           0x%08X\n", task->context.lr);
    //KINFO("   is_first_run: %u\n", task->context.is_first_run);
    
    /* Validation */
    if (task->context.sp >= (uint32_t)task->stack_top || 
        task->context.sp <= (uint32_t)task->stack_base) {
        KERROR("KO FATAL: Invalid SP for task %s\n", task->name);
        panic("Stack configuration error");
    }
}

/**
 * Detruire une tache
 */
void task_destroy(task_t* task)
{
    if (!task) {
        task = current_task;  /* Detruire la tache courante si NULL */
    }
    
    if (task == idle_task) {
        KERROR("Cannot destroy idle task\n");
        return;
    }
    
    //KINFO("Destroying task '%s' (ID=%u)\n", task->name, task->task_id);
    
    spin_lock(&task_lock);
    
    /* Marquer comme zombie d'abord */
    task->state = TASK_ZOMBIE;
    //task->state = TASK_TERMINATED;
    task->process->state = (proc_state_t)PROC_ZOMBIE;
    
    /* Si c'est la tache courante, forcer une commutation */
    if (task == (task_t*)current_task) {
        spin_unlock(&task_lock);
        schedule();  /* Ne reviendra jamais ici */
        /* NOTREACHED */
    }
    
    spin_unlock(&task_lock);

    /* Retirer de la liste */
    remove_task_from_list(task);
    
    /* Liberer les ressources */
    kfree(task->stack_base);

    kfree(task->process);

    kfree(task);
}

/* Ajouter cette vérification dans schedule_next_task */
void verify_ready_queue_integrity(void)
{
    KDEBUG("=== READY QUEUE VERIFICATION ===\n");
    
    task_t* task = task_list_head;
    if (!task) {
        KDEBUG("Ready queue is empty\n");
        return;
    }
    
    int count = 0;
    do {
        count++;
        KDEBUG("  [%d] %s (ID=%u): state=%d, next=0x%08X, prev=0x%08X\n", 
               count, task->name, task->task_id, task->state,
               (uint32_t)task->next, (uint32_t)task->prev);
               
        if (count > 20) {  /* Éviter les boucles infinies */
            KERROR("Ready queue seems corrupted (too many tasks)\n");
            break;
        }
        
        task = task->next;
    } while (task && task != task_list_head);
    
    KDEBUG("Total tasks in ready queue: %d\n", count);
}


/**
 * Ceder le CPU volontairement
 */
void yield(void)
{

    if (!scheduler_initialized) {
        return;
    }
    
    /* VÉRIFIEZ: La tâche courante devient READY */
    if (current_task && current_task->state == TASK_RUNNING) {
        current_task->state = TASK_READY;
    }

    //KDEBUG(" TASK %s is yielding : \n", current_task->name) ;
    //if (current_task && strstr(current_task->name, "child")) {
    //    KDEBUG("[CHILD] yield() called\n");
    //}

    task_sleep_ms(100);  // Pause a bit to avoid race conditions.
    
    schedule();
    
    //if (current_task && strstr(current_task->name, "child")) {
    //    KDEBUG("[CHILD] yield() returning\n");
    //}

}

bool is_on_kernel_stack(uint32_t sp)
{
    extern uint32_t __stack_bottom, __stack_top;
    uint32_t kernel_stack_bottom = (uint32_t)&__stack_bottom;
    uint32_t kernel_stack_top = (uint32_t)&__stack_top;
    
    return (sp >= kernel_stack_bottom && sp < kernel_stack_top);
}

bool is_on_task_stack(task_t* task, uint32_t sp)
{
    if (!task) return false;
    
    uint32_t task_stack_bottom = (uint32_t)task->stack_base;
    uint32_t task_stack_top = (uint32_t)task->stack_top;
    
    return (sp >= task_stack_bottom && sp < task_stack_top);
}

void debug_idle_corruption_source(void)
{
    if (!idle_task) return;
    
    /* Obtenir la trace de la pile */
    uint32_t lr;
    __asm__ volatile("mov %0, lr" : "=r"(lr));
    
    KERROR("IDLE CORRUPTION DETECTED!\n");
    KERROR("  Called from: 0x%08X\n", lr);
    KERROR("  Current task: %s\n", current_task ? current_task->name : "NULL");
    
    /* Dump de toutes les tâches pour voir qui a un stack_top bizarre */
    task_t* task = task_list_head;
    if (task) {
        do {
            uint32_t expected_top = (uint32_t)task->stack_base + task->stack_size;
            if ((uint32_t)task->stack_top != expected_top) {
                KERROR("SUSPECT: Task %s has corrupted stack_top!\n", task->name);
                KERROR("  Expected: 0x%08X, Actual: 0x%08X\n", 
                       expected_top, (uint32_t)task->stack_top);
            }
            task = task->next;
        } while (task != task_list_head);
    }
}

void protect_idle_task(void)
{
    if (!idle_task) return;
    
    /* Sauvegarder les vraies valeurs d'idle */
    static uint8_t* idle_real_stack_base = NULL;
    static uint8_t* idle_real_stack_top = NULL;
    static uint32_t idle_real_stack_size = 0;
    static bool idle_protection_initialized = false;
    
    if (!idle_protection_initialized) {
        /* Sauvegarder les valeurs originales d'idle */
        idle_real_stack_base = idle_task->stack_base;
        idle_real_stack_top = idle_task->stack_top;
        idle_real_stack_size = idle_task->stack_size;
        idle_protection_initialized = true;
        
        //KINFO("IDLE PROTECTION: Saved original values\n");
        //KINFO("  stack_base: 0x%08X\n", (uint32_t)idle_real_stack_base);
        //KINFO("  stack_top:  0x%08X\n", (uint32_t)idle_real_stack_top);
        //KINFO("  stack_size: %u\n", idle_real_stack_size);
        return;  /* Pas de vérification au premier appel */
    }
    
    /* Vérifier et corriger les corruptions */
    bool corrupted = false;
    
    if (idle_task->stack_base != idle_real_stack_base) {
        KERROR("IDLE CORRUPTION: stack_base changed from 0x%08X to 0x%08X\n",
               (uint32_t)idle_real_stack_base, (uint32_t)idle_task->stack_base);
        idle_task->stack_base = idle_real_stack_base;
        corrupted = true;
    }
    
    if (idle_task->stack_top != idle_real_stack_top) {
        KERROR("IDLE CORRUPTION: stack_top changed from 0x%08X to 0x%08X\n",
               (uint32_t)idle_real_stack_top, (uint32_t)idle_task->stack_top);
        idle_task->stack_top = idle_real_stack_top;
        corrupted = true;
    }
    
    if (idle_task->stack_size != idle_real_stack_size) {
        KERROR("IDLE CORRUPTION: stack_size changed from %u to %u\n",
               idle_real_stack_size, idle_task->stack_size);
        idle_task->stack_size = idle_real_stack_size;
        corrupted = true;
    }
    
    /*  SI CORRUPTION DÉTECTÉE, APPELER LE DIAGNOSTIC */
    if (corrupted) {
        debug_idle_corruption_source();  /* ← ICI ! */
        KWARN("IDLE PROTECTION: Corruptions fixed\n");
    }
}

void save_task_context_safe(task_t* task)
{
    if (!task) return;
    
    /* Protéger idle avant toute manipulation */
    if (task == idle_task) {
        protect_idle_task();
    }

    /* NE PAS sauvegarder les zombies ! */
    if (task->state == TASK_ZOMBIE) {
        //KDEBUG("save_task_context_safe: Skipping zombie task %s\n", task->name);
        return;
    }
    
    /* Debug pour les enfants */
    if (strstr(task->name, "child")) {

        if(task->type == TASK_TYPE_PROCESS){
            if(task->context.cpsr == 0x10 )
                return; // User Process forking from userspace
        }
        uint32_t current_sp;
        __asm__ volatile("mov %0, sp" : "=r"(current_sp));
        //KDEBUG("SAVE child: Current SP=0x%08X, task SP=0x%08X\n", 
        //       current_sp, task->context.sp);
    }
    
    uint32_t current_sp;
    __asm__ volatile("mov %0, sp" : "=r"(current_sp));
    
    if (task == idle_task) {
        /* Vérification spéciale pour idle */
        if (is_on_task_stack(task, current_sp)) {
            /* SP valide dans la pile d'idle */
            task->context.sp = current_sp;
            //KDEBUG("Saved valid SP for idle: 0x%08X\n", current_sp);
        } else if (is_on_kernel_stack(current_sp)) {
            /* CRITIQUE: Idle sur pile kernel - ne pas sauvegarder ! */
            //KERROR("Idle still on kernel stack! SP=0x%08X\n", current_sp);
            KERROR("Keeping idle SP at: 0x%08X\n", task->context.sp);
            /* Ne pas écraser task->context.sp */
        } else {
            KERROR("Idle on unknown stack! SP=0x%08X\n", current_sp);
            /* Ne pas écraser task->context.sp */
        }
    } else {
        /* Pour les autres tâches, comportement normal */
        if (is_on_task_stack(task, current_sp)) {
            task->context.sp = current_sp;
            //KDEBUG("Saved valid SP for %s: 0x%08X\n", task->name, current_sp);
        } else {

            //task_dump_stacks_detailed();
            KERROR("Task %s has invalid SP: 0x%08X - context SP = 0x%08X\n", task->name, current_sp, task->context.sp);
            //panic("Stopping");
            return;
        }
    }
}



void schedule(void)
{
    uint32_t irq_flags;
    task_t* old_task;
    task_t* next_task;

    static uint32_t schedule_count = 0;
    schedule_count++;
    
    if (!scheduler_initialized || !current_task) {
        KERROR("SCHED: Not initialized or no current task\n");
        return;
    }

    //void* caller = __builtin_return_address(0);
    //KDEBUG("[CHILD] schedule() called from 0x%08X\n", (uint32_t)caller);

    //validate_task_list("SCHEDULE_START");
    
    //KDEBUG("SCHED: === Starting schedule() ===\n");
    
    irq_flags = disable_interrupts_save();
    //KDEBUG("SCHED: IRQ disabled\n");

    //if (schedule_count /*% 50 == 0*/) {
    //    KINFO("=== SCHEDULE DEBUG #%u ===\n", schedule_count);
    //    verify_ready_queue_integrity();
    //}
    
    /* Petit délai pour éviter les race conditions */
    for (volatile int i = 0; i < 1000; i++);
    
    protect_idle_task();

    if (current_task && current_task->state != TASK_ZOMBIE) {
        save_task_context_safe(current_task);
    } else {
        //KDEBUG("schedule: NOT saving zombie context\n");  /*  Debug */
    }

    old_task = current_task;

    spin_lock(&task_lock);

    /* Modifications atomiques */
    if (old_task->state == TASK_RUNNING) {
        old_task->state = TASK_READY;
    }

    spin_unlock(&task_lock);


    // *** NOUVEAU: Verifier si la tache courante doit etre detruite ***
    if (old_task->state == TASK_ZOMBIE) {
        spin_lock(&task_lock);

        //KDEBUG("SCHED: Current task is zombie, switching without save\n");
        
        //next_task = schedule_next_task();
        //if (next_task == old_task) {
            next_task = idle_task; // Forcer vers idle si pas d'autre choix
        //}
        
        next_task->state = TASK_RUNNING;
        current_task = next_task;

                // *** Commutation speciale : pas de sauvegarde pour zombie ***
        if(next_task == idle_task){
            //KDEBUG("SCHED: Next task is idle, switching to idle stack\n");
                switch_to_idle_stack();
                next_task->context.pc = (uint32_t)idle_task->entry_point;
        }

        //KDEBUG("Next task: %s (ID=%u) is doing is calling __task_first_switch_v2\n", next_task->name, next_task->task_id);
        //KDEBUG("Task stack_base: %p\n", next_task->stack_base);
        //KDEBUG("Task stack_top:  %p\n", next_task->stack_top);
        //KDEBUG("Task stack_size: %u bytes\n", next_task->stack_size);
        //KDEBUG("Task context.sp: 0x%08X\n", next_task->context.sp);
        //KDEBUG("       PC=0x%08X\n", next_task->context.pc);
        //KDEBUG("       SP=0x%08X\n", next_task->context.sp);
        //KDEBUG("       LR=0x%08X\n", next_task->context.lr);

        spin_unlock(&task_lock);

        // *** Commutation speciale : pas de sauvegarde pour zombie ***        
        __task_switch(NULL, &next_task->context);

        KERROR("\n\n======================================= NEVER COME BACK HERE ==================\n");

        
        // Ne revient jamais ici
        return;
    }

    next_task = schedule_next_task();
    
    //KDEBUG("SCHED: old=%s, next=%s\n", old_task->name, next_task->name);
    //print_system_stats();

        // DEBUG DIAGNOSTIC DeTAILLe AVANT VeRIFICATION
    //KDEBUG("=== SCHEDULE DEBUG: Task SP Analysis ===\n");
    //KDEBUG("Next task: %s (ID=%u)\n", next_task->name, next_task->task_id);
    //KDEBUG("Task stack_base: %p\n", next_task->stack_base);
    //KDEBUG("Task stack_top:  %p\n", next_task->stack_top);
    //KDEBUG("Task stack_size: %u bytes\n", next_task->stack_size);
    //KDEBUG("Task context.sp: 0x%08X\n", next_task->context.sp);
    
    // Calculer les limites attendues
    //uint32_t expected_bottom = (uint32_t)next_task->stack_base;
    //uint32_t expected_top = expected_bottom + next_task->stack_size;
    
    //KDEBUG("Expected range: 0x%08X - 0x%08X\n", expected_bottom, expected_top);
    //KDEBUG("SP position relative to base: %d bytes\n", 
    //       (int)(next_task->context.sp - expected_bottom));
    
    // Verifications specifiques
    if (!next_task->stack_base) {
        KERROR("KO stack_base is NULL!\n");
    }
    if (!next_task->stack_top) {
        KERROR("KO stack_top is NULL!\n");
    }
    if (next_task->stack_size == 0) {
        KERROR("KO stack_size is 0!\n");
    }
    if (next_task->context.sp == 0) {
        KERROR("KO context.sp is 0!\n");
    }
    
    // Verifier coherence stack_top
    if (next_task->stack_top != (uint8_t*)next_task->stack_base + next_task->stack_size) {
        KERROR("KO stack_top inconsistent!\n");
        KERROR("   stack_top: %p\n", next_task->stack_top);
        KERROR("   Expected:  %p\n", (uint8_t*)next_task->stack_base + next_task->stack_size);
    }

    //task_sleep_ms(20000);
    
    if (next_task == (task_t *)current_task) {
        //KDEBUG("SCHED: No change needed\n");
        /* Pas de changement, restaurer l'etat */
        spin_lock(&task_lock);

        if (old_task->state == TASK_READY) {
            old_task->state = TASK_RUNNING;
        }
        restore_interrupts(irq_flags);
        spin_unlock(&task_lock);

        return;
    }
    
    /* Verifications pre-commutation */
    //KDEBUG("SCHED: Pre-switch validation\n");
    //KDEBUG("SCHED: old_task SP=0x%08X, PC will be saved as LR\n", old_task->context.sp);
    //KDEBUG("SCHED: next_task SP=0x%08X, PC=0x%08X\n", next_task->context.sp, next_task->context.pc);

    //task_dump_info(old_task);
    //task_dump_info(next_task);
    //task_dump_stacks_detailed();

    //if (next_task && strcmp(next_task->name, "shell-child") == 0) {
    //    KDEBUG("=== SHELL-CHILD SP TRACKING ===\n");
    //    KDEBUG("About to schedule shell-child\n");
    //    KDEBUG("Expected SP: 0x413FC010\n");  // Le bon SP calcule
    //    KDEBUG("Actual SP:   0x%08X\n", next_task->context.sp);
        
    //    if (next_task->context.sp != 0x413FC010) {
    //        KERROR("KO SP CORRUPTION DETECTED!\n");
    //        KERROR("   SP should be 0x413FC010, but is 0x%08X\n", next_task->context.sp);
            
            //  CORRECTION D'URGENCE
    //        KWARN("FIX Emergency SP correction\n");
    //        next_task->context.sp = 0x413FC010;
    //    }
        //KDEBUG("=================================\n");
    // }
    //task_list_all();
    //task_dump_stacks_detailed();
    

    //KDEBUG("OLD TASK NAME = %s : SP = %p : STK BASE = %p , STACK TOP = %p\n" ,
    //        old_task->name , old_task->context.sp, old_task->stack_base, old_task->stack_top );

    //KDEBUG("NEW TASK NAME = %s : SP = %p : STK BASE = %p , STACK TOP = %p\n" ,
    //        next_task->name , next_task->context.sp, next_task->stack_base, old_task->stack_top );

    /* Verifier que les SP sont dans les bonnes plages */
    if (old_task->context.sp < (uint32_t)old_task->stack_base || 
        old_task->context.sp >= (uint32_t)old_task->stack_top) {
        KERROR("SCHED: old_task SP out of range!\n");

        restore_interrupts(irq_flags);
        return;
    }
    
    if (next_task->context.sp < (uint32_t)next_task->stack_base || 
        next_task->context.sp >= (uint32_t)next_task->stack_top) {
        KERROR("SCHED: next_task %s SP out of range!\n", next_task->name);
        KERROR("SCHED: next_task SP 0x%08X\n", next_task->context.sp);
        KERROR("SCHED: next_task Stack Base 0x%08X\n", (uint32_t)next_task->stack_base);
        KERROR("SCHED: next_task Stack Top 0x%08X\n", (uint32_t)next_task->stack_top);
        KERROR("SCHED: old_task %s !\n", old_task->name);
        KERROR("SCHED: old_task SP 0x%08X\n", old_task->context.sp);
        KERROR("SCHED: old_task Stack Base 0x%08X\n", (uint32_t)old_task->stack_base);
        KERROR("SCHED: old_task Stack Top 0x%08X\n", (uint32_t)old_task->stack_top);


        debug_print_ctx(&next_task->context);

        restore_interrupts(irq_flags);
        return;
    }

        //KDEBUG("ROBUST: %s->%s (old_first=%u, new_first=%u)\n", 
        //   old_task->name, next_task->name,
        //   old_task->context.is_first_run, next_task->context.is_first_run);
    
    next_task->state = TASK_RUNNING;
    next_task->switch_count++;
    current_task = next_task;

    #if(0)
    {
        //KDEBUG("SCHED: States updated, about to call __task_switch R0= %p, R1= %p\n", &old_task->context,&next_task->context);
        //KDEBUG("SCHED: States updated, Old task %s first_run = %u, cpsr = 0x%02X, return_to_user = %u\n",old_task->name, old_task->context.is_first_run, old_task->context.cpsr ,old_task->context.returns_to_user);
        //KDEBUG("SCHED: States updated, New task %s first_run = %u, cpsr = 0x%02X, return_to_user = %u\n",next_task->name, next_task->context.is_first_run, next_task->context.cpsr ,next_task->context.returns_to_user);
        //KDEBUG("SCHED: States updated, New task %s svc_sp_top = 0x%08X, svc_sp = 0x%08X\n",next_task->name, next_task->context.svc_sp_top, next_task->context.svc_sp);
        //KDEBUG("SCHED: States updated, New task %s TTBR = 0x%08X, ASID = %d\n",next_task->name, next_task->context.ttbr0, next_task->context.asid);
 
        if(strstr(old_task->name,"shell")){
            KDEBUG("SCHED: States updated, New task %s first_run = %u, cpsr = 0x%02X, return_to_user = %u\n",next_task->name, next_task->context.is_first_run, next_task->context.cpsr ,next_task->context.returns_to_user);
            debug_print_ctx(&old_task->context);
        }
        if(strstr(next_task->name,"shell")) {
            KDEBUG("SCHED: States updated, New task %s first_run = %u, cpsr = 0x%02X, return_to_user = %u\n",next_task->name, next_task->context.is_first_run, next_task->context.cpsr ,next_task->context.returns_to_user);
            debug_print_ctx(&next_task->context);
        }
    }
    #endif
    //debug_task_detailed(old_task);
    //debug_task_detailed(next_task);

    //debug_context_registers(&old_task->context, "BEFORE___task_switch_asm_debug__old_task->context");
    //debug_context_registers(&next_task->context, "BEFORE___task_switch_asm_debug__next_task->context");
    
    /* === POINT CRITIQUE === */
    __task_switch(&old_task->context, &next_task->context);
    //__task_switch_asm_debug(&old_task->context, &next_task->context);

    //KDEBUG("TASK SWITCH SUCCESSFULLLLLLLL ============================================================\n");
    
    /* === On arrive ici dans le contexte de next_task === */

    /*if( strstr(current_task->name, "child"))
    {
        uart_puts("SCHED: RETURNED from __task_switch_asm - now in ");
        uart_puts(current_task->name);
        uart_puts("\n");

        uint32_t reg;
        __asm__ volatile("mov %0, sp" : "=r"(reg));
        KDEBUG("SP immediately after asm: 0x%08X\n", reg);
        __asm__ volatile("mov %0, lr" : "=r"(reg));
        KDEBUG("LR immediately after asm: 0x%08X\n", reg);
        __asm__ volatile("mov %0, pc" : "=r"(reg));
        KDEBUG("PC immediately after asm: 0x%08X\n", reg);

        KDEBUG("Valeurs de la structure context de la tache:\n");
        KDEBUG("   SP : %p\n", current_task->context.sp);
        KDEBUG("   LR : %p\n", current_task->context.lr);
        KDEBUG("   PC : %p\n", current_task->context.pc);
        KDEBUG("   R0 : %p\n", current_task->context.r0);


        uart_puts("[CHILD]: PID =  ");
        uart_put_dec(sys_getpid());
        uart_puts("\n");
        uart_puts("[CHILD]: PPID =  ");
        uart_put_dec(sys_getppid());
        uart_puts("\n");
        task_list_all();
        task_dump_stacks_detailed();
        uart_puts("[CHILD] Debug completed, about to restore interrupts\n");
    }*/

    //uart_puts("[DEBUG] Restoring interrupts\n");

    restore_interrupts(irq_flags);
    //uart_puts("[DEBUG] Schedule() returning\n");

    //validate_task_list("SCHEDULE_START");
    //if (strstr(current_task->name, "child")) {
    //    KDEBUG("[CHILD] Returned from schedule() - should go to user code now\n");
        //sys_exit(99);
   // }

    //caller = __builtin_return_address(0);
    //KDEBUG("[SCHED] schedule() returning to 0x%08X\n", (uint32_t)caller);

    //KDEBUG("SCHED: === schedule() completed for %s ===\n", current_task->name);

}

/**
 * Version etendue de schedule() qui gere les types de taches
 */
void schedule_extended(void)
{
    /* Verifier les signaux en attente pour les processus */
    if (current_task && current_task->type == TASK_TYPE_PROCESS) {
        check_pending_signals();
    }
    
    /* Appeler votre schedule() existant */
    schedule();
}



/**
 * Demarrer le scheduler (premiere commutation)
 */
void sched_start(void)
{
    if (!scheduler_initialized) {
        KERROR("Task system not initialized!\n");
        return;
    }
    
    spin_lock(&task_lock);
    
    if (!task_list_head) {
        spin_unlock(&task_lock);
        KERROR("No tasks to run!\n");
        return;
    }
    
    //KDEBUG("SCHEDULER STARTED\n");
    //task_dump_stacks_detailed();

    /* Choisir la premiere tache */
    //current_task = schedule_next_task();
    //if (!current_task) {
    //    spin_unlock(&task_lock);
    //    KERROR("Unable to select first task!\n");
    //    return;
    //}
    
    /* OK CORRECTION: Marquer idle comme READY avant le switch */
    //if (idle_task && idle_task->state == TASK_RUNNING) {
    //    idle_task->state = TASK_READY;
    //}

    //current_task->state = TASK_RUNNING;
    
    /* La tache idle devient la tache courante */
    current_task = idle_task;
    current_task->state = TASK_RUNNING;

    /* Switch vers la pile d'idle MAINTENANT */
    switch_to_idle_stack();
    
    spin_unlock(&task_lock);
    
    //KINFO("Starting scheduler with task: %s (ID=%u) - Is first RUN = %d\n", 
    //      current_task->name, current_task->task_id, current_task->context.is_first_run);
    //task_dump_stacks_detailed();
    
    /* Premiere commutation unique */
    //print_system_stats();
    //__task_first_switch_v2(&current_task->context);
    __task_switch(NULL, &current_task->context);
    
    /* On ne devrait jamais arriver ici */
    KERROR("FATAL: Returned from sched_start!\n");
    while (1) __asm__ volatile("wfe");
}


static task_t* find_next_same_priority_task(task_t* current)
{
    task_t* task = current->next;
    uint32_t current_priority = current->priority;
    int count = 0;
    
    /* Chercher la prochaine tache READY avec la meme priorite */
    do {
        if (task->state == TASK_READY && task->priority == current_priority
        && task->state != TASK_ZOMBIE &&
        task->state != TASK_TERMINATED ) {
            return task;
        }
        task = task->next;
        count++;
    } while (task != current && count < MAX_TASKS);
    
    return current;  /* Pas d'autre tache de meme priorite */
}

/**
 * Round-robin ameliore qui evite de re-selectionner la meme tache
 */
static task_t* schedule_next_task(void)
{

    if (!task_list_head) {
        return idle_task;
    }
    

    /* OK NOUVEAU: Toujours essayer de trouver une tache differente */
    task_t* start_search = current_task ? current_task->next : task_list_head;
    task_t* current = start_search;
    task_t* fallback = NULL;
    int count = 0;
    
    //KDEBUG("schedule_next_task: Starting search from %s\n", 
    //       start_search ? start_search->name : "NULL");
    spin_lock(&task_lock);

    do {
        if (current->state == TASK_READY && 
            current->state != TASK_ZOMBIE && 
            current->state != TASK_TERMINATED) {
            
            /* Preferer une tache differente de current_task */
            if (current != (task_t *)current_task) {
                //KDEBUG("  -> Selected different task: %s\n", current->name);
                    spin_unlock(&task_lock);

                return current;
            } else {
                /* Garder current_task comme fallback */
                fallback = current;
                //KDEBUG("  -> Found current task as fallback: %s\n", current->name);
            }
        }
        
        current = current->next;
        count++;
        
        if (count > MAX_TASKS) {
            KERROR("schedule_next_task: Loop protection triggered!\n");
            break;
        }
        
    } while (current != start_search);
    
    /* Si on n'a trouve que current_task, l'utiliser */
    if (fallback) {
        //KDEBUG("  -> Using fallback (current): %s\n", fallback->name);
        spin_unlock(&task_lock);
    
        return fallback;
    }
    
    /* Dernier recours : idle */
    //KDEBUG("  -> No ready tasks, returning idle\n");
        spin_unlock(&task_lock);

    return idle_task;
}



/**
 * Ajouter une tache a la liste circulaire
 */
void add_task_to_list(task_t* task)
{
    spin_lock(&task_lock);

    if (!task_list_head) {
        /* Premiere tache */
        task_list_head = task;
        task->next = task;
        task->prev = task;
    } else {
        /* Inserer a la fin */
        task->next = task_list_head;
        task->prev = task_list_head->prev;
        task_list_head->prev->next = task;
        task_list_head->prev = task;
    }
    task_count++;

    spin_unlock(&task_lock);


}

/**
 * Retirer une tache de la liste circulaire
 */
static void remove_task_from_list(task_t* task)
{
    if (!task || !task_list_head) return;

     spin_lock(&task_lock);   
    
    if (task->next == task) {
        /* Derniere tache */
        task_list_head = NULL;
    } else {
        task->prev->next = task->next;
        task->next->prev = task->prev;
        
        if (task_list_head == task) {
            task_list_head = task->next;
        }
    }
    
    task->next = NULL;
    task->prev = NULL;
    task_count--;

     spin_unlock(&task_lock);   

}

/**
 * Fonction de la tache idle
 */
void idle_task_func(void* arg)
{
    (void)arg;
    
    KINFO("Idle task started\n");
    int idle_count = 0;
    
    while (1) {
        idle_count++;
        
        /* Debug periodique */
        if (idle_count % 1000 == 0) {
            //KDEBUG("Idle loop %d, yielding\n", idle_count);
        }
        
        /*  TOUJOURS yield() d'abord */
        yield();
        
        /*  Petite pause au lieu de WFI */
        for (volatile int i = 0; i < 1000; i++) {
            __asm__ volatile("nop");
        }
        
        /* Debug periodique */
        if (idle_count % 1000 == 0) {
            //KDEBUG("Idle completed loop %d\n", idle_count);
        }
    }
}


/**
 * Trouver une tache par ID
 */
task_t* task_find_by_id(uint32_t task_id)
{
    task_t* task = task_list_head;
    int count = 0;
    
    if (!task_list_head) return NULL;
    
    do {
        if (task->task_id == task_id) {
            return task;
        }
        task = task->next;
        count++;
    } while (task != task_list_head && count < MAX_TASKS);
    
    return NULL;
}

/**
 * Trouver une tache par nom
 */
task_t* task_find_by_name(const char* name)
{
    task_t* task = task_list_head;
    int count = 0;
    
    if (!task_list_head || !name) return NULL;
    
    do {
        if (strcmp(task->name, name) == 0) {
            return task;
        }
        task = task->next;
        count++;
    } while (task != task_list_head && count < MAX_TASKS);
    
    return NULL;
}

/**
 * Definir la priorite d'une tache
 */
void task_set_priority(task_t* task, uint32_t priority)
{
    if (!task) return;
    
    spin_lock(&task_lock);
    task->priority = priority;
    spin_unlock(&task_lock);
    
    /* Si on change la priorite de la tache courante, re-scheduler */
    if (task == (task_t *)current_task) {
        schedule();
    }
}

/**
 * Obtenir la priorite d'une tache
 */
uint32_t task_get_priority(task_t* task)
{
    return task ? task->priority : 0;
}

/**
 * Definir l'etat d'une tache
 */
void task_set_state(task_t* task, task_state_t state)
{
    if (!task) return;
    
    spin_lock(&task_lock);
    task->state = state;
    spin_unlock(&task_lock);
}

/**
 * Obtenir l'etat d'une tache
 */
task_state_t task_get_state(task_t* task)
{
    return task ? task->state : TASK_TERMINATED;
}

/**
 * Convertir un etat en chaine
 */
const char* task_state_string(task_state_t state)
{
    switch (state) {
        case TASK_READY: return "READY";
        case TASK_RUNNING: return "RUNNING";
        case TASK_BLOCKED: return "BLOCKED";
        case TASK_ZOMBIE: return "ZOMBIE";
        case TASK_TERMINATED: return "TERMINATED";
        default: return "UNKNOWN";
    }
}


const char* proc_state_string(proc_state_t state)
{
    switch (state) {
        case PROC_READY: return "READY";
        case PROC_RUNNING: return "RUNNING";
        case PROC_BLOCKED: return "BLOCKED";
        case PROC_ZOMBIE: return "ZOMBIE";
        case PROC_DEAD: return "DEAD";
        default: return "UNKNOWN";
    }
}


void task_dump_info(task_t* task)
{
    if (!task) {
        KINFO("task_dump_info: NULL task\n");
        return;
    }
    
    KINFO("=== Task Info ===\n");
    KINFO("  Name:         %s\n", task->name);
    KINFO("  ID:           %u\n", task->task_id);
    KINFO("  State:        %d\n", (int)task->state);
    KINFO("  Priority:     %u\n", task->priority);
    KINFO("  Stack base:   0x%08X\n", (uint32_t)task->stack_base);
    KINFO("  Stack top:    0x%08X\n", (uint32_t)task->stack_top);
    KINFO("  Stack size:   %u bytes\n", task->stack_size);
    KINFO("  Entry point:  0x%08X\n", (uint32_t)task->entry_point);
    KINFO("  Context SP:   0x%08X\n", task->context.sp);
    KINFO("  Context PC:   0x%08X\n", task->context.pc);
}

void task_dump_stacks(void)
{
    task_t* task;
    task_t* start_task;
    int count = 0;
    uint32_t total_stack_memory = 0;
    
    KINFO("=== Task Stack Analysis ===\n");
    KINFO("TaskID  Name         Stack Base   Stack Top    Size     Current SP   Gap to Next\n");
    KINFO("------  -----------  -----------  -----------  -------  -----------  -----------\n");
    
    if (!task_list_head) {
        KINFO("No tasks in list\n");
        return;
    }
    
    /* Parcourir toutes les taches */
    task = task_list_head;
    start_task = task_list_head;
    
    do {
        if (task && task->stack_base && task->stack_top) {
            KINFO("%-6u  %-11s  0x%08X   0x%08X   %-7u  0x%08X   ", 
                  task->task_id,
                  task->name,
                  (uint32_t)task->stack_base,
                  (uint32_t)task->stack_top,
                  task->stack_size,
                  task->context.sp);
            
            /* Calculer l'espace utilise dans la stack */
            uint32_t stack_used = (uint32_t)task->stack_top - task->context.sp;
            uint32_t stack_free = task->stack_size - stack_used;
            
            /* Verifier la prochaine tache pour calculer l'ecart */
            task_t* next_task = task->next;
            if (next_task && next_task != start_task && next_task->stack_base) {
                uint32_t gap = (uint32_t)next_task->stack_base - (uint32_t)task->stack_top;
                KINFO("%-11d\n", (int)gap);
                
                /* Verifier les chevauchements */
                if ((uint32_t)task->stack_top > (uint32_t)next_task->stack_base) {
                    KINFO("        *** OVERLAP DETECTED! Stack collision! ***\n");
                }
            } else {
                KINFO("N/A\n");
            }
            
            /* Verifier les debordements de stack */
            if (task->context.sp < (uint32_t)task->stack_base) {
                KINFO("        *** STACK UNDERFLOW! SP below base! ***\n");
            }
            if (task->context.sp >= (uint32_t)task->stack_top) {
                KINFO("        *** STACK OVERFLOW! SP above top! ***\n");
            }
            
            /* Avertissement si stack presque pleine */
            if (stack_free < 512) {
                KINFO("        *** WARNING: Only %u bytes free in stack! ***\n", stack_free);
            }
            
            total_stack_memory += task->stack_size;
            count++;
        }
        
        task = task->next;
        
        /* Protection contre boucle infinie */
        if (count > 10) {
            KINFO("*** Loop detected, stopping dump ***\n");
            break;
        }
        
    } while (task && task != start_task);
    
    KINFO("\n=== Stack Summary ===\n");
    KINFO("Total tasks:      %d\n", count);
    KINFO("Total stack mem:  %u bytes (%u KB)\n", total_stack_memory, total_stack_memory / 1024);
    KINFO("Average per task: %u bytes\n", count > 0 ? total_stack_memory / count : 0);
    
    /* Afficher la tache courante */
    if (current_task) {
        KINFO("Current task:     %s (ID=%u)\n", current_task->name, current_task->task_id);
        KINFO("Current SP:       0x%08X\n", current_task->context.sp);
        
        /* Verifier la stack de la tache courante */
        if (current_task->context.sp < (uint32_t)current_task->stack_base ||
            current_task->context.sp >= (uint32_t)current_task->stack_top) {
            KINFO("*** CURRENT TASK HAS INVALID SP! ***\n");
        }
    }
    
    KINFO("========================\n");
}

void task_check_stack_integrity(void)
{
    task_t* task;
    task_t* start_task;
    int issues = 0;
    
    KINFO("=== Stack Integrity Check ===\n");
    
    if (!task_list_head) {
        KINFO("No tasks to check\n");
        return;
    }
    
    task = task_list_head;
    start_task = task_list_head;
    
    do {
        if (task && task->stack_base && task->stack_top) {
            /* Verifier l'alignement des adresses */
            if ((uint32_t)task->stack_base % 8 != 0) {
                KERROR("Task %s: Stack base not 8-byte aligned (0x%08X)\n", 
                       task->name, (uint32_t)task->stack_base);
                issues++;
            }
            
            /* Verifier la taille de stack */
            uint32_t actual_size = (uint32_t)task->stack_top - (uint32_t)task->stack_base;
            if (actual_size != task->stack_size) {
                KERROR("Task %s: Stack size mismatch (expected %u, actual %u)\n",
                       task->name, task->stack_size, actual_size);
                issues++;
            }
            
            /* Verifier SP dans les limites */
            if (task->context.sp < (uint32_t)task->stack_base) {
                KERROR("Task %s: SP underflow (SP=0x%08X, base=0x%08X)\n",
                       task->name, task->context.sp, (uint32_t)task->stack_base);
                issues++;
            }
            
            if (task->context.sp >= (uint32_t)task->stack_top) {
                KERROR("Task %s: SP overflow (SP=0x%08X, top=0x%08X)\n",
                       task->name, task->context.sp, (uint32_t)task->stack_top);
                issues++;
            }
            
            /* Verifier que PC est dans une zone valide */
            if (task->context.pc != 0 && task->context.pc < 0x40000000) {
                KERROR("Task %s: Invalid PC (PC=0x%08X)\n", 
                       task->name, task->context.pc);
                issues++;
            }
        }
        
        task = task->next;
        
    } while (task && task != start_task);
    
    if (issues == 0) {
        KINFO("OK Stack integrity check passed - no issues found\n");
    } else {
        KERROR("KO Stack integrity check failed - %d issues found\n", issues);
    }
    
    KINFO("=============================\n");
}

void task_list_all(void)
{
    task_t* task;
    int count = 0;
    
    KINFO("=== Task List ===\n");
    
    if (!scheduler_initialized) {
        KINFO("Scheduler not initialized\n");
        return;
    }
    
    KINFO("Current task: %s (ID=%u)\n", 
          current_task ? current_task->name : "none",
          current_task ? current_task->task_id : 0);
    
    spin_lock(&task_lock);
    
    task = task_list_head;
    if (task) {
        do {
            KINFO("  [%d] %s (ID=%u, state=%s, priority=%u)\n",
                  count, task->name, task->task_id, task_state_string(task->state), task->priority);
            task = task->next;
            count++;
        } while (task != task_list_head && count < 100);
    }
    
    spin_unlock(&task_lock);
    
    KINFO("Total tasks: %d\n", count);
}

void task_sleep_ms(uint32_t ms)
{
    /* Version amelioree qui cede le processeur */
    uint32_t iterations_per_ms = 10000;  /* Ajustez selon votre CPU */
    uint32_t total_iterations = ms * iterations_per_ms;
    uint32_t yield_interval = 1000;  /* Ceder toutes les 1000 iterations */
    
    for (volatile uint32_t i = 0; i < total_iterations; i++) {
        __asm__ volatile("nop");
        
        /* Ceder le processeur regulierement */
        if (i % yield_interval == 0) {
            //yield();
        }
    }
}

/**
 * Obtenir le nombre de taches
 */
uint32_t task_get_count(void)
{
    return task_count;
}

/**
 * Afficher les statistiques globales
 */
void task_print_stats(void)
{
    KINFO("=== Task Statistics ===\n");
    KINFO("Total tasks:     %u\n", task_count);
    KINFO("Max tasks:       %u\n", MAX_TASKS);
    KINFO("Current task:    %s\n", current_task ? current_task->name : "none");
    KINFO("Scheduler:       %s\n", scheduler_initialized ? "running" : "stopped");
    KINFO("Next task ID:    %u\n", next_task_id);
}




/* Fonctions de debug C a appeler depuis l'assembleur */
void debug_context_switch_entry(void)
{
    KDEBUG("ASM: Entering __task_switch_asm_debug\n");
}

void debug_context_switch_middle(void)
{
    KDEBUG("ASM: Context saved, about to restore\n");
}

void debug_context_switch_first_exec(void)
{
    KDEBUG("ASM: First execution path - jumping to function\n");
}

void debug_context_switch_restore(void)
{
    KDEBUG("ASM: Suspended task path - returning to yield point\n");
}

void debug_null_old_ctx(void)
{
    KDEBUG("ASM: NULL old_ctx, using first switch\n");
}

void debug_null_new_ctx(void)
{
    KERROR("ASM: NULL new_ctx - CRITICAL ERROR!\n");
}



/* 1. DIAGNOSTIC: Ajouter debug detaille */
void debug_task_detailed(task_t *current_task)
{
    KDEBUG("  current_task pointer: %p\n", current_task);
    
    if (!current_task) {
        KERROR("  KO current_task is NULL!\n");
        return;
    }
    
    /* Verifier que le pointeur est dans une zone valide */
    if ((uint32_t)current_task < 0x40000000 || (uint32_t)current_task > 0x50000000) {
        KERROR("  KO current_task pointer invalid: %p\n", current_task);
        return;
    }
    
    KDEBUG("  ***************************************************************\n");
    KDEBUG("  Task name: %s\n", current_task->name);
    KDEBUG("  Task ID: %u\n", current_task->task_id);
    KDEBUG("  ***************************************************************\n");
    KDEBUG("  KERNEL STACK ---\n");
    KDEBUG("  Context SP: 0x%08X\n", current_task->context.sp);
    KDEBUG("  Stack base: 0x%08X\n", (uint32_t)current_task->stack_base);
    KDEBUG("  Stack top:  0x%08X\n", (uint32_t)current_task->stack_top);
    KDEBUG("  is_first_run: %u\n", current_task->context.is_first_run);
    KDEBUG("  --------------------------\n");
    
    /* Verification des limites de stack */
    uint32_t sp = current_task->context.sp;
    uint32_t base = (uint32_t)current_task->stack_base;
    uint32_t top = (uint32_t)current_task->stack_top;
    
    if (sp >= base && sp < top) {
        KDEBUG("  OK KERNEL SP in valid range\n");
    } else {
        KERROR("  KO KERNEL SP OUT OF RANGE! (SP=0x%08X, range=0x%08X-0x%08X)\n", 
               sp, base, top);
    }

    if(current_task->process)
    {
        KDEBUG("  USER STACK ---\n");
        KDEBUG("  User SP: 0x%08X\n", current_task->context.usr_sp);
        KDEBUG("  User Stack base: 0x%08X\n", (uint32_t)current_task->process->vm->stack_start);
        KDEBUG("  User Stack top:  0x%08X\n", (uint32_t)current_task->process->vm->stack_start + USER_STACK_SIZE);
        KDEBUG("  --------------------------\n");
        
        /* Verification des limites de stack */
        sp = current_task->context.usr_sp;
        base = (uint32_t)current_task->process->vm->stack_start;
        top = (uint32_t)current_task->process->vm->stack_start + USER_STACK_SIZE;
        
        if (sp >= base && sp < top) {
            KDEBUG("  OK USER SP in valid range\n");
        } else {
            KERROR("  KO USER SP OUT OF RANGE! (SP=0x%08X, range=0x%08X-0x%08X)\n", 
                sp, base, top);
        }

    }

}


/* 1. DIAGNOSTIC: Ajouter debug detaille */
void debug_current_task_detailed(const char* location)
{
    KDEBUG("[%s] === current_task DEBUG ===\n", location);
    KDEBUG("  current_task pointer: %p\n", current_task);
    
    if (!current_task) {
        KERROR("  KO current_task is NULL!\n");
        return;
    }
    
    /* Verifier que le pointeur est dans une zone valide */
    if ((uint32_t)current_task < 0x40000000 || (uint32_t)current_task > 0x50000000) {
        KERROR("  KO current_task pointer invalid: %p\n", current_task);
        return;
    }
    
    KDEBUG("  Task name: %s\n", current_task->name);
    KDEBUG("  Task ID: %u\n", current_task->task_id);
    KDEBUG("  Context SP: 0x%08X\n", current_task->context.sp);
    KDEBUG("  Stack base: 0x%08X\n", (uint32_t)current_task->stack_base);
    KDEBUG("  Stack top:  0x%08X\n", (uint32_t)current_task->stack_top);
    KDEBUG("  is_first_run: %u\n", current_task->context.is_first_run);
    
    /* Verification des limites de stack */
    uint32_t sp = current_task->context.sp;
    uint32_t base = (uint32_t)current_task->stack_base;
    uint32_t top = (uint32_t)current_task->stack_top;
    
    if (sp >= base && sp < top) {
        KDEBUG("  OK SP in valid range\n");
    } else {
        KERROR("  KO SP OUT OF RANGE! (SP=0x%08X, range=0x%08X-0x%08X)\n", 
               sp, base, top);
    }
}

/* Fonction de debug pour tracer les registres */
void debug_context_registers(task_context_t* ctx, const char* moment)
{
    KDEBUG("[%s] Context registers:\n", moment);
    KDEBUG("  r0 (arg): 0x%08X (%d)\n", ctx->r0, ctx->r0);
    KDEBUG("  sp:       0x%08X\n", ctx->sp);
    KDEBUG("  lr:       0x%08X\n", ctx->lr);
    KDEBUG("  pc:       0x%08X\n", ctx->pc);
    KDEBUG("  cpsr:     0x%08X\n", ctx->cpsr);
    KDEBUG("  is_first: %u\n", ctx->is_first_run);
}

__attribute__((noinline))
void debug_print_sp()
{
    //uart_puts("\n\n[DEBUG_SP] =============================\n\n");
    uint32_t r0_val;
    uint32_t r3_val;
    
     __asm__ volatile(
        // Sauvegarder tous les registres dans les variables locales 
        "mov %0, r0\n"          // Charger r0 
        "mov %1, r3\n"          // Charger r0 
        : "=r"(r0_val), "=r"(r3_val)
        :
        : "r3"          // on prévient le compilateur que r3 est touché par l'asm
    ); 

/*     __asm__ volatile(
        // Sauvegarder tous les registres dans les variables locales 
        "mov %0, r0\n"          // Charger r0 
        : "=r"(r0_val)
        :
        : // Pas de registres clobbered car on les sauvegarde explicitement 
    );
 */

    debug_print_ctx((task_context_t *)r0_val);
    
    /* Maintenant afficher avec kprintf (les registres originaux sont intacts) */
    uart_puts("\n\nRegisters __task_switch_asm_debug:\n");
    uart_puts("  &next_task->context: ");
    uart_put_hex(r0_val);
    uart_puts("\n");
    uart_puts("  Traceur R3: ");
    uart_put_hex(r3_val);
    uart_puts("\n");

}

void debug_print_sp2()
{
    //uart_puts("\n\n[DEBUG_SP] =============================\n\n");
    uint32_t r0_val, r1_val, sp_val, pc_val, lr_val;
    
    __asm__ volatile(
        /* Sauvegarder tous les registres dans les variables locales */
        "mov %0, r0\n"          /* Sauvegarder r0 */
        "mov %1, r1\n"          /* Sauvegarder r1 */
        "mov %2, sp\n"          /* Sauvegarder sp */
        "mov %3, pc\n"          /* Sauvegarder pc (approximatif) */
        "mov %4, lr\n"          /* Sauvegarder lr */
        : "=r"(r0_val), "=r"(r1_val), "=r"(sp_val), "=r"(pc_val), "=r"(lr_val)
        :
        : /* Pas de registres clobbered car on les sauvegarde explicitement */
    );
    
    /* Maintenant afficher avec kprintf (les registres originaux sont intacts) */
    uart_puts("\n\nRegisters __task_first_switchV2:\n");
    uart_puts("  r0: ");
    uart_put_hex(r0_val);
    uart_puts("\n  r1: ");
    uart_put_hex(r1_val);
    uart_puts("\n  sp: ");
    uart_put_hex(sp_val);
    uart_puts("\n  pc: ");
    uart_put_hex(pc_val);
    uart_puts("\n  lr: ");
    uart_put_hex(lr_val);
    uart_puts("\n\n");

   //kprintf("  r1: 0x%08X\n", r1_val);
    //kprintf("  sp: 0x%08X\n", sp_val);
    //kprintf("  pc: 0x%08X (approx)\n", pc_val);
    //kprintf("  lr: 0x%08X\n", lr_val);
    //uart_puts("\n\n");
}

void debug_print_sp3()
{
    //uart_puts("\n\n[DEBUG_SP] =============================\n\n");
    uint32_t r0_val, r1_val, sp_val, pc_val, lr_val;
    
    __asm__ volatile(
        /* Sauvegarder tous les registres dans les variables locales */
        "mov %0, r0\n"          /* Sauvegarder r0 */
        "mov %1, r1\n"          /* Sauvegarder r1 */
        "mov %2, sp\n"          /* Sauvegarder sp */
        "mov %3, pc\n"          /* Sauvegarder pc (approximatif) */
        "mov %4, lr\n"          /* Sauvegarder lr */
        : "=r"(r0_val), "=r"(r1_val), "=r"(sp_val), "=r"(pc_val), "=r"(lr_val)
        :
        : /* Pas de registres clobbered car on les sauvegarde explicitement */
    );
    
    /* Maintenant afficher avec kprintf (les registres originaux sont intacts) */
    uart_puts("\n\nRegisters SWI HANDLER:\n");
    uart_puts("  r0: ");
    uart_put_hex(r0_val);
    uart_puts("\n  r1: ");
    uart_put_hex(r1_val);
    uart_puts("\n  sp: ");
    uart_put_hex(sp_val);
    uart_puts("\n  pc: ");
    uart_put_hex(pc_val);
    uart_puts("\n  lr: ");
    uart_put_hex(lr_val);
    uart_puts("\n\n");

   //kprintf("  r1: 0x%08X\n", r1_val);
    //kprintf("  sp: 0x%08X\n", sp_val);
    //kprintf("  pc: 0x%08X (approx)\n", pc_val);
    //kprintf("  lr: 0x%08X\n", lr_val);
    //uart_puts("\n\n");
}

void debug_print_ctx(task_context_t *context)
{
    if(!context)
        KWARN("debug_print_ctx: Input task is NULL\n");

    // r0.         0,
    // r1          4,
    // r2          8,
    // r3          12
    // r4          16
    // r5          20
    // r6          24
    // r7          28
    // r8          32
    // r9          36
    // r10         40
    // r11         44
    // r12         48
    
    /* Registres speciaux */
    // sp          52       // Stack Pointer 
    // lr          56       // Link Register 
    // pc;         60       // Program Counter 
    // cpsr;       64       // Current Program Status Register 
    
    // is_first_run; 68.     // NOUVEAU: Flag pour premiere execution 
    // ttbr0;      72
    // asid;       76

    // spsr;       80        // SPSR_svc 
    // returns_to_user;  84  // has to return to user mode 

    // usr_r[0];     88      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[1];     92      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[2];     96      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[3];     100      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[4];     104      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[5];     108      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[6];     112      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[7];     116      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[8];     120      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[9];     124      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[10];    128      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[11];    132      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[12];    136      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_sp;       140
    // usr_lr;       144         // optionnel si tu l’utilises
    // usr_pc;       148         // point de reprise user
    // usr_cpsr;     152        // en général 0x10
    // svc_sp_top;   156        // haut de pile noyau allouée pour ce task
    // svc_sp;       160        // courant (si tu le tiens à jour)
    // svc_lr_saved; 164        // si tu en as besoin

    
    /* Maintenant afficher avec kprintf (les registres originaux sont intacts) */
    kprintf("Current Task (0x%08X) saved Context:\n", (uint32_t)context);
    kprintf("  r0: 0x%08X\n", context->r0);
    kprintf("  r1: 0x%08X\n", context->r1);
    kprintf("  r2: 0x%08X\n", context->r2);
    kprintf("  r3: 0x%08X\n", context->r3);
    kprintf("  r4: 0x%08X\n", context->r4);
    kprintf("  r5: 0x%08X\n", context->r5);
    kprintf("  r6: 0x%08X\n", context->r6);
    kprintf("  r7: 0x%08X\n", context->r7);
    kprintf("  r8: 0x%08X\n", context->r8);
    kprintf("  r9: 0x%08X\n", context->r9);
    kprintf("  r10: 0x%08X\n", context->r10);
    kprintf("  r11: 0x%08X\n", context->r11);
    kprintf("  r12: 0x%08X\n", context->r12);
    kprintf("  SP: 0x%08X\n", context->sp);
    kprintf("  LR: 0x%08X\n", context->lr);
    kprintf("  PC: 0x%08X\n", context->pc);
    kprintf("  CPSR: 0x%02X\n", context->cpsr /*& 0x1F*/);
    kprintf("  IS FIRST RUN: 0x%01X\n", context->is_first_run);
    kprintf("  TTBR0: 0x%08X\n", context->ttbr0);
    kprintf("  ASID: 0x%03X\n", context->asid);
    kprintf("  SPSR: 0x%02X\n", context->spsr & 0x1F);
    kprintf("  RETURNS TO USER: 0x%01X\n", context->returns_to_user);

    for(int i = 0 ; i < 13 ; i++)
    {
        kprintf("  usr_r[%d]: 0x%08X\n", i, context->usr_r[i]);
    }

    kprintf("  USR SP: 0x%08X\n", context->usr_sp);
    kprintf("  USR LR: 0x%08X\n", context->usr_lr);
    kprintf("  USR PC: 0x%08X\n", context->usr_pc);
    kprintf("  USR CPSR: 0x%02X\n", context->usr_cpsr /*& 0x1F*/);

    kprintf("  SVC SP TOP: 0x%08X\n", context->svc_sp_top);
    kprintf("  SVC SP: 0x%08X\n", context->svc_sp);
    kprintf("  SVC LR SAVED : 0x%08X\n", context->svc_lr_saved);
}

__attribute__((noinline))
void debug_return_snapshot(task_context_t *ctx, uint32_t spsr, uint32_t usr_pc, uint32_t tracer) {
    uart_puts("\n-- Return-to-user snapshot --\n");
    uart_puts("ctx="); uart_put_hex((uint32_t)ctx);
    uart_puts(" tracer="); uart_put_hex(tracer); uart_puts("\n");
    uart_puts("SPSR="); uart_put_hex(spsr);
    uart_puts(" (mode="); uart_put_hex(spsr & 0x1F);
    uart_puts(" T="); uart_put_dec((spsr>>5)&1); uart_puts(")\n");
    uart_puts("LR_svc(next) = "); uart_put_hex(usr_pc); uart_puts("\n");
}


void debug_print_task(task_t *task_in)
{
    task_t *task = NULL;
    if(task_in)
        task = task_in;
    else
        task = get_current_task();

    if(!task)
        KWARN("debug_print_ctx: Input task is NULL\n");

    // r0.         0,
    // r1          4,
    // r2          8,
    // r3          12
    // r4          16
    // r5          20
    // r6          24
    // r7          28
    // r8          32
    // r9          36
    // r10         40
    // r11         44
    // r12         48
    
    /* Registres speciaux */
    // sp          52       // Stack Pointer 
    // lr          56       // Link Register 
    // pc;         60       // Program Counter 
    // cpsr;       64       // Current Program Status Register 
    
    // is_first_run; 68.     // NOUVEAU: Flag pour premiere execution 
    // ttbr0;      72
    // asid;       76

    // spsr;       80        // SPSR_svc 
    // returns_to_user;  84  // has to return to user mode 

    // usr_r[0];     88      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[1];     92      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[2];     96      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[3];     100      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[4];     104      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[5];     108      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[6];     112      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[7];     116      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[8];     120      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[9];     124      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[10];    128      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[11];    132      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_r[12];    136      // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    // usr_sp;       140
    // usr_lr;       144         // optionnel si tu l’utilises
    // usr_pc;       148         // point de reprise user
    // usr_cpsr;     152        // en général 0x10
    // svc_sp_top;   156        // haut de pile noyau allouée pour ce task
    // svc_sp;       160        // courant (si tu le tiens à jour)
    // svc_lr_saved; 164        // si tu en as besoin

    
    /* Maintenant afficher avec kprintf (les registres originaux sont intacts) */
    kprintf("Current Task (%s) saved Context:\n", task->name);
    kprintf("  r0: 0x%08X\n", task->context.r0);
    kprintf("  r1: 0x%08X\n", task->context.r1);
    kprintf("  r2: 0x%08X\n", task->context.r2);
    kprintf("  r3: 0x%08X\n", task->context.r3);
    kprintf("  r4: 0x%08X\n", task->context.r4);
    kprintf("  r5: 0x%08X\n", task->context.r5);
    kprintf("  r6: 0x%08X\n", task->context.r6);
    kprintf("  r7: 0x%08X\n", task->context.r7);
    kprintf("  r8: 0x%08X\n", task->context.r8);
    kprintf("  r9: 0x%08X\n", task->context.r9);
    kprintf("  r10: 0x%08X\n", task->context.r10);
    kprintf("  r11: 0x%08X\n", task->context.r11);
    kprintf("  r12: 0x%08X\n", task->context.r12);
    kprintf("  SP: 0x%08X\n", task->context.sp);
    kprintf("  LR: 0x%08X\n", task->context.lr);
    kprintf("  PC: 0x%08X\n", task->context.pc);
    kprintf("  CPSR: 0x%02X\n", task->context.cpsr & 0x1F);
    kprintf("  IS FIRST RUN: 0x%01X\n", task->context.is_first_run);
    kprintf("  TTBR0: 0x%08X\n", task->context.ttbr0);
    kprintf("  ASID: 0x%03X\n", task->context.asid);
    kprintf("  SPSR: 0x%02X\n", task->context.spsr & 0x1F);
    kprintf("  RETURNS TO USER: 0x%01X\n", task->context.returns_to_user);

    for(int i = 0 ; i < 13 ; i++)
    {
        kprintf("  usr_r[%d]: 0x%08X\n", i, task->context.usr_r[i]);
    }

    kprintf("  USR SP: 0x%08X\n", task->context.usr_sp);
    kprintf("  USR LR: 0x%08X\n", task->context.usr_lr);
    kprintf("  USR PC: 0x%08X\n", task->context.usr_pc);
    kprintf("  USR CPSR: 0x%02X\n", task->context.usr_cpsr & 0x1F);

    kprintf("  SVC SP TOP: 0x%08X\n", task->context.svc_sp_top);
    kprintf("  SVC SP: 0x%08X\n", task->context.svc_sp);
    kprintf("  SVC LR SAVED : 0x%08X\n", task->context.svc_lr_saved);
 
   //kprintf("  r1: 0x%08X\n", r1_val);
    //kprintf("  sp: 0x%08X\n", sp_val);
    //kprintf("  pc: 0x%08X (approx)\n", pc_val);
    //kprintf("  lr: 0x%08X\n", lr_val);
    //uart_puts("\n\n");
}

/**
 * Ajouter un processus a la queue des prets - utilisant vos fonctions
 */
void add_to_ready_queue(task_t* task)
{
    if (!task) return;

    /* Ne pas ajouter les zombies a la ready queue */
    if (task->state == TASK_ZOMBIE || task->state == TASK_TERMINATED) {
        //KDEBUG("add_to_ready_queue: Ignoring zombie/terminated task %s\n", 
        //       task->name);
        return;
    }
    
    /* Verifier si deja dans la queue */
    if (is_in_ready_queue(task)) {
        //KDEBUG("add_to_ready_queue: Task %s already in ready queue\n", 
        //       task->name);
        return;
    }

    
    spin_lock(&task_lock);
    
    if (task->state != TASK_READY) {
        task->state = TASK_READY;
    }
    
    spin_unlock(&task_lock);
    
    /* Si pas encore dans la liste, l'ajouter avec votre fonction */
    if (!task->next && !task->prev && task != task_list_head) {
        add_task_to_list(task);
    }
    
    //KDEBUG("add_to_ready_queue: Task %s added to ready queue\n", task->name);
}

/**
 * Version securisee avec verifications supplementaires
 */
void remove_from_ready_queue(task_t* task)
{
    if (!task) {
        KERROR("remove_from_ready_queue: NULL task\n");
        return;
    }
    
    //KDEBUG("remove_from_ready_queue: Marking task %s as non-ready\n", task->name);
    spin_lock(&task_lock);

    /*  Simplement marquer comme non-READY */
    /* Le scheduler ignorera automatiquement cette tache */
    if (task->state == TASK_READY) {
        task->state = TASK_ZOMBIE;  /* ou autre etat approprie */
    }
    
    spin_unlock(&task_lock);

    //KDEBUG("remove_from_ready_queue: Task %s marked as zombie (state=%d)\n", 
    //       task->name, task->state);
}

/**
 * Supprime definitivement un processus zombie du systeme
 * (appelee depuis sys_waitpid apres recolte)
 */
void destroy_zombie_process(task_t* zombie)
{
    if (!zombie || !zombie->process) {
        KERROR("destroy_zombie_process: NULL zombie\n");
        return;
    }
    
    //KDEBUG("destroy_zombie_process: Destroying zombie %s (PID=%u)\n", 
    //       zombie->name, zombie->process->pid);
    
    /* Maintenant on peut vraiment le retirer de la liste */
    remove_task_from_list(zombie);
    
    /* Liberer les ressources */
    if (zombie->process->vm) {
        destroy_vm_space(zombie->process->vm);
        zombie->process->vm = NULL;
    }
    
    if (zombie->stack_base) {
        kfree(zombie->stack_base);
        zombie->stack_base = NULL;
    }
    
    /* Marquer comme completement mort */
    zombie->state = TASK_TERMINATED;
    zombie->process->state = (proc_state_t)PROC_DEAD;
    
    /* Liberer la structure (optionnel, ou garder pour debug) */
    /* kfree(zombie); */
    
    KDEBUG("destroy_zombie_process: Zombie %s destroyed\n", zombie->name);
}

/**
 * Version avec debug et verifications d'integrite
 */
bool is_in_ready_queue(task_t* task)
{
    if (!task) {
        KERROR("is_in_ready_queue: NULL task\n");
        return false;
    }
    
    /* Verification de base de l'etat */
    if (task->state != TASK_READY) {
        //KDEBUG("is_in_ready_queue: Task %s not READY (state=%d)\n", 
        //       task->name, task->state);
        return false;
    }
    
    /* Si pas de liste, aucune tache ne peut y etre */
    if (!task_list_head) {
        //KDEBUG("is_in_ready_queue: No task list\n");
        return false;
    }
    
    /* Verification d'integrite de base de la tache */
    if (!task->next || !task->prev) {
        //KDEBUG("is_in_ready_queue: Task %s has NULL links (next=%p, prev=%p)\n", 
        //       task->name, task->next, task->prev);
        return false;
    }
    
    /* Parcours de la liste circulaire */
    task_t* current = task_list_head;
    task_t* start = current;
    int count = 0;
    
    do {
        if (current == task) {
            //KDEBUG("is_in_ready_queue: Task %s found in list (position %d)\n", 
            //       task->name, count);
            return true;
        }
        
        /* Verification d'integrite pendant le parcours */
        if (!current->next) {
            //KERROR("is_in_ready_queue: Broken list - NULL next at task %s\n", 
            //       current->name);
            return false;
        }
        
        current = current->next;
        count++;
        
        if (count >= MAX_TASKS) {
            KERROR("is_in_ready_queue: List too long or corrupted (>%d tasks)\n", 
                   MAX_TASKS);
            return false;
        }
        
    } while (current != start);
    
    //KDEBUG("is_in_ready_queue: Task %s not found in list (%d tasks checked)\n", 
    //       task->name, count);
    return false;
}

void debug_all_task_stacks(void)
{
    KINFO("=== DIAGNOSTIC TOUTES LES PILES ===\n");
    
    KINFO("Pile KERNEL:\n");
    KINFO("  Bottom: 0x%08X\n", (uint32_t)&__stack_bottom);
    KINFO("  Top:    0x%08X\n", (uint32_t)&__stack_top);
    KINFO("  Size:   %u bytes\n", (uint32_t)&__stack_top - (uint32_t)&__stack_bottom);
    
    task_t* task = task_list_head;
    if (!task) return;
    
    do {
        KINFO("Tache %s:\n", task->name);
        KINFO("  Stack base: 0x%08X\n", (uint32_t)task->stack_base);
        KINFO("  Stack top:  0x%08X\n", (uint32_t)task->stack_top);
        KINFO("  Stack size: %u bytes\n", task->stack_size);
        KINFO("  Context SP: 0x%08X\n", task->context.sp);
        
        /* Vérifier chevauchement avec pile kernel */
        uint32_t task_start = (uint32_t)task->stack_base;
        uint32_t task_end = (uint32_t)task->stack_top;
        uint32_t kernel_start = (uint32_t)&__stack_bottom;
        uint32_t kernel_end = (uint32_t)&__stack_top;
        
        if ((task_start < kernel_end && task_end > kernel_start)) {
            KERROR("  KO CONFLIT avec pile kernel !\n");
        } else {
            KINFO("  OK Pas de conflit\n");
        }
        
        task = task->next;
    } while (task != task_list_head);
}