/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/task/task.c
 * Layer: Kernel / scheduler and tasking
 *
 * Responsibilities:
 * - Create, schedule, block, wake, and destroy tasks.
 * - Track scheduling and lifecycle diagnostics.
 *
 * Notes:
 * - Scheduler invariants are shared with timer preemption and wait paths.
 */

#include <kernel/task.h>
#include <kernel/memory.h>
#include <kernel/kernel.h>
#include <kernel/kprintf.h>
#include <kernel/string.h>
#include <kernel/uart.h>
#include <kernel/tty.h>
#include <kernel/syscalls.h>
#include <kernel/signal.h>
#include <kernel/timer.h>
#include <kernel/process.h>
#include <asm/arm.h>
#include <kernel/file.h>

_Static_assert(offsetof(task_t, context) == 48,
               "task_t.context offset must match syscall.S/task_switch.S");
_Static_assert(sizeof(task_context_t) == 168,
               "task_context_t layout must match task_switch.S offsets");

//const uint32_t TASK_CONTEXT_OFF = offsetof(task_t, context);

/* Variables globales du scheduler */
task_t* current_task = NULL;
task_t* task_list_head = NULL;
typedef struct runqueue {
    task_t* head[TASK_PRIORITY_LEVELS];
    task_t* tail[TASK_PRIORITY_LEVELS];
    uint32_t count[TASK_PRIORITY_LEVELS];
    uint32_t nr_running;
} runqueue_t;

static runqueue_t ready_queue;
static uint32_t next_task_id = 1;
static uint32_t next_pid = 1;
uint32_t task_count = 0;
static bool scheduler_initialized = false;
DEFINE_SPINLOCK(task_lock);

volatile int need_resched = 0;

//static spinlock_t task_lock = {0};

/* Tache idle et processus init */
task_t* idle_task = NULL;
task_t* init_process = NULL;
volatile kernel_lifecycle_stats_t kernel_lifecycle_stats;
static spinlock_t sched_trace_lock = SPINLOCK_INIT("sched_trace");
static sched_trace_event_t sched_trace[SCHED_TRACE_SIZE];
static uint32_t sched_trace_seq;
static uint32_t sched_aging_selections;
//static int yield_count = 0;

/* === NOUVELLES VARIABLES POUR PROCESSUS === */
//task_t* current_process = NULL;  /* Alias vers current_task */

/* Forward declarations */
void idle_task_func(void* arg);
void init_process_main(void* arg);
static task_t* schedule_next_task(void);
static bool task_stack_metadata_valid(task_t* task);
static bool task_is_schedulable(task_t* task);
static bool runqueue_contains_locked(task_t* task);
static void runqueue_enqueue_tail_locked(task_t* task);
static void runqueue_remove_locked(task_t* task);
static void runqueue_clear_locked(void);
static void task_make_ready_locked(task_t* task);
void add_task_to_list(task_t* task);
void remove_task_from_list(task_t* task);
void setup_task_context(task_t* task);
bool is_in_ready_queue(task_t* task);

uint64_t task_runtime_ticks(task_t* task)
{
    if (!task)
        return 0;

    return task->total_runtime;
}

static uint32_t task_trace_pid(task_t* task)
{
    return (task && task->type == TASK_TYPE_PROCESS && task->process)
        ? (uint32_t)task->process->pid
        : 0;
}

void sched_trace_record(sched_trace_event_type_t event, task_t* task)
{
    unsigned long flags;
    sched_trace_event_t* dst;

    spin_lock_irqsave(&sched_trace_lock, &flags);
    dst = &sched_trace[sched_trace_seq % SCHED_TRACE_SIZE];
    memset(dst, 0, sizeof(*dst));
    dst->seq = sched_trace_seq + 1;
    dst->tick = get_system_ticks();
    dst->event = event;
    dst->syscall = task ? task->current_syscall : 0;
    dst->pid = task_trace_pid(task);
    dst->tid = task ? task->task_id : 0;
    dst->state = task ? (uint32_t)task->state : 0xffffffffu;
    dst->wakeup_time = task ? task->wakeup_time : 0;
    dst->current_pid = task_trace_pid(current_task);
    dst->current_tid = current_task ? current_task->task_id : 0;
    dst->current_syscall = current_task ? current_task->current_syscall : 0;
    dst->task_ptr = (uintptr_t)task;
    dst->next_ptr = task ? (uintptr_t)task->next : 0;
    dst->prev_ptr = task ? (uintptr_t)task->prev : 0;
    if (task)
        strncpy(dst->name, task->name, TASK_NAME_MAX - 1);
    if (current_task)
        strncpy(dst->current_name, current_task->name, TASK_NAME_MAX - 1);
    sched_trace_seq++;
    spin_unlock_irqrestore(&sched_trace_lock, flags);
}

void sched_trace_snapshot(sched_trace_event_t* out, uint32_t max,
                          uint32_t* total, uint32_t* written)
{
    unsigned long flags;
    uint32_t seq;
    uint32_t count;
    uint32_t start;

    if (total)
        *total = 0;
    if (written)
        *written = 0;
    if (!out || max == 0)
        return;

    spin_lock_irqsave(&sched_trace_lock, &flags);
    seq = sched_trace_seq;
    count = seq < SCHED_TRACE_SIZE ? seq : SCHED_TRACE_SIZE;
    if (count > max)
        count = max;
    start = seq >= count ? seq - count : 0;

    for (uint32_t i = 0; i < count; i++)
        out[i] = sched_trace[(start + i) % SCHED_TRACE_SIZE];

    spin_unlock_irqrestore(&sched_trace_lock, flags);

    if (total)
        *total = seq;
    if (written)
        *written = count;
}

void scheduler_get_stats(scheduler_stats_t* stats)
{
    unsigned long flags;
    process_t* proc;

    if (!stats)
        return;

    memset(stats, 0, sizeof(*stats));

    spin_lock_irqsave(&task_lock, &flags);

    stats->nr_running = ready_queue.nr_running;
    stats->policy_levels = TASK_PRIORITY_LEVELS;
    stats->default_priority = TASK_DEFAULT_PRIORITY;
    stats->idle_priority = TASK_IDLE_PRIORITY;
    stats->nice_min = TASK_NICE_MIN;
    stats->nice_max = TASK_NICE_MAX;
    stats->quantum_ticks = QUANTUM_TICKS;
    stats->aging_step_ticks = SCHED_AGING_STEP_TICKS;
    stats->aging_max_bonus = SCHED_AGING_MAX_BONUS;
    stats->aging_selections = sched_aging_selections;
    stats->highest_ready_priority = TASK_PRIORITY_LEVELS;
    stats->lowest_ready_priority = TASK_PRIORITY_LEVELS;

    for (uint32_t prio = 0; prio < TASK_PRIORITY_LEVELS; prio++) {
        stats->priority_counts[prio] = ready_queue.count[prio];
        if (ready_queue.count[prio] > 0) {
            stats->nonempty_queues++;
            if (stats->highest_ready_priority == TASK_PRIORITY_LEVELS)
                stats->highest_ready_priority = prio;
            stats->lowest_ready_priority = prio;
        }
    }

    if (current_task) {
        proc = (current_task->type == TASK_TYPE_PROCESS) ? current_task->process : NULL;
        stats->current_tid = current_task->task_id;
        stats->current_pid = proc ? (uint32_t)proc->pid : 0;
        stats->current_priority = current_task->priority;
        strncpy(stats->current_name, current_task->name, TASK_NAME_MAX - 1);
    }

    spin_unlock_irqrestore(&task_lock, flags);
}

void debug_context_switch_entry(void);
void debug_context_switch_middle(void);
void debug_context_switch_first_exec(void);
void debug_context_switch_restore(void);
void debug_null_old_ctx(void);
void debug_null_new_ctx(void);
void debug_context_registers(task_context_t* ctx, const char* moment);
void debug_task_detailed(task_t *current_task);

void debug_print_ctx(task_context_t *context, const char* caller);
void debug_return_snapshot(task_context_t *ctx, uint32_t spsr, uint32_t usr_pc, uint32_t tracer);


/* Fonctions assembleur externes */
extern void __task_first_switch_v2(task_context_t* new_ctx);
extern void __task_switch_asm_debug(task_context_t* old_ctx, task_context_t* new_ctx);
extern void __task_switch(task_context_t* old_ctx, task_context_t* new_ctx);
extern void print_system_stats(void);


uid_t current_uid(void) {
    if (current_task && current_task->process) {
        return current_task->process->uid;
    }
    return 0;  /* Root par défaut */
}

uid_t current_gid(void) {
    if (current_task && current_task->process) {
        return current_task->process->gid;
    }
    return 0;  /* Root group par défaut */
}

static bool task_stack_metadata_valid(task_t* task)
{
    if (!task || !task->stack_base || !task->stack_top || task->stack_size == 0) {
        return false;
    }

    if (task->stack_top != (uint8_t*)task->stack_base + task->stack_size) {
        KERROR("TASK: %s stack metadata inconsistent base=%p top=%p size=%u\n",
               task->name, task->stack_base, task->stack_top, task->stack_size);
        return false;
    }

    if (task->context.sp < (uint32_t)task->stack_base ||
        task->context.sp >= (uint32_t)task->stack_top) {
        KERROR("TASK: %s context SP 0x%08X outside stack 0x%08X-0x%08X\n",
               task->name, task->context.sp,
               (uint32_t)task->stack_base, (uint32_t)task->stack_top);
        return false;
    }

    return true;
}

static bool task_kernel_sp_valid(task_t* task, uint32_t sp)
{
    if (!task || !task->stack_base || !task->stack_top) {
        return false;
    }

    return sp >= (uint32_t)task->stack_base &&
           sp < (uint32_t)task->stack_top;
}

static bool task_is_schedulable(task_t* task)
{
    if (!task) {
        return false;
    }

    if (task->state != TASK_READY) {
        return false;
    }

    return task_stack_metadata_valid(task);
}

static bool runqueue_contains_locked(task_t* task)
{
    return task && task->rq_priority < TASK_PRIORITY_LEVELS;
}

static uint32_t task_runqueue_priority(task_t* task)
{
    if (!task)
        return TASK_PRIORITY_LEVELS - 1;

    if (task->priority >= TASK_PRIORITY_LEVELS)
        return TASK_PRIORITY_LEVELS - 1;

    return task->priority;
}

static void runqueue_enqueue_tail_locked(task_t* task)
{
    uint32_t prio;

    if (!task || task == idle_task || runqueue_contains_locked(task))
        return;

    prio = task_runqueue_priority(task);
    task->ready_since_tick = get_system_ticks();
    task->rq_next = NULL;
    task->rq_prev = ready_queue.tail[prio];
    task->rq_priority = prio;

    if (ready_queue.tail[prio])
        ready_queue.tail[prio]->rq_next = task;
    else
        ready_queue.head[prio] = task;

    ready_queue.tail[prio] = task;
    ready_queue.count[prio]++;
    ready_queue.nr_running++;
}

static void runqueue_remove_locked(task_t* task)
{
    uint32_t prio;

    if (!task || !runqueue_contains_locked(task))
        return;

    prio = task->rq_priority;
    if (prio >= TASK_PRIORITY_LEVELS) {
        task->rq_next = NULL;
        task->rq_prev = NULL;
        task->rq_priority = TASK_PRIORITY_LEVELS;
        return;
    }

    if (task->rq_prev)
        task->rq_prev->rq_next = task->rq_next;
    else
        ready_queue.head[prio] = task->rq_next;

    if (task->rq_next)
        task->rq_next->rq_prev = task->rq_prev;
    else
        ready_queue.tail[prio] = task->rq_prev;

    task->rq_next = NULL;
    task->rq_prev = NULL;
    task->rq_priority = TASK_PRIORITY_LEVELS;
    task->ready_since_tick = 0;
    if (ready_queue.count[prio] > 0)
        ready_queue.count[prio]--;
    if (ready_queue.nr_running > 0)
        ready_queue.nr_running--;
}

static void runqueue_clear_locked(void)
{
    memset(&ready_queue, 0, sizeof(ready_queue));
}

static void task_make_ready_locked(task_t* task)
{
    if (!task || task->state == TASK_ZOMBIE || task->state == TASK_TERMINATED)
        return;

    task->state = TASK_READY;
    if (task->type == TASK_TYPE_PROCESS && task->process)
        task->process->state = (proc_state_t)PROC_READY;

    runqueue_enqueue_tail_locked(task);
}

#define KERNEL_TASK_STACK_PAGES \
    ((KERNEL_TASK_STACK_SIZE + PAGE_SIZE - 1) / PAGE_SIZE)

static void *kstack_alloc(void)
{
    void *p = allocate_pages(KERNEL_TASK_STACK_PAGES);
    if (p)
        memset(p, 0, KERNEL_TASK_STACK_SIZE);
    return p;
}

static void kstack_free(void *p)
{
    if (p)
        free_pages(p, KERNEL_TASK_STACK_PAGES);
}

static bool task_alloc_kernel_stack(task_t *task)
{
    if (!task)
        return false;

    task->stack_base = kstack_alloc();
    if (!task->stack_base)
        return false;

    task->stack_size = KERNEL_TASK_STACK_SIZE;
    task->stack_top = (uint8_t *)task->stack_base + task->stack_size;
    kernel_lifecycle_stats.stack_pages_allocated += KERNEL_TASK_STACK_PAGES;
    return true;
}

void task_free_kernel_stack(task_t *task)
{
    if (!task || !task->stack_base)
        return;

    kstack_free(task->stack_base);
    task->stack_base = NULL;
    task->stack_top = NULL;
    task->stack_size = 0;
    kernel_lifecycle_stats.stack_pages_freed += KERNEL_TASK_STACK_PAGES;
}


// Construit une pile noyau "propre" pour un PROCESS (utile pour from_user=true)
static void build_clean_kernel_stack(task_t *t)
{
    if(!t->stack_base && !task_alloc_kernel_stack(t))
        return;

    // SP noyau posé près du top (garde 512B pour sentinelles/debug si tu veux)
    t->context.svc_sp_top = (uint32_t)t->stack_top;
    t->context.svc_sp     = ((uint32_t)t->stack_top - 512) & ~7u;
    t->context.sp         = t->context.svc_sp;
    t->context.sp         = t->context.svc_sp;  // sp = SP_svc dans ton design
}


task_t* set_process_stack(task_t* parent, task_t* child, bool from_user)
{
    /* Allouer une nouvelle pile */
    if (!task_alloc_kernel_stack(child)) {
        KERROR("task_create_copy: Failed to allocate child stack\n");
        //kfree(child);
        return NULL;
    }

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
            
            //KDEBUG("Parent stack analysis:\n");
            //KDEBUG("  Parent stack: %p - %p\n", parent->stack_base, (uint8_t*)parent->stack_base + parent->stack_size);
            //KDEBUG("  Parent SP: 0x%08X\n", parent->context.sp);
            //KDEBUG("  Offset from top: %u bytes\n", parent_sp_offset_from_top);
            
            /* Verifier que le SP parent est valide AVANT de copier */
            if (parent->context.sp < (uint32_t)parent->stack_base || 
                parent->context.sp >= parent_stack_top) {
                //KERROR("task_create_copy: Parent SP invalid! Cannot copy stack\n");
                //KERROR("  Parent SP: 0x%08X, Range: %p - 0x%08X\n", 
                //    parent->context.sp, parent->stack_base, parent_stack_top);
                
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
    child->context.svc_sp &= ~7;

    return child;

}

/**
 * Creer une copie d'une tache pour fork()
 */
task_t* task_create_copy(task_t* parent, bool from_user)
{
    task_t* child;
    unsigned long flags;
    
    if (!parent || !parent->process) {
        KERROR("task_create_copy: parent NULL\n");
        KERROR("task_create_copy: Parent NULL Proc\n");
        return NULL;
    }

    spin_lock_irqsave(&task_lock, &flags);
    if (task_count >= MAX_TASKS) {
        spin_unlock_irqrestore(&task_lock, flags);
        KERROR("task_create_copy: Maximum task count reached (%d)\n", MAX_TASKS);
        return NULL;
    }
    spin_unlock_irqrestore(&task_lock, flags);
    
    /* Allouer la structure de tache */
    child = (task_t*)kmalloc(sizeof(task_t));
    if (!child) {
        KERROR("task_create_copy: Failed to allocate child task\n");
        return NULL;
    }

    /* Copier la structure parent */
    memcpy(child, parent, sizeof(task_t));
    
    /* Reinitialiser les champs specifiques a l'enfant */
    child->task_id = next_task_id++;
    strncpy(child->name, parent->name, TASK_NAME_MAX - 1);
    child->name[TASK_NAME_MAX - 1] = '\0';
    
    if(!set_process_stack(parent,child, from_user)) {
        kfree(child);
        return NULL;
    }

    /* Configuration processus pour l'enfant */
    if (parent->type == TASK_TYPE_PROCESS) {

        child->process = (process_t *)kmalloc(sizeof(process_t));
        if(child->process){
            child->type = TASK_TYPE_PROCESS;
            child->process->pid = next_pid++;
            child->process->ppid = parent->process->pid;
            child->process->pgid = parent->process->pgid;
            child->process->sid = parent->process->sid;
            child->process->controlling_tty = parent->process->controlling_tty;
            child->process->parent = parent;
            child->process->children = NULL;
            child->process->sibling_next = NULL;
            child->process->exit_code = 0;
            child->process->term_signal = 0;
            child->process->stop_signal = 0;
            child->process->stop_reported = 0;
            child->process->uid = parent->process->uid;
            child->process->gid = parent->process->gid;
            child->process->umask = parent->process->umask;
            child->process->state = (proc_state_t)PROC_READY;
            strcpy(child->process->cwd, parent->process->cwd);    // Setting Current Working Directory
            strcpy(child->process->exe_path, parent->process->exe_path);
            memcpy(child->process->cmdline, parent->process->cmdline, sizeof(child->process->cmdline));
            child->process->cmdline_len = parent->process->cmdline_len;
            memcpy(child->process->environ, parent->process->environ, sizeof(child->process->environ));
            child->process->environ_len = parent->process->environ_len;
            
            /* Initialiser la table des fichiers (sera copiee plus tard) */
            memset(child->process->files, 0, sizeof(child->process->files));
            memset(child->process->fd_flags, 0, sizeof(child->process->fd_flags));
            
            /* La VM sera copiee avec COW dans sys_fork() */
            child->process->vm = NULL;

            child->process->waitpid_pid = 0;
            child->process->waitpid_status = NULL;
            child->process->waitpid_options = 0;
            child->process->waitpid_iteration = 0;
            child->process->waitpid_caller_lr = 0;

        }
        else {
            task_free_kernel_stack(child);
            kfree(child);
            panic("Task Create Copy - cannot allocate Process Structure");
        }
    } else {
        /* Pour les threads kernel, garder le meme type */
        child->type = parent->type;
    }
    
    /* etat initial */
    child->state = TASK_READY;
    child->next = NULL;
    child->prev = NULL;
    child->rq_next = NULL;
    child->rq_prev = NULL;
    child->rq_priority = TASK_PRIORITY_LEVELS;
    
    /* Statistiques */
    child->created_time = get_current_time();
    child->total_runtime = 0;
    child->switch_count = 0;
    child->context.is_first_run = 1;
    child->context.r0 = 0;
    child->wakeup_time = 0;
    child->quantum_left = QUANTUM_TICKS;

    kernel_lifecycle_stats.tasks_created++;
    return child;
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
    
    if (current_sp < (uint32_t)idle_task->stack_base || 
        current_sp >= (uint32_t)idle_task->stack_top) {
        panic("Failed to switch to idle stack");
    }
    
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
    runqueue_clear_locked();
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
    runqueue_clear_locked();
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
    if (!task_alloc_kernel_stack(task)) {
        KERROR("task_create: Failed to allocate stack\n");
        kfree(task);
        return NULL;
    }
    
    /* Initialiser la structure */
    task->task_id = next_task_id++;
    strncpy(task->name, name ? name : "unnamed", TASK_NAME_MAX - 1);
    task->name[TASK_NAME_MAX - 1] = '\0';
    
    task->state = TASK_READY;
    task->priority = priority;
    
    task->entry_point = entry;
    task->entry_arg = arg;
    
    task->next = NULL;
    task->prev = NULL;
    task->rq_next = NULL;
    task->rq_prev = NULL;
    task->rq_priority = TASK_PRIORITY_LEVELS;
    
    /* Statistiques */
    task->created_time = 0;
    task->total_runtime = 0;
    task->switch_count = 0;
    task->page_faults = 0;
    task->cow_faults = 0;
    task->stack_faults = 0;

    task->type = TASK_TYPE_PROCESS;  /* Nouvelle ligne */
    //task->process->pid = task->task_id;  /* Nouvelle ligne */
    task->context.is_first_run = 1;
    
    /* === CONFIGURATION CORRIGeE DU CONTEXTE === */
    setup_task_context(task);

    task->context.svc_sp_top = (uint32_t)task->stack_top;
    task->context.svc_sp = ((uint32_t)task->stack_top - 512) & ~7u;
    task->context.sp = task->context.svc_sp;

    task->quantum_left = QUANTUM_TICKS;
    task->wakeup_time = 0;
    task->process = NULL;  /* Par defaut, pas de processus associe */

    //debug_context_registers(&task->context, "AFTER_setup_task_context");
    
    /* === VALIDATION CRITIQUE === */
    if (!validate_task_stack_safe(task)) {
        KERROR("KO Stack validation failed for task %s\n", task->name);
        task_free_kernel_stack(task);
        kfree(task);
        return NULL;
    }
    
    /* Ajouter a la liste des taches */
    add_task_to_list(task);
    kernel_lifecycle_stats.tasks_created++;
    
    KINFO("OK Created task '%s' (ID=%u, priority=%u) - Stack validated\n", 
          task->name, task->task_id, task->priority);
    
    return task;
}

void init_standard_files(process_t* process) {
    // stdin (fd = 0) - TTY logique, backend UART
    process->files[STDIN_FILENO] = create_tty_console_file("stdin", O_RDONLY);
    process->fd_flags[STDIN_FILENO] = 0;
    
    // stdout (fd = 1) - TTY logique, backend UART
    process->files[STDOUT_FILENO] = create_tty_console_file("stdout", O_WRONLY);
    process->fd_flags[STDOUT_FILENO] = 0;
    
    // stderr (fd = 2) - TTY logique, backend UART
    process->files[STDERR_FILENO] = create_tty_console_file("stderr", O_WRONLY);
    process->fd_flags[STDERR_FILENO] = 0;
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
        task->process->pgid = task->process->pid;
        task->process->sid = task->process->pid;
        task->process->controlling_tty = 0;
        task->process->parent = (current_task && current_task->type == TASK_TYPE_PROCESS) ? 
                               current_task : NULL;
        task->process->children = NULL;
        task->process->sibling_next = NULL;
        task->process->exit_code = 0;
        task->process->term_signal = 0;
        task->process->stop_signal = 0;
        task->process->stop_reported = 0;
        task->process->uid = 0;
        task->process->gid = 0;
        task->process->umask = 022;
        task->process->state = (proc_state_t)PROC_READY;
        
        /* Creer l'espace memoire */
        task->process->vm = create_vm_space();

        if (!task->process->vm) {
            task_destroy(task);
            return NULL;
        }

        task->context.ttbr0 = (uint32_t)task->process->vm->pgdir;
        task->context.asid = task->process->vm->asid;
        
        /* Initialiser les fichiers */
        memset(task->process->files, 0, sizeof(task->process->files));
        memset(task->process->fd_flags, 0, sizeof(task->process->fd_flags));

        init_standard_files(task->process);

        /* Initialiser les champs waitpid */
        task->process->waitpid_pid = 0;
        task->process->waitpid_status = NULL;
        task->process->waitpid_options = 0;
        task->process->waitpid_iteration = 0;
        task->process->waitpid_caller_lr = 0;
        strcpy(task->process->cwd, "/");    // Setting Current Working Directory
        strncpy(task->process->exe_path, name ? name : task->name, MAX_PATH - 1);
        task->process->exe_path[MAX_PATH - 1] = '\0';
        strncpy(task->process->cmdline, name ? name : task->name, PROC_CMDLINE_MAX - 1);
        task->process->cmdline[PROC_CMDLINE_MAX - 1] = '\0';
        task->process->cmdline_len = strlen(task->process->cmdline) + 1;
        task->process->environ[0] = '\0';
        task->process->environ_len = 0;
        
        /* Initialiser les signaux */
        init_process_signals(task);
        
    } else {
        // Mettre toute la structure process à zéro
        task->process = NULL; // KERNEL TASK
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
    unsigned long flags;

    if (!task) {
        task = current_task;  /* Detruire la tache courante si NULL */
    }
    
    if (task == idle_task) {
        KERROR("Cannot destroy idle task\n");
        return;
    }

    //KDEBUG("DESTROYING TASK %s, with state = %s\n", task->name, task_state_string(task->state));
    
    spin_lock_irqsave(&task_lock, &flags);
    
    if (task->state != TASK_ZOMBIE && task->state != TASK_TERMINATED) {
        runqueue_remove_locked(task);
        task->state = TASK_ZOMBIE;
        if (task->process)
            task->process->state = (proc_state_t)PROC_ZOMBIE;
        kernel_lifecycle_stats.zombies_created++;
    }
    
    /* Si c'est la tache courante, forcer une commutation */
    if (task == (task_t*)current_task) {
        spin_unlock_irqrestore(&task_lock, flags);
        schedule();  /* Ne reviendra jamais ici */
        /* NOTREACHED */
    }
    
    spin_unlock_irqrestore(&task_lock, flags);

    /* Retirer de la liste */
    remove_task_from_list(task);
    
    /* Liberer les ressources */
    task_free_kernel_stack(task);

    kfree(task->process);

    kfree(task);
    kernel_lifecycle_stats.tasks_destroyed++;
}

/* Ajouter cette vérification dans schedule_next_task */
void verify_ready_queue_integrity(void)
{
    unsigned long flags;
    task_t* task;
    int count = 0;

    KDEBUG("=== READY QUEUE VERIFICATION ===\n");

    spin_lock_irqsave(&task_lock, &flags);

    if (ready_queue.nr_running == 0) {
        KDEBUG("Ready queue is empty\n");
        spin_unlock_irqrestore(&task_lock, flags);
        return;
    }

    for (uint32_t prio = 0; prio < TASK_PRIORITY_LEVELS; prio++) {
        task = ready_queue.head[prio];
        while (task) {
            count++;
            KDEBUG("  [%d] p=%u %s (ID=%u): state=%d, rq_next=0x%08X, rq_prev=0x%08X\n",
                   count, prio, task->name, task->task_id, task->state,
                   (uint32_t)task->rq_next, (uint32_t)task->rq_prev);

            if (count > MAX_TASKS) {
                KERROR("Ready queue seems corrupted (too many tasks)\n");
                spin_unlock_irqrestore(&task_lock, flags);
                return;
            }

            task = task->rq_next;
        }
    }

    KDEBUG("Total tasks in ready queue: %d (tracked=%u)\n",
           count, ready_queue.nr_running);
    spin_unlock_irqrestore(&task_lock, flags);
}


/**
 * Ceder le CPU volontairement
 */
void yield(void)
{
    unsigned long flags;

    if (!scheduler_initialized) {
        return;
    }
    
    spin_lock_irqsave(&task_lock, &flags);
    if (current_task && current_task->state == TASK_RUNNING) {
        task_make_ready_locked(current_task);
    }
    spin_unlock_irqrestore(&task_lock, flags);

    //task_sleep_ms(500);  // Pause a bit to avoid race conditions.

    //KDEBUG("Task %s is yielding...\n", current_task->name);
    
    schedule();

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

void save_task_context_safe(task_t* task, uint32_t current_sp)
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
/*     if (strstr(task->name, "child")) {

        if(task->type == TASK_TYPE_PROCESS){
            if(task->context.cpsr == 0x10 )
                return; // User Process forking from userspace
        }
        uint32_t current_sp;
        __asm__ volatile("mov %0, sp" : "=r"(current_sp));
        //KDEBUG("SAVE child: Current SP=0x%08X, task SP=0x%08X\n", 
        //       current_sp, task->context.sp);
    } */
    
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
            task->context.svc_sp = current_sp;
            //KDEBUG("Saved valid SP for %s: 0x%08X\n", task->name, current_sp);
        } else {
            task_dump_stacks_detailed();
            KERROR("Task %s has invalid SP: 0x%08X - context SP = 0x%08X\n", task->name, current_sp, task->context.sp);
            //panic("Stopping");
            yield();
            return;
        }
    }
}

void switch_to_idle(void){
    unsigned long flags;
    task_t *next_task = schedule_next_task();

    if (!next_task ||
        next_task == (task_t *)current_task ||
        next_task->state == TASK_ZOMBIE ||
        next_task->state == TASK_TERMINATED) {
        next_task = idle_task;
    }

    spin_lock_irqsave(&task_lock, &flags);

    runqueue_remove_locked(next_task);
    next_task->state = TASK_RUNNING;
    if (next_task->type == TASK_TYPE_PROCESS && next_task->process)
        next_task->process->state = (proc_state_t)PROC_RUNNING;
    next_task->switch_count++;

    spin_unlock_irqrestore(&task_lock, flags);

    /*
     * Ne pas sauvegarder une tache morte et ne jamais modifier manuellement
     * le SP d'une tache suspendue.
     */
    __task_switch(NULL, &next_task->context);

    __builtin_unreachable();
}

static void for_each_task(task_t* current)
{
    task_t* task;
    uint32_t current_time = get_system_ticks();
    int count = 0;

    if (!current || !current->next)
        return;

    task = current->next;
    
    /* Chercher la prochaine tache READY avec la meme priorite */
    do {
        if (!task) {
            KERROR("for_each_task: broken task list near %s\n",
                   current ? current->name : "?");
            kernel_lifecycle_stats.scheduler_refused++;
            sched_trace_record(SCHED_TRACE_REFUSE_BROKEN_LIST, current);
            return;
        }

        if ((task->state == TASK_INTERRUPTIBLE ||
             task->state == TASK_UNINTERRUPTIBLE) &&
            task->wakeup_time > 0 &&
            current_time >= task->wakeup_time) {

            //KDEBUG("Waking up task %s from sleep\n", task->name);
            
            if (task->state == TASK_UNINTERRUPTIBLE) {
                kernel_lifecycle_stats.fs_wait_timeouts++;
                sched_trace_record(SCHED_TRACE_FS_WAIT_TIMEOUT, task);
            }
            task->state = TASK_READY;
            if (task->type == TASK_TYPE_PROCESS && task->process)
                task->process->state = (proc_state_t)PROC_READY;
            task->wakeup_time = 0;
            add_to_ready_queue(task);
        }

        if (!task->next) {
            KERROR("for_each_task: task %s has NULL next\n", task->name);
            kernel_lifecycle_stats.scheduler_refused++;
            sched_trace_record(SCHED_TRACE_REFUSE_NULL_NEXT, task);
            return;
        }
        task = task->next;
        count++;
    } while (task != current && count < MAX_TASKS);
    
    return ;  /* Pas d'autre tache de meme priorite */
}

static bool scheduler_entry_allowed(const char* caller, task_t* requested)
{
    if (!scheduler_initialized || !current_task) {
        KERROR("%s: scheduler not initialized or no current task\n", caller);
        return false;
    }

    if (requested &&
        (requested->state == TASK_ZOMBIE ||
         requested->state == TASK_TERMINATED ||
         !task_stack_metadata_valid(requested))) {
        KERROR("%s: refusing invalid task %s state=%d\n",
               caller, requested->name, requested->state);
        kernel_lifecycle_stats.scheduler_refused++;
        sched_trace_record(SCHED_TRACE_REFUSE_INVALID_TASK, requested);
        return false;
    }

    if (get_critical_section()) {
        kernel_lifecycle_stats.scheduler_refused++;
        sched_trace_record(SCHED_TRACE_REFUSE_CRITICAL, current_task);
        unset_critical_section();
    }

    if (get_cpu_mode() == ARM_MODE_IRQ)
        return false;

    return true;
}

static void scheduler_mark_running_locked(task_t* task)
{
    if (!task)
        return;

    runqueue_remove_locked(task);
    task->state = TASK_RUNNING;
    if (task->type == TASK_TYPE_PROCESS && task->process)
        task->process->state = (proc_state_t)PROC_RUNNING;
    task->switch_count++;
}

static bool scheduler_validate_switch(task_t* old_task,
                                      task_t* next_task,
                                      uint32_t current_sp)
{
    if (!next_task || !task_stack_metadata_valid(next_task)) {
        kernel_lifecycle_stats.scheduler_refused++;
        sched_trace_record(SCHED_TRACE_REFUSE_INVALID_TASK, next_task);
        return false;
    }

    if (old_task && !task_kernel_sp_valid(old_task, current_sp)) {
        KERROR("SCHED: old task %s current SP 0x%08X out of range\n",
               old_task->name, current_sp);
        KERROR("      stack 0x%08X-0x%08X context.sp=0x%08X svc_sp=0x%08X\n",
               (uint32_t)old_task->stack_base,
               (uint32_t)old_task->stack_top,
               old_task->context.sp,
               old_task->context.svc_sp);
        kernel_lifecycle_stats.scheduler_refused++;
        sched_trace_record(SCHED_TRACE_REFUSE_INVALID_TASK, old_task);
        return false;
    }

    return true;
}

static void scheduler_finish_no_switch(uint32_t irq_flags)
{
    unset_critical_section();
    restore_interrupts(irq_flags);
}

static void scheduler_restore_current_if_needed(void)
{
    unsigned long flags;

    spin_lock_irqsave(&task_lock, &flags);
    if (current_task && current_task->state == TASK_READY)
        scheduler_mark_running_locked(current_task);
    spin_unlock_irqrestore(&task_lock, flags);
}

static void scheduler_prepare_current_for_switch(void)
{
    unsigned long flags;

    spin_lock_irqsave(&task_lock, &flags);
    if (current_task && current_task->state == TASK_RUNNING)
        task_make_ready_locked(current_task);
    spin_unlock_irqrestore(&task_lock, flags);
}

static void scheduler_prepare_next_for_switch(task_t* next_task)
{
    unsigned long flags;

    spin_lock_irqsave(&task_lock, &flags);
    scheduler_mark_running_locked(next_task);
    spin_unlock_irqrestore(&task_lock, flags);
}

static void scheduler_switch_to(task_t* next_task,
                                uint32_t irq_flags,
                                bool save_current_context)
{
    scheduler_prepare_next_for_switch(next_task);
    unset_critical_section();

    __task_switch(save_current_context ? &current_task->context : NULL,
                  &next_task->context);

    restore_interrupts(irq_flags);
}

void schedule(void)
{
    uint32_t irq_flags;
    uint32_t current_sp;
    bool save_current_context;
    task_t* next_task;
    
    if (!scheduler_entry_allowed("schedule", NULL))
        return;

    irq_flags = disable_interrupts_save();
    set_critical_section();

    for_each_task(current_task);

    __asm__ volatile("mov %0, sp" : "=r"(current_sp));
    save_current_context = current_task->state != TASK_ZOMBIE &&
                           current_task->state != TASK_TERMINATED;

    if (save_current_context)
        scheduler_prepare_current_for_switch();

    next_task = schedule_next_task();

    if (next_task == (task_t *)current_task) {
        scheduler_restore_current_if_needed();
        scheduler_finish_no_switch(irq_flags);
        return;
    }

    if (!scheduler_validate_switch(save_current_context ? current_task : NULL,
                                   next_task,
                                   current_sp)) {
        if (save_current_context)
            scheduler_restore_current_if_needed();
        scheduler_finish_no_switch(irq_flags);
        return;
    }

    scheduler_switch_to(next_task, irq_flags, save_current_context);

}

void schedule_to(task_t *next_task)
{
    uint32_t irq_flags;
    uint32_t current_sp;
    bool save_current_context;
    
    if (!next_task || !scheduler_entry_allowed("schedule_to", next_task))
        return;

    irq_flags = disable_interrupts_save();
    set_critical_section();

    for_each_task(current_task);

    __asm__ volatile("mov %0, sp" : "=r"(current_sp));
    save_current_context = current_task->state != TASK_ZOMBIE &&
                           current_task->state != TASK_TERMINATED;

    if (save_current_context)
        scheduler_prepare_current_for_switch();

    if (next_task == (task_t *)current_task) {
        scheduler_restore_current_if_needed();
        scheduler_finish_no_switch(irq_flags);
        return;
    }

    if (!scheduler_validate_switch(save_current_context ? current_task : NULL,
                                   next_task,
                                   current_sp)) {
        if (save_current_context)
            scheduler_restore_current_if_needed();
        scheduler_finish_no_switch(irq_flags);
        return;
    }

    scheduler_switch_to(next_task, irq_flags, save_current_context);

}

/**
 * Version etendue de schedule() qui gere les types de taches
 */
void schedule_extended(void)
{
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
    
    //spin_lock(&task_lock);
    
    if (!task_list_head) {
        //spin_unlock(&task_lock);
        KERROR("No tasks to run!\n");
        return;
    }

    switch_to_idle();
        
/*     // La tache idle devient la tache courante
    current_task = idle_task;
    current_task->state = TASK_RUNNING;

    // Switch vers la pile d'idle MAINTENANT
    switch_to_idle_stack();
    
    spin_unlock(&task_lock);

    __task_switch(NULL, &current_task->context); */
    
    // On ne devrait jamais arriver ici
    KERROR("FATAL: Returned from sched_start!\n");
    while (1) __asm__ volatile("wfe");
}


static uint32_t scheduler_effective_priority_locked(task_t* task, uint32_t now)
{
    uint32_t base;
    uint32_t waited;
    uint32_t bonus;

    if (!task)
        return TASK_PRIORITY_LEVELS - 1;

    base = task_runqueue_priority(task);
    if (base == 0 || base >= TASK_PRIORITY_LEVELS)
        return base;

    if (task->ready_since_tick == 0 || now < task->ready_since_tick)
        return base;

    waited = now - task->ready_since_tick;
    bonus = waited / SCHED_AGING_STEP_TICKS;
    if (bonus > SCHED_AGING_MAX_BONUS)
        bonus = SCHED_AGING_MAX_BONUS;
    if (bonus > base)
        bonus = base;

    return base - bonus;
}

/**
 * Priority round-robin scheduler with bounded aging.
 *
 * Lower numeric priorities still mean higher scheduling preference, and tasks
 * at the same base priority are served FIFO/RR. To avoid starvation, the picker
 * compares an effective priority derived from how long the head task of each
 * priority queue has waited. The visible nice/priority does not change; only
 * this scheduling decision receives a temporary aging bonus.
 */
static task_t* schedule_next_task(void)
{
    unsigned long flags;
    task_t* task;
    task_t* best;
    uint32_t best_prio;
    uint32_t best_waited;
    uint32_t now;
    uint32_t scanned = 0;

    spin_lock_irqsave(&task_lock, &flags);

    while (ready_queue.nr_running > 0 && scanned <= MAX_TASKS) {
        best = NULL;
        best_prio = TASK_PRIORITY_LEVELS;
        best_waited = 0;
        now = get_system_ticks();

        for (uint32_t prio = 0; prio < TASK_PRIORITY_LEVELS; prio++) {
            task_t* candidate = ready_queue.head[prio];
            uint32_t effective;
            uint32_t waited;

            if (!candidate)
                continue;

            effective = scheduler_effective_priority_locked(candidate, now);
            waited = candidate->ready_since_tick && now >= candidate->ready_since_tick ?
                     now - candidate->ready_since_tick : 0;

            if (!best ||
                effective < best_prio ||
                (effective == best_prio && waited > best_waited)) {
                best = candidate;
                best_prio = effective;
                best_waited = waited;
            }
        }

        if (!best)
            break;

        task = best;
        runqueue_remove_locked(task);
        scanned++;

        if (task_is_schedulable(task)) {
            if (best_prio < task_runqueue_priority(task))
                sched_aging_selections++;
            spin_unlock_irqrestore(&task_lock, flags);
            return task;
        }

        /*
         * A stale runqueue entry means a task changed state without going
         * through the scheduler helpers. Drop it instead of letting a dead or
         * blocked task spin forever at the head of the queue.
         */
        kernel_lifecycle_stats.scheduler_refused++;
        sched_trace_record(SCHED_TRACE_REFUSE_INVALID_TASK, task);
    }

    if (scanned > MAX_TASKS) {
        KERROR("schedule_next_task: runqueue loop protection triggered\n");
        kernel_lifecycle_stats.scheduler_refused++;
        sched_trace_record(SCHED_TRACE_REFUSE_LOOP, NULL);
    }

    spin_unlock_irqrestore(&task_lock, flags);
    return idle_task;
}



/**
 * Ajouter une tache a la liste circulaire
 */
void add_task_to_list(task_t* task)
{
    unsigned long flags;

    if (!task)
        return;

    spin_lock_irqsave(&task_lock, &flags);

    task->rq_next = NULL;
    task->rq_prev = NULL;
    task->rq_priority = TASK_PRIORITY_LEVELS;

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

    spin_unlock_irqrestore(&task_lock, flags);

}

/**
 * Retirer une tache de la liste circulaire
 */
void remove_task_from_list(task_t* task)
{
    task_t* current;
    bool found = false;
    int count = 0;
    unsigned long flags;

    if (!task || !task_list_head) return;

    spin_lock_irqsave(&task_lock, &flags);

    if (!task->next || !task->prev) {
        runqueue_remove_locked(task);
        spin_unlock_irqrestore(&task_lock, flags);
        return;
    }

    current = task_list_head;
    do {
        if (current == task) {
            found = true;
            break;
        }
        current = current->next;
        count++;
    } while (current && current != task_list_head && count < MAX_TASKS);

    if (!found) {
        runqueue_remove_locked(task);
        spin_unlock_irqrestore(&task_lock, flags);
        return;
    }

    runqueue_remove_locked(task);
    
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
    if (task_count > 0)
        task_count--;

    spin_unlock_irqrestore(&task_lock, flags);

}

/**
 * Fonction de la tache idle
 */
void idle_task_func(void* arg)
{
    (void)arg;
    
    KINFO("Idle task started\n");
    
    while (1) {
        /*
         * Before timer preemption existed, idle had to yield in a tight loop.
         * With the periodic IRQ scheduler, that becomes artificial scheduler
         * pressure during long idle runs. Sleep until an interrupt, then let
         * the scheduler pick any task that became runnable.
         */
        __asm__ volatile("cpsie i" ::: "memory");
        __asm__ volatile("wfi" ::: "memory");
        schedule();
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
    unsigned long flags;
    bool queued;

    if (!task) return;
    
    spin_lock_irqsave(&task_lock, &flags);
    queued = runqueue_contains_locked(task);
    if (queued)
        runqueue_remove_locked(task);

    task->priority = priority;

    if (queued && task->state == TASK_READY)
        runqueue_enqueue_tail_locked(task);

    spin_unlock_irqrestore(&task_lock, flags);
    
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
static proc_state_t task_state_to_proc_state(task_state_t state)
{
    switch (state) {
        case TASK_READY:           return (proc_state_t)PROC_READY;
        case TASK_RUNNING:         return (proc_state_t)PROC_RUNNING;
        case TASK_BLOCKED:         return (proc_state_t)PROC_BLOCKED;
        case TASK_ZOMBIE:          return (proc_state_t)PROC_ZOMBIE;
        case TASK_TERMINATED:      return (proc_state_t)PROC_DEAD;
        case TASK_INTERRUPTIBLE:   return (proc_state_t)PROC_INTERRUPTIBLE;
        case TASK_UNINTERRUPTIBLE: return (proc_state_t)PROC_UNINTERRUPTIBLE;
        case TASK_STOPPED:         return (proc_state_t)PROC_STOPPED;
    }
    return (proc_state_t)PROC_DEAD;
}

void task_set_state(task_t* task, task_state_t state)
{
    unsigned long flags;

    if (!task) return;
    
    spin_lock_irqsave(&task_lock, &flags);
    if (state != TASK_READY)
        runqueue_remove_locked(task);
    task->state = state;
    if (task->type == TASK_TYPE_PROCESS && task->process) {
        proc_state_t proc_state = task_state_to_proc_state(state);
        if (task->process->state != proc_state)
            kernel_lifecycle_stats.state_sync_repairs++;
        task->process->state = proc_state;
    }
    spin_unlock_irqrestore(&task_lock, flags);
}

void task_set_ready(task_t* task)
{
    task_set_state(task, TASK_READY);
}

void task_set_blocked(task_t* task)
{
    task_set_state(task, TASK_BLOCKED);
}

void task_set_interruptible(task_t* task)
{
    task_set_state(task, TASK_INTERRUPTIBLE);
}

void task_set_uninterruptible(task_t* task)
{
    task_set_state(task, TASK_UNINTERRUPTIBLE);
}

void task_set_stopped(task_t* task)
{
    task_set_state(task, TASK_STOPPED);
}

void task_set_zombie(task_t* task)
{
    task_set_state(task, TASK_ZOMBIE);
}

void task_set_terminated(task_t* task)
{
    task_set_state(task, TASK_TERMINATED);
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
        case TASK_INTERRUPTIBLE: return "INTERRUPTIBLE";
        case TASK_UNINTERRUPTIBLE: return "UNINTERRUPTIBLE";
        case TASK_STOPPED: return "STOPPED";
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
        case PROC_INTERRUPTIBLE: return "INTERRUPTIBLE";
        case PROC_UNINTERRUPTIBLE: return "UNINTERRUPTIBLE";
        case PROC_STOPPED: return "STOPPED";
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
    unsigned long flags;
    uint32_t ticks;

    if (!current_task || ms == 0) {
        yield();
        return;
    }

    if (!scheduler_initialized) {
        volatile uint32_t total = ms * 1000;
        for (volatile uint32_t i = 0; i < total; i++)
            __asm__ volatile("nop");
        return;
    }

    ticks = (ms * TIMER_FREQ + 999) / 1000;
    if (ticks == 0)
        ticks = 1;

    spin_lock_irqsave(&task_lock, &flags);
    current_task->wakeup_time = get_system_ticks() + ticks;
    runqueue_remove_locked(current_task);
    current_task->state = TASK_INTERRUPTIBLE;
    if (current_task->type == TASK_TYPE_PROCESS && current_task->process)
        current_task->process->state = (proc_state_t)PROC_INTERRUPTIBLE;
    spin_unlock_irqrestore(&task_lock, flags);

    schedule();

    spin_lock_irqsave(&task_lock, &flags);
    current_task->wakeup_time = 0;
    spin_unlock_irqrestore(&task_lock, flags);
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

    debug_print_ctx((task_context_t *)r0_val, "---->>>> IN DEBUG__PRINT_SP - CALLED FROM ASM");
    
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
    uint32_t r0_val, r1_val, sp_val, pc_val, lr_val, r7_val;
    
    __asm__ volatile(
        /* Sauvegarder tous les registres dans les variables locales */
        "mov %0, r0\n"          /* Sauvegarder r0 */
        "mov %1, r1\n"          /* Sauvegarder r1 */
        "mov %2, sp\n"          /* Sauvegarder sp */
        "mov %3, pc\n"          /* Sauvegarder pc (approximatif) */
        "mov %4, lr\n"          /* Sauvegarder lr */
        "mov %5, r7\n"          /* Sauvegarder r7 */
        : "=r"(r0_val), "=r"(r1_val), "=r"(sp_val), "=r"(pc_val), "=r"(lr_val), "=r"(r7_val)
        :
        : /* Pas de registres clobbered car on les sauvegarde explicitement */
    );
    
    /* Maintenant afficher avec kprintf (les registres originaux sont intacts) */
    uart_puts("\n\nRegisters SWI HANDLER:\n");
    uart_puts("  r0: ");
    uart_put_hex(r0_val);
    uart_puts("\n  r1: ");
    uart_put_hex(r7_val);
    uart_puts("\n  r7: ");
    uart_put_hex(r7_val);
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

void debug_print_ctx(task_context_t *context, const char* caller)
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
    kprintf("Current Task (0x%08X) saved Contex - Called from %st:\n", (uint32_t)context, caller);
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
    unsigned long flags;

    if (!task) return;

    /* Ne pas ajouter les zombies a la ready queue */
    if (task->state == TASK_ZOMBIE || task->state == TASK_TERMINATED) {
        //KDEBUG("add_to_ready_queue: Ignoring zombie/terminated task %s\n", 
        //       task->name);
        kernel_lifecycle_stats.ready_queue_refused++;
        sched_trace_record(SCHED_TRACE_READY_REFUSE_DEAD, task);
        return;
    }

    /*
     * Fork creates the child object off-list. Put it in the global task list
     * before exposing it to the scheduler runqueue.
     */
    if (!task->next && !task->prev && task != task_list_head) {
        add_task_to_list(task);
    }

    spin_lock_irqsave(&task_lock, &flags);
    task_make_ready_locked(task);
    spin_unlock_irqrestore(&task_lock, flags);

    //KDEBUG("add_to_ready_queue: Task %s added to ready queue\n", task->name);
}

/**
 * Version securisee avec verifications supplementaires
 */
void remove_from_ready_queue(task_t* task)
{
    unsigned long flags;

    if (!task) {
        KERROR("remove_from_ready_queue: NULL task\n");
        return;
    }
    
    //KDEBUG("remove_from_ready_queue: Marking task %s as non-ready\n", task->name);
    spin_lock_irqsave(&task_lock, &flags);

    runqueue_remove_locked(task);
    if (task->state == TASK_READY) {
        task->state = TASK_BLOCKED;  /* ou autre etat approprie */
        if (task->type == TASK_TYPE_PROCESS && task->process)
            task->process->state = (proc_state_t)PROC_BLOCKED;
    }
    
    spin_unlock_irqrestore(&task_lock, flags);

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
    
    KDEBUG("destroy_zombie_process: Destroying zombie %s (PID=%u)\n", 
           zombie->name, zombie->process->pid);
    
    /* Maintenant on peut vraiment le retirer de la liste */
    remove_task_from_list(zombie);
    
    /* Liberer les ressources */
    if (zombie->process->vm) {
        //destroy_vm_space(zombie->process->vm);
        zombie->process->vm = NULL;
    }
    
    task_free_kernel_stack(zombie);
    
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
    unsigned long flags;
    bool in_queue;

    if (!task) {
        KERROR("is_in_ready_queue: NULL task\n");
        return false;
    }

    spin_lock_irqsave(&task_lock, &flags);
    in_queue = task->state == TASK_READY && runqueue_contains_locked(task);
    spin_unlock_irqrestore(&task_lock, flags);
    return in_queue;
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
