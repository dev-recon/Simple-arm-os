/* kernel/process/fork.c */
#include <kernel/process.h>
#include <kernel/syscalls.h>
#include <kernel/memory.h>
#include <kernel/kernel.h>
#include <kernel/vfs.h>
#include <asm/arm.h>
#include <kernel/kprintf.h>

/* Forward declarations de toutes les fonctions statiques */
task_t* find_zombie_child(task_t* parent, pid_t pid);
bool has_children(task_t* parent, pid_t pid);
void remove_child_from_parent(task_t* parent, task_t* child);
void orphan_children(task_t* proc);
/* Supprime: static bool has_pending_signals(process_t* proc); */
void copy_process_files(task_t* parent, task_t* child);


/* ========================================================================= */
/* FONCTIONS HELPER - Adaptees a task_t */
/* ========================================================================= */

/**
 * Copier les fichiers ouverts - ADAPTe
 */
void copy_process_files(task_t* parent, task_t* child)
{
    int i;
    
    if (!parent || !child || !parent->process || !child->process ||
        parent->type != TASK_TYPE_PROCESS || 
        child->type != TASK_TYPE_PROCESS) {
        KERROR("copy_process_files: NULL Proc\n");
        return;
    }
    
    /* ACCeS CORRECT */
    for (i = 0; i < MAX_FILES; i++) {
        if (parent->process->files[i]) {
            child->process->files[i] = parent->process->files[i];
            parent->process->files[i]->ref_count++;
        }
    }
}

void close_all_process_files(task_t* proc) {

    if(!proc || !proc->process){
        KERROR("Wake up : no parent or no process structure\n");
        KERROR("NULL PROC\n");
        return;
    }

    for (int i = 0; i < MAX_FILES; i++) {
        if (proc->process->files[i]) {
            close_file(proc->process->files[i]);
            proc->process->files[i] = NULL;
        }
    }
}

/**
 * Retourner au code appelant avec une valeur - ADAPTe
 */
void return_to_caller_with_value(int return_value)
{
    task_t* proc = current_task;
    
    if (!proc || proc->type != TASK_TYPE_PROCESS) {
        KERROR("[WAITPID] Invalid process\n");
        KERROR("NULL PROC\n");
        return;
    }
    
    KDEBUG("[WAITPID] Retour avec valeur: %d\n", return_value);
    
    /* ACCeS CORRECT au contexte */
    proc->context.r0 = return_value;
    
    /* Utiliser l'adresse stockee lors de l'appel initial - ACCeS CORRECT */
    if (proc->process->waitpid_caller_lr != 0) {
        proc->context.pc = proc->process->waitpid_caller_lr;
        KDEBUG("[WAITPID] PC mis a caller_lr: 0x%08X\n", proc->process->waitpid_caller_lr);
    } else {
        /* Fallback: utiliser LR si disponible */
        if (proc->context.lr != 0) {
            proc->context.pc = proc->context.lr;
            KDEBUG("[WAITPID] PC mis a LR: 0x%08X\n", proc->context.lr);
        } else {
            KDEBUG("[WAITPID] Ni caller_lr ni LR disponible - continuation normale\n");
        }
    }
}

/**
 * Point de reprise pour waitpid - ADAPTe
 */
void waitpid_resume_point(void)
{
    task_t* parent = current_task;
    
    //KDEBUG("[WAITPID] === REPRISE apres reveil ===\n");
    
    if (!parent || parent->type != TASK_TYPE_PROCESS || !parent->process) {
        KERROR("[WAITPID] Processus parent invalid lors de la reprise\n");
        KERROR("wait_pid_resume_point: NULL Proc\n");
        return;
    }
    
    /* Recuperer les arguments depuis les champs dedies - ACCeS CORRECT */
    pid_t pid = parent->process->waitpid_pid;
    int* status = parent->process->waitpid_status;
    int options = parent->process->waitpid_options;
    int iteration = parent->process->waitpid_iteration;
    
    KDEBUG("[WAITPID] Reprise avec pid=%d, status=%p, options=%d, iteration=%d\n", 
           pid, status, options, iteration);
    
    /* Chercher le zombie maintenant que nous sommes reveilles */
    task_t* zombie = find_zombie_child(parent, pid);
    if (zombie) {
        pid_t child_pid = zombie->process->pid;
        int exit_code = zombie->process->exit_code;
        
        //KINFO("[WAITPID] OK Processus zombie trouve apres reveil: PID %u\n", child_pid);
        
        /* Copier le statut avant le cleanup */
        if (status) {
            //KDEBUG("[WAITPID] Tentative copy_to_user vers %p, valeur %d\n", 
            //       status, exit_code);
            
            if (!is_valid_user_ptr(status)) {
                if ((uint32_t)status >= KERNEL_BASE) {  /* KERNEL_BASE */
                    KDEBUG("[WAITPID] Adresse kernel detectee - copie directe\n");
                    *status = exit_code;
                } else {
                    KERROR("[WAITPID] Adresse status invalide: %p\n", status);
                    return_to_caller_with_value(-EFAULT);
                    return;
                }
            } else {
                if (copy_to_user(status, &exit_code, sizeof(int)) < 0) {
                    KERROR("[WAITPID] echec copy_to_user lors de la reprise\n");
                    return_to_caller_with_value(-EFAULT);
                    return;
                }
            }
            
            //KDEBUG("[WAITPID] Code de sortie copie: %d\n", exit_code);
        }
        
        /* Retirer de la liste des enfants AVANT destroy_process */
        //KDEBUG("[WAITPID] Retrait securise de la liste des enfants...\n");
        remove_child_from_parent(parent, zombie);
        
        /* Marquer comme DEAD avant destruction */
        zombie->state = TASK_TERMINATED;
        zombie->process->state = (proc_state_t)PROC_DEAD;
        
        /* Nettoyer le processus zombie */
        //KDEBUG("[WAITPID] Destruction securisee du processus zombie...\n");
        destroy_process(zombie);
        
        KDEBUG("[WAITPID] === FIN reprise sys_waitpid - retour %d ===\n", child_pid);
        
        /* Retourner au code appelant avec le PID */
        return_to_caller_with_value(child_pid);
        return;
        
    } else {
        /* Cas d'erreur : pas de zombie trouve */
        KDEBUG("[WAITPID] Aucun zombie trouve lors de la reprise\n");
        
        if (!has_children(parent, pid)) {
            KDEBUG("[WAITPID] Aucun enfant - retour ECHILD\n");
            return_to_caller_with_value(-ECHILD);
            return;
        }
        
        /* Continuer l'attente */
        KDEBUG("[WAITPID] Enfants encore vivants - continuer l'attente\n");
        
        /* Incrementer l'iteration et verifier la limite */
        parent->process->waitpid_iteration = iteration + 1;
        if (parent->process->waitpid_iteration >= 50) {
            KERROR("[WAITPID] Limite d'iterations atteinte\n");
            return_to_caller_with_value(-1);
            return;
        }
        
        /* Re-bloquer le processus */
        parent->state = TASK_BLOCKED;
        parent->process->state = (proc_state_t)PROC_BLOCKED;
        schedule();
    }
}

/**
 * Nettoyer la liste des enfants - ADAPTe
 */
void clean_children_list(task_t* parent)
{
    task_t* child;
    task_t* prev = NULL;
    int count = 0;
    const int MAX_CHILDREN = 50;
    
    if (!parent || parent->type != TASK_TYPE_PROCESS || !parent->process) {
        KERROR("clean_children_list: NULL Proc\n");
        return;
    }
    
    /* ACCeS CORRECT */
    child = parent->process->children;
    
    while (child && count < MAX_CHILDREN) {
        task_t* next = child->process->sibling_next;
        
        /* Verifier la coherence */
        if (next == child) {
            KERROR("[WAITPID] Boucle circulaire detectee - correction\n");
            child->process->sibling_next = NULL;
            break;
        }
        
        /* Verifier que l'enfant a bien ce parent */
        if (child->process->parent != parent) {
            KERROR("[WAITPID] Enfant orphelin detecte - correction\n");
            if (prev) {
                prev->process->sibling_next = next;
            } else {
                parent->process->children = next;
            }
        } else {
            prev = child;
        }
        
        child = next;
        count++;
    }
    
    if (count >= MAX_CHILDREN) {
        KERROR("[WAITPID] Trop d'enfants - nettoyage force\n");
        parent->process->children = NULL;
    }
}


task_t* find_zombie_child(task_t* parent, pid_t pid)
{
    if (!parent) {
        KERROR("find_zombie_child: NULL Parent\n");
        return NULL;
    }

    if (parent->type != TASK_TYPE_PROCESS) {
        KERROR("find_zombie_child: Parent not Processs task\n");
        KERROR("find_zombie_child: Parent name = %s\n", parent->name);
        return NULL;
    }

    if (!parent->process) {
        KERROR("find_zombie_child: NULL Proc\n");
        return NULL;
    }


    /* Chercher un processus zombie - ACCeS CORRECT */
    task_t* child = parent->process->children;
    //task_t* prev = NULL;
    task_t* zombie = NULL;

            //KINFO("find_zombie_child: checking childs of PID %u for zombie PID %d \n", 
            //      parent->process->pid, pid);

    while (child) {
        /* CORRIGER: Utiliser TASK_ZOMBIE au lieu de TASK_TERMINATED */

        if ((pid == -1 || child->process->pid == pid) && 
            child->state == TASK_ZOMBIE && child->process->state == (proc_state_t)PROC_ZOMBIE) {
            zombie = child;
            break;
        }
        //prev = child;
        child = child->process->sibling_next;
    }
    
    return zombie;
}


bool has_children(task_t* parent, pid_t pid)
{
    if (!parent) {
        KERROR("has_children: NULL Parent\n");
        return false;
    }

    if (parent->type != TASK_TYPE_PROCESS) {
        KERROR("has_children: Parent not Process Task\n");
        return false;
    }

    if (!parent->process) {
        KERROR("has_children: NULL Proc\n");
        return false;
    }

    bool has_children = false;
    task_t* child = parent->process->children;

    while (child) {
        if (pid == -1 || child->process->pid == pid) {
            has_children = true;
            break;
        }
        child = child->process->sibling_next;
    }
    
    return has_children;
}


/**
 * Retirer un enfant de la liste du parent - ADAPTe
 */
void remove_child_from_parent(task_t* parent, task_t* child_to_remove)
{
    if (!parent || !child_to_remove || 
        parent->type != TASK_TYPE_PROCESS || 
        child_to_remove->type != TASK_TYPE_PROCESS || !parent->process || !child_to_remove->process) {
        KERROR("remove_child_from_parent: NULL Proc\n");
        //KDEBUG("[REMOVE_CHILD] Parent ou enfant invalid\n");
        return;
    }
    
    /* ACCeS CORRECT */
    //KDEBUG("[REMOVE_CHILD] Retrait PID %u du parent PID %u\n", 
    //       child_to_remove->process->pid, parent->process->pid);
    
    if (parent->process->children == child_to_remove) {
        parent->process->children = child_to_remove->process->sibling_next;
        //KDEBUG("[REMOVE_CHILD] Enfant retire en tete de liste\n");
    } else {
        task_t* current = parent->process->children;
        int count = 0;
        const int MAX_SEARCH = 20;
        
        while (current && current->process->sibling_next != child_to_remove && count < MAX_SEARCH) {
            current = current->process->sibling_next;
            count++;
        }
        
        if (current && count < MAX_SEARCH) {
            current->process->sibling_next = child_to_remove->process->sibling_next;
            //KDEBUG("[REMOVE_CHILD] Enfant retire du milieu de liste\n");
        } else {
            //KDEBUG("[REMOVE_CHILD] Enfant non trouve dans la liste\n");
        }
    }
    
    /* Nettoyer les references de l'enfant - ACCeS CORRECT */
    child_to_remove->process->sibling_next = NULL;
    child_to_remove->process->parent = NULL;
    
    //KDEBUG("[REMOVE_CHILD] Retrait termine\n");
}

/**
 * Orpheliner les enfants vers init - ADAPTe
 */
void orphan_children(task_t* proc)
{
    task_t* init_proc;
    task_t* child;
    task_t* next;
    
    if (!proc || proc->type != TASK_TYPE_PROCESS || !proc->process) {
        KERROR("NULL PROC\n");
        return;
    }
    
    init_proc = find_process_by_pid(1);
    if (!init_proc) {
        KERROR("orphan_children: Init process not found\n");
        return;
    }
    
    /* ACCeS CORRECT */
    child = proc->process->children;
    
    while (child) {
        next = child->process->sibling_next;
        
        /* Reassigner a init - ACCeS CORRECT */
        child->process->parent = init_proc;
        child->process->ppid = 1;
        child->process->sibling_next = init_proc->process->children;
        init_proc->process->children = child;
        
        /* Reveiller init si l'enfant est zombie */
        if (child->state == TASK_ZOMBIE && init_proc->state == TASK_BLOCKED) {
            init_proc->state = TASK_READY;
            init_proc->process->state = (proc_state_t)PROC_READY;
            add_to_ready_queue(init_proc);
        }
        
        child = next;
    }
    
    proc->process->children = NULL;
}


void wakeup_parent(task_t *proc){

    if(!proc || !proc->process){
        KERROR("Wake up : no proc or no process structure\n");
        KERROR("NULL PROC\n");
        return;
    }

        /* Reveiller le parent s'il attend - ACCeS CORRECT */
    if (proc->process->parent) {
        task_t* parent = proc->process->parent;
        if(!parent || !parent->process)
        {
            KERROR("Wake up : no parent or no parent process structure\n");
            KERROR("wakeup_parent: NULL Proc\n");
            return;
        }
        
/*         KINFO("[EXIT] *** WAKING UP PARENT ***\n");
        KDEBUG("sys_exit: Parent PID=%d state=%s proc_state=%s\n", 
               parent->process->pid, task_state_string(parent->state), proc_state_string(parent->process->state));
        KDEBUG("sys_exit: Parent waiting for PID=%d\n", 
               parent->process->waitpid_pid);
        KDEBUG("sys_exit: Child exit code =%d\n", 
               proc->process->exit_code);
        KDEBUG("sys_exit: Child PID=%d state=%s proc_state=%s\n", 
               proc->process->pid, task_state_string(proc->state), proc_state_string(proc->process->state));
  */
        
        /* Verifier si le parent attend vraiment */
        if (parent->state == TASK_BLOCKED && 
            parent->process->state == (proc_state_t)PROC_BLOCKED) {
            
            /* Verifier si le parent attend ce processus specifiquement */
            pid_t wait_pid = parent->process->waitpid_pid;
            if (wait_pid == -1 || wait_pid == proc->process->pid) {
                //KINFO("sys_exit: Waking up parent PID=%u\n", parent->process->pid);
                
                parent->state = TASK_READY;
                parent->process->state = (proc_state_t)PROC_READY;
                *parent->process->waitpid_status = proc->process->exit_code;
                
                /* Ajouter le parent a la ready queue */
                add_to_ready_queue(parent);
                
                //KDEBUG("sys_exit: Parent PID=%u added to ready queue\n", 
                //       parent->process->pid);
            } else {
                KINFO("sys_exit: Parent waiting for different PID (%d vs %u)\n", 
                       wait_pid, proc->process->pid);
            }
        } else {
            KINFO("sys_exit: Parent not blocked (state=%d proc_state=%d)\n", 
                   parent->state, parent->process->state);
        }
    } else {
        KWARN("sys_exit: No parent found\n");
    }

}