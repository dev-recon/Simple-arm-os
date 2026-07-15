/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/task/kernel_tasks.c
 * Layer: Kernel / scheduler and tasking
 *
 * Responsibilities:
 * - Create, schedule, block, wake, and destroy tasks.
 * - Track scheduling and lifecycle diagnostics.
 *
 * Notes:
 * - Scheduler invariants are shared with timer preemption and wait paths.
 */

#include <kernel/kernel_tasks.h>
#include <kernel/task.h>
#include <kernel/memory.h>
#include <kernel/kprintf.h>
#include <kernel/syscalls.h>
#include <kernel/process.h>

void print_system_stats(void)
{
    task_t* current = task_current_local();
    
    KINFO("=== System Statistics ===\n");
    KINFO("Current task: %s\n", current ? current->name : "unknown");
    
    print_memory_stats();
    
    KINFO("Task list:\n");
    task_list_all();
    
    KINFO("=========================\n");
}

void print_memory_stats(void)
{
    uint32_t free_pages = get_free_page_count();
    uint32_t total_pages = get_total_page_count();
    uint32_t used_pages = total_pages - free_pages;
    uint32_t total_mb = (uint32_t)
        (((uint64_t)total_pages * PAGE_SIZE) / (1024u * 1024u));
    uint32_t used_mb = (uint32_t)
        (((uint64_t)used_pages * PAGE_SIZE) / (1024u * 1024u));
    uint32_t free_mb = (uint32_t)
        (((uint64_t)free_pages * PAGE_SIZE) / (1024u * 1024u));
    
    KINFO("Memory status:\n");
    KINFO("  Total pages: %u (%u MB)\n", total_pages, total_mb);
    KINFO("  Used pages:  %u (%u MB)\n", used_pages, used_mb);
    KINFO("  Free pages:  %u (%u MB)\n", free_pages, free_mb);
    KINFO("  Usage:       %u%%\n", 
          total_pages > 0 ? (used_pages * 100) / total_pages : 0);
    
    KINFO("Heap statistics:\n");
    kheap_stats();
}


/**
 * Lister tous les processus - CORRIGe
 */
void list_all_processes(void)
{
    task_t* task = task_list_head;
    int count = 0;
    
    KINFO("=== Process List ===\n");
    
    if (!task_list_head) {
        KINFO("No processes\n");
        return;
    }
    
    spin_lock(&task_lock);
    
    do {
        if (task->type == TASK_TYPE_PROCESS) {
            /* ACCeS CORRECT */
            KINFO("PID=%u PPID=%u %s (state=%s proc_state=%s)\n",
                  task->process->pid,
                  task->process->ppid,
                  task->name,
                  task_state_string(task->state),
                  proc_state_string(task->process->state));
        } else {
            KINFO("TID=%u %s (type=%d, state=%s)\n",
                  task->task_id,
                  task->name,
                  task->type,
                  task_state_string(task->state));
        }
        
        task = task->next;
        count++;
    } while (task != task_list_head && count < MAX_TASKS);
    
    spin_unlock(&task_lock);
    
    KINFO("Total: %d tasks/processes\n", count);
}


void simple_shell_task(void* arg) {

    (void)arg;

    const char* primary_path = "/sbin/mash";
    const char* fallback_path = "/bin/mash";
    char* primary_name = "mash";
    char* fallback_name = "mash";
    int result = 0;
        
    char* const primary_argv[] = { primary_name, NULL };
    char* const fallback_argv[] = { fallback_name, NULL };
    char* const envp[] = { NULL };

    KBOOT_OKF("Init: starting %s", primary_path);
    result = sys_execve(primary_path, primary_argv, envp);
    KWARN("Primary shell exec failed with %d, falling back to %s\n",
          result, fallback_path);
    result = sys_execve(fallback_path, fallback_argv, envp);
        
    // Si on arrive ici, exec a échoué
    KERROR("Child: exec failed with %d\n", result);
    sys_exit(-1);
}
