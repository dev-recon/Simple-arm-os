/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/drivers/power.c
 * Layer: Kernel / device drivers
 *
 * Responsibilities:
 * - Expose hardware or pseudo-device services to the kernel and VFS.
 * - Translate device-specific state into stable kernel interfaces.
 *
 * Notes:
 * - Driver failures should degrade without hiding tty0 diagnostics.
 */

#include <kernel/power.h>
#include <kernel/kprintf.h>
#include <kernel/types.h>
#include <kernel/task.h>
#include <kernel/process.h>
#include <kernel/virtio_block.h>
#include <kernel/vfs.h>
#include <kernel/signal.h>
#include <kernel/timer.h>
#include <asm/arm.h>

#define PSCI_0_2_FN_SYSTEM_OFF 0x84000008u
#define SHUTDOWN_TERM_GRACE_MS 200
#define SHUTDOWN_KILL_GRACE_MS 100

static volatile bool shutdown_in_progress = false;

static bool shutdown_process_target(task_t *task)
{
    if (!task || task == current_task)
        return false;
    if (task->type != TASK_TYPE_PROCESS || !task->process)
        return false;
    if (task->process->pid == 1)
        return false;
    if (task->state == TASK_ZOMBIE || task->state == TASK_TERMINATED)
        return false;

    return true;
}

static bool shutdown_signal_target(task_t *task)
{
    if (!shutdown_process_target(task))
        return false;

    /*
     * PID 1 is notified by /sbin/shutdown before entering the kernel poweroff
     * path. Once init is in shutdown mode, login shells must receive SIGTERM so
     * they can persist userland state such as command history before VFS sync.
     */
    return true;
}

static unsigned shutdown_count_live_targets(void)
{
    task_t *task = task_list_head;
    unsigned count = 0;
    unsigned live = 0;

    if (!task)
        return 0;

    do {
        if (shutdown_signal_target(task))
            live++;
        task = task->next;
        count++;
    } while (task && task != task_list_head && count < MAX_TASKS);

    return live;
}

static unsigned shutdown_signal_targets(int sig)
{
    task_t *task = task_list_head;
    unsigned count = 0;
    unsigned delivered = 0;

    if (!task)
        return 0;

    do {
        task_t *next = task->next;

        if (shutdown_signal_target(task) && send_signal(task, sig) == 0)
            delivered++;
        task = next;
        count++;
    } while (task && task != task_list_head && count < MAX_TASKS);

    return delivered;
}

static void shutdown_wait_for_targets(const char *phase, uint32_t grace_ms)
{
    uint32_t deadline = get_system_ticks() + (grace_ms * TIMER_FREQ + 999) / 1000;
    unsigned live;

    do {
        live = shutdown_count_live_targets();
        if (live == 0) {
            kprintf("Shutdown: %s complete\n", phase);
            return;
        }
        task_sleep_ms(10);
    } while (get_system_ticks() < deadline);

    kprintf("Shutdown: %s timeout, %u process(es) still alive\n",
            phase, live);
}

static unsigned shutdown_force_terminate_targets(void)
{
    task_t *task = task_list_head;
    unsigned count = 0;
    unsigned stopped = 0;

    if (!task)
        return 0;

    do {
        task_t *next = task->next;

        if (shutdown_signal_target(task)) {
            unsigned long flags;

            close_all_process_files(task);
            remove_from_ready_queue(task);

            spin_lock_irqsave(&task_lock, &flags);
            task->state = TASK_TERMINATED;
            task->process->state = (proc_state_t)PROC_DEAD;
            spin_unlock_irqrestore(&task_lock, flags);
            stopped++;
        }

        task = next;
        count++;
    } while (task && task != task_list_head && count < MAX_TASKS);

    return stopped;
}

static void shutdown_processes(void)
{
    unsigned delivered;
    unsigned forced;

    kprintf("Shutdown: sending SIGTERM to user processes\n");
    delivered = shutdown_signal_targets(SIGTERM);
    kprintf("Shutdown: SIGTERM delivered to %u process(es)\n", delivered);
    shutdown_wait_for_targets("SIGTERM grace", SHUTDOWN_TERM_GRACE_MS);

    if (shutdown_count_live_targets() > 0) {
        kprintf("Shutdown: sending SIGKILL to remaining processes\n");
        delivered = shutdown_signal_targets(SIGKILL);
        kprintf("Shutdown: SIGKILL delivered to %u process(es)\n", delivered);
        shutdown_wait_for_targets("SIGKILL grace", SHUTDOWN_KILL_GRACE_MS);
    }

    forced = shutdown_force_terminate_targets();
    if (forced)
        kprintf("Shutdown: force-terminated %u process(es)\n", forced);

    if (current_task && current_task->type == TASK_TYPE_PROCESS && current_task->process) {
        close_all_process_files(current_task);
    }
}

static void shutdown_drivers(void)
{
    if (vfs_shutdown() < 0)
        KERROR("Shutdown: VFS shutdown completed with errors\n");

    kprintf("Shutdown: flushing and stopping block device\n");
    virtio_blk_shutdown();
    kprintf("Shutdown: block device stopped\n");
}

static void psci_system_off(void) __attribute__((noreturn));

static void psci_system_off(void)
{
    __asm__ volatile("cpsid if\n"
                     "dsb\n"
                     "isb\n"
                     ::: "memory", "cc");

    register uint32_t function_id __asm__("r0") = PSCI_0_2_FN_SYSTEM_OFF;
    __asm__ volatile("hvc #0"
                     : "+r"(function_id)
                     :
                     : "r1", "r2", "r3", "memory");

    KERROR("PSCI SYSTEM_OFF returned: 0x%08X\n", function_id);
    for (;;) {
        __asm__ volatile("wfi");
    }
}

void kernel_poweroff(void)
{
    if (shutdown_in_progress) {
        psci_system_off();
    }

    shutdown_in_progress = true;
    kprintf("System shutdown requested\n");

    shutdown_processes();
    shutdown_drivers();
    disable_interrupts();
    kprintf("Shutdown: interrupts disabled\n");
    kprintf("Shutdown: entering PSCI SYSTEM_OFF\n");
    psci_system_off();
    __builtin_unreachable();
}

int sys_shutdown(void)
{
    kernel_poweroff();
}
