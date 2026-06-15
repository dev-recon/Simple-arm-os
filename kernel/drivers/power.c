#include <kernel/power.h>
#include <kernel/kprintf.h>
#include <kernel/types.h>
#include <kernel/task.h>
#include <kernel/process.h>
#include <kernel/virtio_block.h>
#include <asm/arm.h>

#define PSCI_0_2_FN_SYSTEM_OFF 0x84000008u

static volatile bool shutdown_in_progress = false;

static void shutdown_processes(void)
{
    task_t *task = task_list_head;
    unsigned count = 0;

    if (!task)
        return;

    KINFO("Shutdown: stopping user processes\n");

    do {
        task_t *next = task->next;

        if (task->type == TASK_TYPE_PROCESS && task->process) {
            if (task != current_task) {
                close_all_process_files(task);
                task->state = TASK_TERMINATED;
                task->process->state = (proc_state_t)PROC_DEAD;
            }
        }

        task = next;
        count++;
    } while (task && task != task_list_head && count < MAX_TASKS);

    if (current_task && current_task->type == TASK_TYPE_PROCESS && current_task->process) {
        close_all_process_files(current_task);
    }
}

static void shutdown_drivers(void)
{
    KINFO("Shutdown: flushing and stopping block device\n");
    virtio_blk_shutdown();
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
    KINFO("System shutdown requested\n");

    shutdown_processes();
    shutdown_drivers();
    disable_interrupts();
    KINFO("Shutdown: entering PSCI SYSTEM_OFF\n");
    psci_system_off();
    __builtin_unreachable();
}

int sys_shutdown(void)
{
    kernel_poweroff();
}
