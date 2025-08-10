/* ====== include/kernel/signal.h - Correction avec forward declaration ====== */
#ifndef _KERNEL_SIGNAL_H
#define _KERNEL_SIGNAL_H

#include <kernel/types.h>
#include <kernel/task.h>


/* Signal numbers */
#define SIGHUP      1
#define SIGINT      2
#define SIGQUIT     3
#define SIGILL      4
#define SIGTRAP     5
#define SIGABRT     6
#define SIGBUS      7
#define SIGFPE      8
#define SIGKILL     9
#define SIGUSR1    10
#define SIGSEGV    11
#define SIGUSR2    12
#define SIGPIPE    13
#define SIGALRM    14
#define SIGTERM    15
#define SIGCHLD    17
#define SIGCONT    18
#define SIGSTOP    19
#define SIGTSTP    20

/* Signal flags */
#define SA_RESTART    0x01
#define SA_NODEFER    0x02
#define SA_RESETHAND  0x04

/* Signal functions */
void init_process_signals(task_t* proc);
int send_signal(task_t* target, int sig);
void check_pending_signals(void);
void deliver_signal(task_t* proc, int sig);
bool has_pending_signals(task_t* proc);

void print_signal_stack_stats(void);
void cleanup_process_signals(task_t* proc);
void init_signal_stack_allocator(void);
   
#endif