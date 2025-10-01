#ifndef _SIGNAL_H
#define _SIGNAL_H

#include <stdint.h>

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

/* Signal actions */
typedef enum {
    SIG_ACT_TERM,
    SIG_ACT_IGN,
    SIG_ACT_CORE,
    SIG_ACT_STOP,
    SIG_ACT_CONT
} sig_default_action;

/* Signal handler */
typedef void (*sig_handler)(int);
#define SIG_DFL  ((sig_handler)0)
#define SIG_IGN  ((sig_handler)1)

/* Sigaction structure */
typedef struct sigaction {
    sig_handler sa_handler;
    uint32_t sa_mask;
    int sa_flags;
} ;


int signal(int sig, sig_handler handler); 
int sigaction(int sig, const struct sigaction* act, struct sigaction* oldact);
   
#endif