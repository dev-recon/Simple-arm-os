/* src/signals.c */
#include "shell.h"

void setup_signal_handlers(void) {
    /* SIGINT - Ctrl+C */
    signal(SIGINT, sigint_handler);
    
    /* SIGTSTP - Ctrl+Z */
    signal(SIGTSTP, sigtstp_handler);
    
    /* SIGCHLD - Enfant termine */
    signal(SIGCHLD, sigchld_handler);
    
    /* SIGQUIT - Ignorer par defaut dans le shell */
    signal(SIGQUIT, SIG_IGN);
    
    /* SIGTERM - Terminer proprement */
    signal(SIGTERM, sigint_handler);
}

void sigchld_handler(int sig) {
    /* eviter les warnings */
    (void)sig;
    
    /* Mettre a jour le statut des jobs */
    /* Note: Cette fonction est appelee de maniere asynchrone,
     * donc on evite les operations complexes ici */
}

void sigint_handler(int sig) {
    /* eviter les warnings */
    (void)sig;
    
    if (shell_state.interactive) {
        printf("\n");
        printf("%s", shell_state.prompt);
        fflush(stdout);
    } else {
        printf("\nInterruption detectee, fermeture...\n");
        shell_cleanup();
        exit(130);
    }
}

void sigtstp_handler(int sig) {
    /* eviter les warnings */
    (void)sig;
    
    if (shell_state.interactive) {
        printf("\n");
        printf("%s", shell_state.prompt);
        fflush(stdout);
    }
}