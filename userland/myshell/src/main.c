/* src/main.c */
#include "../userland/myshell/include/shell.h"

shell_state_t shell_state;

int main(int argc, char** argv) {
    shell_init(argc, argv);
    shell_loop();
    shell_cleanup();
    return shell_state.last_exit_status;
}

void shell_init(int argc, char** argv) {
    /* Initialiser l'etat du shell */
    memset(&shell_state, 0, sizeof(shell_state_t));
    
    shell_state.prompt = strdup("myshell$ ");
    shell_state.cwd = getcwd(NULL, 0);
    shell_state.last_exit_status = 0;
    shell_state.interactive = isatty(STDIN_FILENO);
    shell_state.history_count = 0;
    shell_state.history_index = 0;
    shell_state.job_count = 0;
    shell_state.variables = NULL;
    
    /* Allouer l'historique */
    shell_state.history = malloc(MAX_HISTORY * sizeof(char*));
    if (!shell_state.history) {
        perror("malloc");
        exit(1);
    }
    
    /* Sauvegarder les attributs du terminal */
    if (shell_state.interactive) {
        tcgetattr(STDIN_FILENO, &shell_state.original_termios);
    }
    
    /* Initialiser les variables du shell */
    init_shell_variables(argc, argv);
    
    /* Configurer les gestionnaires de signaux */
    setup_signal_handlers();
    
    /* Initialiser le controle des jobs */
    init_job_control();
    
    /* Charger les fichiers RC */
    load_rc_files();
    
    /* Charger l'historique */
    load_history(".myshell_history");
    
    if (shell_state.interactive) {
        printf("MyShell v1.0 - Tapez 'help' pour l'aide\n");
    }
}

void shell_cleanup(void) {
    int i;
    
    /* Sauvegarder l'historique */
    save_history(".myshell_history");
    
    /* Liberer l'historique */
    for (i = 0; i < shell_state.history_count; i++) {
        free(shell_state.history[i]);
    }
    free(shell_state.history);
    
    /* Nettoyer les jobs */
    cleanup_jobs();
    
    /* Liberer les variables */
    shell_var_t* var = shell_state.variables;
    while (var) {
        shell_var_t* next = var->next;
        free(var->name);
        free(var->value);
        free(var);
        var = next;
    }
    
    /* Liberer les autres ressources */
    free(shell_state.prompt);
    free(shell_state.cwd);
    
    /* Restaurer les attributs du terminal */
    if (shell_state.interactive) {
        tcsetattr(STDIN_FILENO, TCSANOW, &shell_state.original_termios);
    }
}

void shell_loop(void) {
    char* line;
    command_line_t* cmdline;
    token_t* tokens;
    
    while (1) {
        /* Mettre a jour le statut des jobs */
        update_job_status();
        
        /* Mettre a jour le prompt */
        update_prompt();
        
        /* Lire une ligne */
        line = read_line();
        if (!line) {
            break; /* EOF */
        }
        
        /* Ignorer les lignes vides */
        if (strlen(line) == 0) {
            free(line);
            continue;
        }
        
        /* Ajouter a l'historique */
        add_to_history(line);
        
        /* Tokeniser */
        tokens = tokenize(line);
        if (!tokens) {
            free(line);
            continue;
        }
        
        /* Parser */
        cmdline = parse_command_line(tokens);
        if (!cmdline) {
            free_tokens(tokens);
            free(line);
            continue;
        }
        
        /* Executer */
        execute_command_line(cmdline);
        
        /* Nettoyer */
        free_command_line(cmdline);
        free_tokens(tokens);
        free(line);
    }
}

char* read_line(void) {
    char* line = NULL;
    size_t bufsize = 0;
    
    if (shell_state.interactive) {
        printf("%s", shell_state.prompt);
        fflush(stdout);
    }
    
    if (getline(&line, &bufsize, stdin) == -1) {
        if (feof(stdin)) {
            if (shell_state.interactive) {
                printf("\n");
            }
            return NULL;
        } else {
            perror("getline");
            return NULL;
        }
    }
    
    /* Enlever le newline */
    size_t len = strlen(line);
    if (len > 0 && line[len-1] == '\n') {
        line[len-1] = '\0';
    }
    
    return line;
}