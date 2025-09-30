/* src/builtins.c */
#include <shell.h>
 
typedef struct {
    char* name;
    int (*func)(int argc, char** argv);
    char* help;
} builtin_t;

static builtin_t builtins[] = {
    {"cd", builtin_cd, "Changer de repertoire"},
    {"pwd", builtin_pwd, "Afficher le repertoire courant"},
    {"echo", builtin_echo, "Afficher du texte"},
    {"exit", builtin_exit, "Quitter le shell"},
    {"export", builtin_export, "Exporter une variable"},
    {"unset", builtin_unset, "Supprimer une variable"},
    {"env", builtin_env, "Afficher les variables d'environnement"},
    {"history", builtin_history, "Afficher l'historique"},
    {"jobs", builtin_jobs, "Afficher les jobs"},
    {"fg", builtin_fg, "Mettre un job au premier plan"},
    {"bg", builtin_bg, "Mettre un job en arriere-plan"},
    {"help", builtin_help, "Afficher cette aide"},
    {"test", builtin_test, "evaluer une expression conditionnelle"},
    {"true", builtin_true, "Retourner vrai"},
    {"false", builtin_false, "Retourner faux"},
    {"source", builtin_source, "Executer un fichier de commandes"},
    {".", builtin_source, "Executer un fichier de commandes"},
    {NULL, NULL, NULL}
};

int execute_builtin(const char* cmd, int argc, char** argv) {
    int i;
    
    for (i = 0; builtins[i].name; i++) {
        if (strcmp(cmd, builtins[i].name) == 0) {
            return builtins[i].func(argc, argv);
        }
    }
    
    return -1; /* Pas un builtin */
}

int builtin_cd(int argc, char** argv) {
    char* target_dir;
    char* oldpwd;
    
    if (argc == 1) {
        target_dir = getenv("HOME");
        if (!target_dir) {
            fprintf(stderr, "cd: HOME non defini\n");
            return 1;
        }
    } else if (argc == 2) {
        if (strcmp(argv[1], "-") == 0) {
            target_dir = getenv("OLDPWD");
            if (!target_dir) {
                fprintf(stderr, "cd: OLDPWD non defini\n");
                return 1;
            }
            printf("%s\n", target_dir);
        } else {
            target_dir = argv[1];
        }
    } else {
        fprintf(stderr, "cd: trop d'arguments\n");
        return 1;
    }
    
    /* Expansion du tilde */
    char* expanded_dir = expand_tilde(target_dir);
    
    /* Sauvegarder l'ancien repertoire */
    oldpwd = shell_state.cwd;
    
    if (chdir(expanded_dir) == -1) {
        perror("cd");
        free(expanded_dir);
        return 1;
    }
    
    /* Mettre a jour PWD et OLDPWD */
    setenv("OLDPWD", oldpwd, 1);
    
    free(shell_state.cwd);
    shell_state.cwd = getcwd(NULL, 0);
    setenv("PWD", shell_state.cwd, 1);
    
    free(expanded_dir);
    return 0;
}

int builtin_pwd(int argc, char** argv) {
    printf("%s\n", shell_state.cwd);
    return 0;
}

int builtin_echo(int argc, char** argv) {
    int i;
    int newline = 1;
    int start = 1;
    
    /* Option -n pour supprimer le newline */
    if (argc > 1 && strcmp(argv[1], "-n") == 0) {
        newline = 0;
        start = 2;
    }
    
    for (i = start; i < argc; i++) {
        if (i > start) {
            printf(" ");
        }
        printf("%s", argv[i]);
    }
    
    if (newline) {
        printf("\n");
    }
    
    return 0;
}

int builtin_exit(int argc, char** argv) {
    int status = shell_state.last_exit_status;
    
    if (argc > 1) {
        status = atoi(argv[1]);
    }
    
    shell_cleanup();
    exit(status);
}

int builtin_export(int argc, char** argv) {
    int i;
    
    if (argc == 1) {
        /* Afficher toutes les variables exportees */
        extern char** environ;
        char** env = environ;
        while (*env) {
            printf("export %s\n", *env);
            env++;
        }
        return 0;
    }
    
    for (i = 1; i < argc; i++) {
        char* equals = strchr(argv[i], '=');
        if (equals) {
            *equals = '\0';
            setenv(argv[i], equals + 1, 1);
            *equals = '='; /* Restaurer pour liberation */
        } else {
            /* Exporter une variable existante */
            char* value = get_shell_variable(argv[i]);
            if (!value) {
                value = getenv(argv[i]);
            }
            if (value) {
                setenv(argv[i], value, 1);
            } else {
                setenv(argv[i], "", 1);
            }
        }
    }
    
    return 0;
}

int builtin_unset(int argc, char** argv) {
    int i;
    
    for (i = 1; i < argc; i++) {
        unsetenv(argv[i]);
        unset_shell_variable(argv[i]);
    }
    
    return 0;
}

int builtin_env(int argc, char** argv) {
    extern char** environ;
    char** env = environ;
    
    while (*env) {
        printf("%s\n", *env);
        env++;
    }
    
    return 0;
}

int builtin_history(int argc, char** argv) {
    int i;
    int start = 0;
    int count = shell_state.history_count;
    
    /* Option -c pour effacer l'historique */
    if (argc > 1 && strcmp(argv[1], "-c") == 0) {
        for (i = 0; i < shell_state.history_count; i++) {
            free(shell_state.history[i]);
            shell_state.history[i] = NULL;
        }
        shell_state.history_count = 0;
        shell_state.history_index = 0;
        return 0;
    }
    
    /* Limiter le nombre d'entrees affichees */
    if (argc > 1) {
        int n = atoi(argv[1]);
        if (n > 0 && n < count) {
            start = count - n;
        }
    }
    
    for (i = start; i < count; i++) {
        printf("%4d  %s\n", i + 1, shell_state.history[i]);
    }
    
    return 0;
}

int builtin_jobs(int argc, char** argv) {
    int i;
    
    for (i = 0; i < shell_state.job_count; i++) {
        job_t* job = &shell_state.jobs[i];
        if (job->id > 0) {
            printf("[%d]%c %s\t\t%s\n", 
                   job->id,
                   job->running ? '+' : '-',
                   job->running ? "Running" : "Stopped",
                   job->command);
        }
    }
    
    return 0;
}

int builtin_fg(int argc, char** argv) {
    int job_id = 1;
    
    if (argc > 1) {
        if (argv[1][0] == '%') {
            job_id = atoi(argv[1] + 1);
        } else {
            job_id = atoi(argv[1]);
        }
    }
    
    job_t* job = find_job(job_id);
    if (!job) {
        fprintf(stderr, "fg: job %d introuvable\n", job_id);
        return 1;
    }
    
    /* Continuer le job s'il est arrete */
    if (!job->running) {
        kill(-job->pgid, SIGCONT);
        job->running = 1;
    }
    
    printf("%s\n", job->command);
    
    /* Attendre que le job se termine */
    int status;
    waitpid(job->pgid, &status, WUNTRACED);
    
    if (WIFSTOPPED(status)) {
        job->running = 0;
        printf("\n[%d]+  Stopped\t\t%s\n", job->id, job->command);
    } else {
        remove_job(job->id);
    }
    
    return 0;
}

int builtin_bg(int argc, char** argv) {
    int job_id = 1;
    
    if (argc > 1) {
        if (argv[1][0] == '%') {
            job_id = atoi(argv[1] + 1);
        } else {
            job_id = atoi(argv[1]);
        }
    }
    
    job_t* job = find_job(job_id);
    if (!job) {
        fprintf(stderr, "bg: job %d introuvable\n", job_id);
        return 1;
    }
    
    if (job->running) {
        fprintf(stderr, "bg: job %d deja en cours d'execution\n", job_id);
        return 1;
    }
    
    /* Continuer le job en arriere-plan */
    kill(-job->pgid, SIGCONT);
    job->running = 1;
    job->background = 1;
    
    printf("[%d]+ %s &\n", job->id, job->command);
    
    return 0;
}

int builtin_help(int argc, char** argv) {
    int i;
    
    if (argc == 1) {
        printf("MyShell - Commandes integrees:\n\n");
        
        for (i = 0; builtins[i].name; i++) {
            printf("  %-12s %s\n", builtins[i].name, builtins[i].help);
        }
        
        printf("\nUtilisez 'man nom_commande' pour les commandes externes.\n");
        printf("Utilisez 'help commande' pour plus d'informations sur une commande.\n");
    } else {
        /* Aide pour une commande specifique */
        for (i = 0; builtins[i].name; i++) {
            if (strcmp(argv[1], builtins[i].name) == 0) {
                printf("%s - %s\n", builtins[i].name, builtins[i].help);
                return 0;
            }
        }
        printf("help: %s: commande inconnue\n", argv[1]);
        return 1;
    }
    
    return 0;
}

int builtin_test(int argc, char** argv) {
    /* Implementation basique de test */
    if (argc < 2) {
        return 1;
    }
    
    if (argc == 2) {
        /* Test si la chaine est non-vide */
        return (strlen(argv[1]) == 0) ? 1 : 0;
    }
    
    if (argc == 3 && strcmp(argv[1], "!") == 0) {
        /* Negation */
        return (strlen(argv[2]) == 0) ? 0 : 1;
    }
    
    if (argc == 4) {
        char* op = argv[2];
        
        if (strcmp(op, "=") == 0 || strcmp(op, "==") == 0) {
            return (strcmp(argv[1], argv[3]) == 0) ? 0 : 1;
        } else if (strcmp(op, "!=") == 0) {
            return (strcmp(argv[1], argv[3]) != 0) ? 0 : 1;
        } else if (strcmp(op, "-eq") == 0) {
            return (atoi(argv[1]) == atoi(argv[3])) ? 0 : 1;
        } else if (strcmp(op, "-ne") == 0) {
            return (atoi(argv[1]) != atoi(argv[3])) ? 0 : 1;
        } else if (strcmp(op, "-lt") == 0) {
            return (atoi(argv[1]) < atoi(argv[3])) ? 0 : 1;
        } else if (strcmp(op, "-le") == 0) {
            return (atoi(argv[1]) <= atoi(argv[3])) ? 0 : 1;
        } else if (strcmp(op, "-gt") == 0) {
            return (atoi(argv[1]) > atoi(argv[3])) ? 0 : 1;
        } else if (strcmp(op, "-ge") == 0) {
            return (atoi(argv[1]) >= atoi(argv[3])) ? 0 : 1;
        } else if (strcmp(op, "-f") == 0) {
            struct stat st;
            return (stat(argv[3], &st) == 0 && S_ISREG(st.st_mode)) ? 0 : 1;
        } else if (strcmp(op, "-d") == 0) {
            struct stat st;
            return (stat(argv[3], &st) == 0 && S_ISDIR(st.st_mode)) ? 0 : 1;
        } else if (strcmp(op, "-e") == 0) {
            return (access(argv[3], F_OK) == 0) ? 0 : 1;
        }
    }
    
    return 1;
}

int builtin_true(int argc, char** argv) {
    return 0;
}

int builtin_false(int argc, char** argv) {
    return 1;
}

int builtin_source(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "source: nom de fichier requis\n");
        return 1;
    }
    
    execute_rc_file(argv[1]);
    return 0;
}