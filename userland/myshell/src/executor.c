/* src/executor.c */
#include "shell.h"

void execute_command_line(command_line_t* cmdline) {
    int i;
    
    for (i = 0; i < cmdline->pipeline_count; i++) {
        pipeline_t* pipeline = cmdline->pipelines[i];
        
        /* Executer le pipeline */
        int status = execute_pipeline(pipeline);
        
        /* Gerer les operateurs logiques */
        if (i < cmdline->pipeline_count - 1) {
            token_type_t sep = cmdline->separators[i];
            
            if (sep == TOKEN_AND && status != 0) {
                break; /* && : arreter si echec */
            } else if (sep == TOKEN_OR && status == 0) {
                break; /* || : arreter si succes */
            }
        }
        
        shell_state.last_exit_status = status;
    }
    
    /* Mettre a jour $? */
    char status_str[16];
    snprintf(status_str, sizeof(status_str), "%d", shell_state.last_exit_status);
    set_shell_variable("?", status_str);
}

int execute_pipeline(pipeline_t* pipeline) {
    if (pipeline->cmd_count == 1) {
        /* Commande simple */
        return execute_simple_command(pipeline->commands[0], pipeline->background);
    } else {
        /* Pipeline avec pipes */
        return execute_pipe_sequence(pipeline);
    }
}

int execute_simple_command(simple_cmd_t* cmd, int background) {
    if (cmd->argc == 0) {
        return 0;
    }
    
    /* Verifier les builtins */
    int builtin_result = execute_builtin(cmd->args[0], cmd->argc, cmd->args);
    if (builtin_result >= 0) {
        return builtin_result;
    }
    
    /* Commande externe */
    pid_t pid = fork();
    
    if (pid == 0) {
        /* Processus enfant */
        
        /* Appliquer les redirections */
        apply_redirections(cmd->redirects);
        
        /* Si background, ignorer SIGINT et SIGQUIT */
        if (background) {
            signal(SIGINT, SIG_IGN);
            signal(SIGQUIT, SIG_IGN);
        } else {
            signal(SIGINT, SIG_DFL);
            signal(SIGQUIT, SIG_DFL);
        }
        
        /* Executer la commande */
        execvp(cmd->args[0], cmd->args);
        
        /* Si on arrive ici, exec a echoue */
        fprintf(stderr, "myshell: %s: commande introuvable\n", cmd->args[0]);
        exit(127);
        
    } else if (pid > 0) {
        /* Processus parent */
        
        if (background) {
            /* Job en arriere-plan */
            add_job(pid, cmd->args[0], 1, &pid, 1);
            printf("[%d] %d\n", shell_state.job_count, pid);
            return 0;
        } else {
            /* Attendre la fin */
            int status;
            waitpid(pid, &status, 0);
            return WEXITSTATUS(status);
        }
        
    } else {
        perror("fork");
        return 1;
    }
}

int execute_pipe_sequence(pipeline_t* pipeline) {
    int pipes[MAX_ARGS][2];
    pid_t pids[MAX_ARGS];
    int i;
    
    /* Creer les pipes */
    for (i = 0; i < pipeline->cmd_count - 1; i++) {
        if (pipe(pipes[i]) == -1) {
            perror("pipe");
            return 1;
        }
    }
    
    /* Lancer les processus */
    for (i = 0; i < pipeline->cmd_count; i++) {
        pids[i] = fork();
        
        if (pids[i] == 0) {
            /* Processus enfant */
            
            /* Connecter stdin */
            if (i > 0) {
                dup2(pipes[i-1][0], STDIN_FILENO);
            }
            
            /* Connecter stdout */
            if (i < pipeline->cmd_count - 1) {
                dup2(pipes[i][1], STDOUT_FILENO);
            }
            
            /* Fermer tous les pipes */
            int j;
            for (j = 0; j < pipeline->cmd_count - 1; j++) {
                close(pipes[j][0]);
                close(pipes[j][1]);
            }
            
            /* Appliquer les redirections */
            apply_redirections(pipeline->commands[i]->redirects);
            
            /* Configuration des signaux */
            if (pipeline->background) {
                signal(SIGINT, SIG_IGN);
                signal(SIGQUIT, SIG_IGN);
            } else {
                signal(SIGINT, SIG_DFL);
                signal(SIGQUIT, SIG_DFL);
            }
            
            /* Executer la commande */
            simple_cmd_t* cmd = pipeline->commands[i];
            
            int builtin_result = execute_builtin(cmd->args[0], cmd->argc, cmd->args);
            if (builtin_result >= 0) {
                exit(builtin_result);
            }
            
            execvp(cmd->args[0], cmd->args);
            fprintf(stderr, "myshell: %s: commande introuvable\n", cmd->args[0]);
            exit(127);
            
        } else if (pids[i] < 0) {
            perror("fork");
            return 1;
        }
    }
    
    /* Fermer les pipes dans le parent */
    for (i = 0; i < pipeline->cmd_count - 1; i++) {
        close(pipes[i][0]);
        close(pipes[i][1]);
    }
    
    /* Attendre tous les processus */
    int last_status = 0;
    if (pipeline->background) {
        /* Job en arriere-plan */
        add_job(pids[0], "pipeline", 1, pids, pipeline->cmd_count);
        printf("[%d] %d\n", shell_state.job_count, pids[0]);
    } else {
        for (i = 0; i < pipeline->cmd_count; i++) {
            int status;
            waitpid(pids[i], &status, 0);
            if (i == pipeline->cmd_count - 1) {
                last_status = WEXITSTATUS(status);
            }
        }
    }
    
    return last_status;
}

void apply_redirections(redirect_t* redirects) {
    redirect_t* redir = redirects;
    
    while (redir) {
        int fd;
        
        switch (redir->type) {
            case TOKEN_REDIRECT_IN:
                fd = open(redir->filename, O_RDONLY);
                if (fd >= 0) {
                    dup2(fd, redir->fd);
                    close(fd);
                } else {
                    perror(redir->filename);
                    exit(1);
                }
                break;
                
            case TOKEN_REDIRECT_OUT:
                fd = open(redir->filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd >= 0) {
                    dup2(fd, redir->fd);
                    close(fd);
                } else {
                    perror(redir->filename);
                    exit(1);
                }
                break;
                
            case TOKEN_REDIRECT_APPEND:
                fd = open(redir->filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
                if (fd >= 0) {
                    dup2(fd, redir->fd);
                    close(fd);
                } else {
                    perror(redir->filename);
                    exit(1);
                }
                break;
                
            default:
                break;
        }
        
        redir = redir->next;
    }
}