/* src/jobs.c */
#include "shell.h"

static int next_job_id = 1;

void init_job_control(void) {
    int i;
    
    for (i = 0; i < MAX_JOBS; i++) {
        shell_state.jobs[i].id = 0;
        shell_state.jobs[i].pgid = 0;
        shell_state.jobs[i].command = NULL;
        shell_state.jobs[i].running = 0;
        shell_state.jobs[i].background = 0;
        shell_state.jobs[i].pids = NULL;
        shell_state.jobs[i].pid_count = 0;
    }
    
    shell_state.job_count = 0;
}

void add_job(pid_t pgid, const char* command, int background, pid_t* pids, int pid_count) {
    int i;
    
    /* Chercher un slot libre */
    for (i = 0; i < MAX_JOBS; i++) {
        if (shell_state.jobs[i].id == 0) {
            job_t* job = &shell_state.jobs[i];
            
            job->id = next_job_id++;
            job->pgid = pgid;
            job->command = strdup(command);
            job->running = 1;
            job->background = background;
            job->pid_count = pid_count;
            
            /* Copier les PIDs */
            job->pids = malloc(pid_count * sizeof(pid_t));
            if (job->pids) {
                int j;
                for (j = 0; j < pid_count; j++) {
                    job->pids[j] = pids[j];
                }
            }
            
            shell_state.job_count++;
            return;
        }
    }
}

void remove_job(int job_id) {
    int i;
    
    for (i = 0; i < MAX_JOBS; i++) {
        if (shell_state.jobs[i].id == job_id) {
            job_t* job = &shell_state.jobs[i];
            
            free(job->command);
            free(job->pids);
            
            job->id = 0;
            job->pgid = 0;
            job->command = NULL;
            job->running = 0;
            job->background = 0;
            job->pids = NULL;
            job->pid_count = 0;
            
            shell_state.job_count--;
            return;
        }
    }
}

job_t* find_job(int job_id) {
    int i;
    
    for (i = 0; i < MAX_JOBS; i++) {
        if (shell_state.jobs[i].id == job_id) {
            return &shell_state.jobs[i];
        }
    }
    
    return NULL;
}

job_t* find_job_by_pgid(pid_t pgid) {
    int i;
    
    for (i = 0; i < MAX_JOBS; i++) {
        if (shell_state.jobs[i].pgid == pgid) {
            return &shell_state.jobs[i];
        }
    }
    
    return NULL;
}

void update_job_status(void) {
    int i;
    pid_t pid;
    int status;
    
    /* Verifier les processus termines */
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        /* Trouver le job correspondant */
        for (i = 0; i < MAX_JOBS; i++) {
            job_t* job = &shell_state.jobs[i];
            if (job->id > 0) {
                int j;
                for (j = 0; j < job->pid_count; j++) {
                    if (job->pids[j] == pid) {
                        if (WIFEXITED(status) || WIFSIGNALED(status)) {
                            /* Processus termine */
                            job->pids[j] = -1; /* Marquer comme termine */
                            
                            /* Verifier si tous les processus du job sont termines */
                            int all_done = 1;
                            int k;
                            for (k = 0; k < job->pid_count; k++) {
                                if (job->pids[k] != -1) {
                                    all_done = 0;
                                    break;
                                }
                            }
                            
                            if (all_done) {
                                if (job->background) {
                                    printf("\n[%d]+  Done\t\t%s\n", job->id, job->command);
                                }
                                remove_job(job->id);
                            }
                        } else if (WIFSTOPPED(status)) {
                            /* Processus arrete */
                            job->running = 0;
                            if (job->background) {
                                printf("\n[%d]+  Stopped\t\t%s\n", job->id, job->command);
                            }
                        }
                        goto next_pid;
                    }
                }
            }
        }
        next_pid:;
    }
}

void cleanup_jobs(void) {
    int i;
    
    for (i = 0; i < MAX_JOBS; i++) {
        if (shell_state.jobs[i].id > 0) {
            remove_job(shell_state.jobs[i].id);
        }
    }
}