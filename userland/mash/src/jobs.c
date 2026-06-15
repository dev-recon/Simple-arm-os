#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../include/jobs.h"

#define JOBS_MAX 32

typedef enum job_state {
    JOB_EMPTY = 0,
    JOB_RUNNING,
    JOB_DONE
} job_state_t;

typedef struct job {
    int id;
    int pid;
    int pgid;
    int status;
    job_state_t state;
    char command[JOBS_COMMAND_LEN];
} job_t;

static job_t jobs[JOBS_MAX];
static int next_job_id = 1;

void jobs_build_command(int argc, char* argv[], char* out, int out_size)
{
    int used = 0;

    if (!out || out_size <= 0)
        return;

    out[0] = '\0';

    for (int i = 0; i < argc && argv[i]; i++) {
        int remaining = out_size - used;
        int written;

        if (remaining <= 1)
            break;

        written = snprintf(out + used, remaining, "%s%s", i ? " " : "", argv[i]);
        if (written < 0)
            break;
        if (written >= remaining) {
            out[out_size - 1] = '\0';
            break;
        }
        used += written;
    }
}

static job_t* jobs_find_by_pid(int pid)
{
    for (int i = 0; i < JOBS_MAX; i++) {
        if (jobs[i].state != JOB_EMPTY && jobs[i].pid == pid)
            return &jobs[i];
    }
    return NULL;
}

void jobs_add(int pid, int pgid, const char* command)
{
    job_t* job = NULL;

    for (int i = 0; i < JOBS_MAX; i++) {
        if (jobs[i].state == JOB_EMPTY) {
            job = &jobs[i];
            break;
        }
    }

    if (!job) {
        printf("mash: job table full\n");
        return;
    }

    job->id = next_job_id++;
    job->pid = pid;
    job->pgid = pgid;
    job->status = 0;
    job->state = JOB_RUNNING;
    strncpy(job->command, command ? command : "", JOBS_COMMAND_LEN - 1);
    job->command[JOBS_COMMAND_LEN - 1] = '\0';
}

void jobs_reap_background(void)
{
    int status = 0;
    int pid;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        job_t* job = jobs_find_by_pid(pid);

        if (job) {
            job->status = status;
            job->state = JOB_DONE;
            printf("[%d] done pid %d status=%d  %s\n",
                   job->id, pid, status, job->command);
        } else {
            printf("[bg] pid %d done status=%d\n", pid, status);
        }
    }
}

int jobs_builtin(int argc, char* argv[])
{
    int shown = 0;

    (void)argc;
    (void)argv;

    jobs_reap_background();

    for (int i = 0; i < JOBS_MAX; i++) {
        job_t* job = &jobs[i];

        if (job->state == JOB_EMPTY)
            continue;

        printf("[%d] %-7s pid=%d pgid=%d status=%d  %s\n",
               job->id,
               job->state == JOB_RUNNING ? "running" : "done",
               job->pid, job->pgid, job->status, job->command);
        shown++;
    }

    for (int i = 0; i < JOBS_MAX; i++) {
        if (jobs[i].state == JOB_DONE)
            jobs[i].state = JOB_EMPTY;
    }

    if (!shown)
        printf("jobs: no background jobs\n");

    return SHELL_OK;
}
