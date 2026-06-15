#include <stdio.h>
#include <stdlib.h>
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
static int shell_pgid = 0;

void jobs_set_shell_pgid(int pgid)
{
    shell_pgid = pgid;
}

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

static job_t* jobs_find_by_id(int id)
{
    for (int i = 0; i < JOBS_MAX; i++) {
        if (jobs[i].state != JOB_EMPTY && jobs[i].id == id)
            return &jobs[i];
    }
    return NULL;
}

static job_t* jobs_current(void)
{
    job_t* current = NULL;

    for (int i = 0; i < JOBS_MAX; i++) {
        if (jobs[i].state != JOB_EMPTY)
            current = &jobs[i];
    }

    return current;
}

static job_t* jobs_find_arg(int argc, char* argv[])
{
    const char* spec;
    int id;

    if (argc < 2)
        return jobs_current();

    spec = argv[1];
    if (spec[0] == '%')
        spec++;

    id = atoi(spec);
    if (id <= 0)
        return NULL;

    return jobs_find_by_id(id);
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

static void jobs_reap(int notify)
{
    int status = 0;
    int pid;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        job_t* job = jobs_find_by_pid(pid);

        if (job) {
            job->status = status;
            job->state = JOB_DONE;
            if (notify)
                printf("[%d] done pid %d status=%d  %s\n",
                       job->id, pid, status, job->command);
        } else if (notify) {
            printf("[bg] pid %d done status=%d\n", pid, status);
        }
    }
}

void jobs_reap_background(void)
{
    jobs_reap(1);
}

int jobs_builtin(int argc, char* argv[])
{
    int shown = 0;

    (void)argc;
    (void)argv;

    jobs_reap(0);

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

int jobs_fg_builtin(int argc, char* argv[])
{
    job_t* job;
    int status = 0;

    job = jobs_find_arg(argc, argv);
    if (!job) {
        printf("fg: no such job\n");
        return SHELL_ERROR;
    }

    if (job->state == JOB_DONE) {
        printf("[%d] done pid=%d status=%d  %s\n",
               job->id, job->pid, job->status, job->command);
        job->state = JOB_EMPTY;
        return job->status;
    }

    printf("%s\n", job->command);
    stty(TTY_STTY_SET_FOREGROUND_PGID, job->pgid);
    if (waitpid(job->pid, &status, 0) == job->pid) {
        job->status = status;
        job->state = JOB_EMPTY;
    }
    if (shell_pgid > 0)
        stty(TTY_STTY_SET_FOREGROUND_PGID, shell_pgid);

    return status;
}

int jobs_bg_builtin(int argc, char* argv[])
{
    job_t* job;

    job = jobs_find_arg(argc, argv);
    if (!job) {
        printf("bg: no such job\n");
        return SHELL_ERROR;
    }

    if (job->state == JOB_DONE) {
        printf("[%d] done pid=%d status=%d  %s\n",
               job->id, job->pid, job->status, job->command);
        return job->status;
    }

    printf("[%d] running pid=%d pgid=%d  %s\n",
           job->id, job->pid, job->pgid, job->command);
    return SHELL_OK;
}
