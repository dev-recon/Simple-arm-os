#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include "../include/jobs.h"

#define JOBS_MAX 32
#define JOBS_MAX_PIDS 8

typedef enum job_state {
    JOB_EMPTY = 0,
    JOB_RUNNING,
    JOB_STOPPED,
    JOB_DONE
} job_state_t;

typedef enum job_pid_state {
    JOB_PID_RUNNING = 0,
    JOB_PID_STOPPED,
    JOB_PID_DONE
} job_pid_state_t;

typedef struct job {
    int id;
    int pids[JOBS_MAX_PIDS];
    int statuses[JOBS_MAX_PIDS];
    job_pid_state_t pid_states[JOBS_MAX_PIDS];
    int pid_count;
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
        if (jobs[i].state == JOB_EMPTY)
            continue;
        for (int j = 0; j < jobs[i].pid_count; j++) {
            if (jobs[i].pids[j] == pid)
                return &jobs[i];
        }
    }
    return NULL;
}

static job_t* jobs_find_by_pgid(int pgid)
{
    for (int i = 0; i < JOBS_MAX; i++) {
        if (jobs[i].state != JOB_EMPTY && jobs[i].pgid == pgid)
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

static const char* jobs_state_name(job_state_t state)
{
    switch (state) {
        case JOB_RUNNING: return "running";
        case JOB_STOPPED: return "stopped";
        case JOB_DONE: return "done";
        default: return "empty";
    }
}

static int jobs_find_pid_slot(job_t* job, int pid)
{
    if (!job)
        return -1;

    for (int i = 0; i < job->pid_count; i++) {
        if (job->pids[i] == pid)
            return i;
    }

    return -1;
}

static void jobs_update_state(job_t* job)
{
    int running = 0;
    int stopped = 0;
    int done = 0;

    if (!job || job->state == JOB_EMPTY)
        return;

    for (int i = 0; i < job->pid_count; i++) {
        if (job->pid_states[i] == JOB_PID_DONE)
            done++;
        else if (job->pid_states[i] == JOB_PID_STOPPED)
            stopped++;
        else
            running++;
    }

    if (done == job->pid_count)
        job->state = JOB_DONE;
    else if (stopped > 0 && running == 0)
        job->state = JOB_STOPPED;
    else
        job->state = JOB_RUNNING;
}

static int jobs_has_stopped_pid(job_t* job)
{
    if (!job)
        return 0;

    for (int i = 0; i < job->pid_count; i++) {
        if (job->pid_states[i] == JOB_PID_STOPPED)
            return 1;
    }

    return 0;
}

static int jobs_append_pid(job_t* job, int pid)
{
    int slot;

    if (!job)
        return -1;

    if (jobs_find_pid_slot(job, pid) >= 0)
        return 0;

    if (job->pid_count >= JOBS_MAX_PIDS) {
        printf("mash: job has too many processes\n");
        return -1;
    }

    slot = job->pid_count++;
    job->pids[slot] = pid;
    job->statuses[slot] = 0;
    job->pid_states[slot] = JOB_PID_RUNNING;
    job->state = JOB_RUNNING;
    return 0;
}

void jobs_add(int pid, int pgid, const char* command)
{
    job_t* job;

    job = jobs_find_by_pgid(pgid);
    if (job) {
        jobs_append_pid(job, pid);
        return;
    }

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
    job->pid_count = 0;
    job->pgid = pgid;
    job->status = 0;
    job->state = JOB_RUNNING;
    strncpy(job->command, command ? command : "", JOBS_COMMAND_LEN - 1);
    job->command[JOBS_COMMAND_LEN - 1] = '\0';
    jobs_append_pid(job, pid);
}

void jobs_note_status(int pid, int status)
{
    job_t* job = jobs_find_by_pid(pid);
    int slot;

    if (!job)
        return;

    slot = jobs_find_pid_slot(job, pid);
    if (slot < 0)
        return;

    job->statuses[slot] = status;

    if (WIFSTOPPED(status)) {
        job->pid_states[slot] = JOB_PID_STOPPED;
        job->status = status;
    } else {
        job->pid_states[slot] = JOB_PID_DONE;
        if (!jobs_has_stopped_pid(job))
            job->status = status;
    }

    jobs_update_state(job);
    if (job->state == JOB_DONE)
        job->status = status;
}

static void jobs_continue(job_t* job)
{
    if (!job || job->state == JOB_EMPTY)
        return;

    if (job->state == JOB_STOPPED) {
        kill(-job->pgid, SIGCONT);
        for (int i = 0; i < job->pid_count; i++) {
            if (job->pid_states[i] == JOB_PID_STOPPED)
                job->pid_states[i] = JOB_PID_RUNNING;
        }
        job->state = JOB_RUNNING;
    }
}

static void jobs_reap(int notify)
{
    int status = 0;
    int pid;

    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        job_t* job = jobs_find_by_pid(pid);

        if (job) {
            jobs_note_status(pid, status);
            if (notify && WIFSTOPPED(status))
                printf("[%d] stopped pgid=%d signal=%d  %s\n",
                       job->id, job->pgid, WSTOPSIG(status), job->command);
            else if (notify && job->state == JOB_DONE)
                printf("[%d] done pgid=%d status=%d  %s\n",
                       job->id, job->pgid, status, job->command);
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
               jobs_state_name(job->state),
               job->pids[0], job->pgid, job->status, job->command);
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
               job->id, job->pids[0], job->status, job->command);
        job->state = JOB_EMPTY;
        return job->status;
    }

    printf("%s\n", job->command);
    jobs_continue(job);
    tcsetpgrp(STDIN_FILENO, job->pgid);
    while (job->state == JOB_RUNNING) {
        int pid = waitpid(-job->pgid, &status, WUNTRACED);

        if (pid <= 0)
            break;

        jobs_note_status(pid, status);
    }
    if (shell_pgid > 0)
        tcsetpgrp(STDIN_FILENO, shell_pgid);

    if (job->state == JOB_DONE)
        job->state = JOB_EMPTY;

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
               job->id, job->pids[0], job->status, job->command);
        return job->status;
    }

    jobs_continue(job);
    printf("[%d] running pid=%d pgid=%d  %s\n",
           job->id, job->pids[0], job->pgid, job->command);
    return SHELL_OK;
}
