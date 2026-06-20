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

static job_t* jobs_previous(void)
{
    job_t* current = jobs_current();
    job_t* previous = NULL;

    for (int i = 0; i < JOBS_MAX; i++) {
        if (jobs[i].state != JOB_EMPTY && &jobs[i] != current)
            previous = &jobs[i];
    }

    return previous;
}

static job_t* jobs_find_arg(int argc, char* argv[])
{
    const char* spec;
    int id;

    if (argc < 2)
        return jobs_current();

    spec = argv[1];
    if (strcmp(spec, "%%") == 0 || strcmp(spec, "%+") == 0)
        return jobs_current();
    if (strcmp(spec, "%-") == 0)
        return jobs_previous();

    if (spec[0] == '%') {
        spec++;
        if (!*spec)
            return jobs_current();
    }

    id = atoi(spec);
    if (id <= 0)
        return NULL;

    return jobs_find_by_id(id);
}

static const char* jobs_state_name(job_state_t state)
{
    switch (state) {
        case JOB_RUNNING: return "Running";
        case JOB_STOPPED: return "Stopped";
        case JOB_DONE: return "Done";
        default: return "Empty";
    }
}

static const char* jobs_signal_name(int sig)
{
    switch (sig) {
        case SIGINT: return "SIGINT";
        case SIGKILL: return "SIGKILL";
        case SIGTERM: return "SIGTERM";
        case SIGCONT: return "SIGCONT";
        case SIGSTOP: return "SIGSTOP";
        case SIGTSTP: return "SIGTSTP";
#ifdef SIGTTIN
        case SIGTTIN: return "SIGTTIN";
#endif
#ifdef SIGTTOU
        case SIGTTOU: return "SIGTTOU";
#endif
        default: return "signal";
    }
}

static void jobs_format_status(job_t* job, char* out, int out_size)
{
    if (!out || out_size <= 0)
        return;

    if (!job || job->state == JOB_EMPTY) {
        snprintf(out, out_size, "-");
        return;
    }

    if (job->state == JOB_STOPPED && WIFSTOPPED(job->status)) {
        int sig = WSTOPSIG(job->status);
        snprintf(out, out_size, "%s(%d)", jobs_signal_name(sig), sig);
        return;
    }

    if (job->state == JOB_DONE) {
        snprintf(out, out_size, "%d", job->status);
        return;
    }

    snprintf(out, out_size, "-");
}

static const char* jobs_stop_reason(int sig)
{
#ifdef SIGTTIN
    if (sig == SIGTTIN)
        return " (tty input)";
#endif
#ifdef SIGTTOU
    if (sig == SIGTTOU)
        return " (tty output)";
#endif
    return "";
}

static void jobs_format_state(job_t* job, char* out, int out_size, int long_format)
{
    if (!out || out_size <= 0)
        return;

    if (!job || job->state == JOB_EMPTY) {
        snprintf(out, out_size, "Empty");
        return;
    }

    if (job->state == JOB_STOPPED && WIFSTOPPED(job->status)) {
        int sig = WSTOPSIG(job->status);
        if (long_format)
            snprintf(out, out_size, "Stopped (%s)", jobs_signal_name(sig));
        else
            snprintf(out, out_size, "Stopped%s", jobs_stop_reason(sig));
        return;
    }

    snprintf(out, out_size, "%s", jobs_state_name(job->state));
}

static char jobs_marker(job_t* job)
{
    if (job == jobs_current())
        return '+';
    if (job == jobs_previous())
        return '-';
    return ' ';
}

static int jobs_shell_status_from_wait_status(int status)
{
    if (WIFSTOPPED(status) && WSTOPSIG(status) != 0)
        return 128 + WSTOPSIG(status);
    if (status < 0)
        return SHELL_ERROR;
    return status & 0xff;
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

    if (WIFSTOPPED(status) && WSTOPSIG(status) != 0) {
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

void jobs_print_stopped(int pgid)
{
    job_t* job = jobs_find_by_pgid(pgid);
    char state_buf[40];

    if (!job) {
        printf("\n[?] Stopped\n");
        return;
    }

    jobs_format_state(job, state_buf, sizeof(state_buf), 0);
    printf("\n[%d]%c %-22s %s\n",
           job->id, jobs_marker(job), state_buf, job->command);
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

static int jobs_reap(int notify)
{
    int status = 0;
    int pid;
    int notified = 0;

    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        job_t* job = jobs_find_by_pid(pid);

        if (job) {
            jobs_note_status(pid, status);
            if (notify && WIFSTOPPED(status) && WSTOPSIG(status) != 0) {
                int sig = WSTOPSIG(status);
                printf("[%d]+ Stopped%s        %s\n",
                       job->id, jobs_stop_reason(sig), job->command);
                notified++;
            } else if (notify && job->state == JOB_DONE) {
                printf("[%d]+ Done                   %s\n",
                       job->id, job->command);
                notified++;
            }
        } else if (notify) {
            printf("[bg] pid %d done status=%d\n", pid, status);
            notified++;
        }
    }

    return notified;
}

int jobs_reap_background(void)
{
    return jobs_reap(1);
}

int jobs_builtin(int argc, char* argv[])
{
    int shown = 0;
    int long_format = 0;
    int pids_only = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            long_format = 1;
        } else if (strcmp(argv[i], "-p") == 0) {
            pids_only = 1;
        } else {
            printf("jobs: usage: jobs [-l|-p]\n");
            return SHELL_ERROR;
        }
    }

    jobs_reap(0);

    for (int i = 0; i < JOBS_MAX; i++) {
        job_t* job = &jobs[i];
        char state_buf[40];

        if (job->state == JOB_EMPTY)
            continue;

        if (pids_only) {
            printf("%d\n", job->pgid);
            shown++;
            continue;
        }

        jobs_format_state(job, state_buf, sizeof(state_buf), long_format);
        if (long_format) {
            char status_buf[32];
            jobs_format_status(job, status_buf, sizeof(status_buf));
            printf("[%d]%c %-5d pgid=%-5d %-18s status=%-12s %s\n",
                   job->id, jobs_marker(job), job->pids[0], job->pgid,
                   state_buf, status_buf, job->command);
        } else {
            printf("[%d]%c %-22s %s\n",
                   job->id, jobs_marker(job), state_buf, job->command);
        }
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
        printf("[%d] Done pid=%d status=%d  %s\n",
               job->id, job->pids[0], job->status, job->command);
        job->state = JOB_EMPTY;
        return jobs_shell_status_from_wait_status(job->status);
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

    return jobs_shell_status_from_wait_status(status);
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
        printf("[%d] Done pid=%d status=%d  %s\n",
               job->id, job->pids[0], job->status, job->command);
        return jobs_shell_status_from_wait_status(job->status);
    }

    jobs_continue(job);
    printf("[%d]+ %s &\n", job->id, job->command);
    return SHELL_OK;
}
