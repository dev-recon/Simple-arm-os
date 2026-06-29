/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/include/sys/resource.h
 * Layer: Userland / POSIX compatibility
 * Description: Minimal resource-priority declarations for newlib programs.
 */

#ifndef ARMOS_SYS_RESOURCE_H
#define ARMOS_SYS_RESOURCE_H

#include <sys/types.h>
#include <sys/time.h>

#define PRIO_PROCESS 0
#define PRIO_PGRP    1
#define PRIO_USER    2

#define RUSAGE_SELF      0
#define RUSAGE_CHILDREN -1

struct rusage {
    struct timeval ru_utime;
    struct timeval ru_stime;
    long ru_maxrss;
    long ru_ixrss;
    long ru_idrss;
    long ru_isrss;
    long ru_minflt;
    long ru_majflt;
    long ru_nswap;
    long ru_inblock;
    long ru_oublock;
    long ru_msgsnd;
    long ru_msgrcv;
    long ru_nsignals;
    long ru_nvcsw;
    long ru_nivcsw;
};

int getpriority(int which, id_t who);
int setpriority(int which, id_t who, int prio);
int getrusage(int who, struct rusage *usage);

#endif /* ARMOS_SYS_RESOURCE_H */
