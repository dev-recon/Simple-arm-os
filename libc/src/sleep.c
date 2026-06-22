/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: libc/src/sleep.c
 * Layer: Userland / legacy libc
 * Description: Legacy freestanding C runtime support kept for compatibility.
 */

#include <unistd.h>
#include <time.h>
#include <errno.h>

extern int nanosleep(const struct timespec *req, struct timespec *rem);

unsigned int sleep(unsigned int seconds) {
    struct timespec req, rem;
    
    req.tv_sec = seconds;
    req.tv_nsec = 0;
    
    while (nanosleep(&req, &rem) < 0) {
        if (errno != EINTR)
            return req.tv_sec;

        if (rem.tv_sec == 0 && rem.tv_nsec == 0)
            return 0;

        req = rem;
    }
    
    return 0;
}

int usleep(useconds_t usec) {
    struct timespec req;
    
    req.tv_sec = usec / 1000000;
    req.tv_nsec = (usec % 1000000) * 1000;
    
    return nanosleep(&req, NULL);
}
