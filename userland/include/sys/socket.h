/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/include/sys/socket.h
 * Layer: Userland / C library compatibility
 *
 * Responsibilities:
 * - Provide the small BSD socket surface currently implemented by ArmOS.
 * - Keep source compatibility with simple POSIX-style network tools.
 */

#ifndef _ARMOS_SYS_SOCKET_H
#define _ARMOS_SYS_SOCKET_H

#include <stddef.h>
#include <sys/types.h>

#define AF_INET      2
#define PF_INET      AF_INET
#define SOCK_STREAM  1

typedef unsigned int socklen_t;
typedef unsigned short sa_family_t;

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};

int socket(int domain, int type, int protocol);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

#endif /* _ARMOS_SYS_SOCKET_H */
