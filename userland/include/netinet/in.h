/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/include/netinet/in.h
 * Layer: Userland / C library compatibility
 *
 * Responsibilities:
 * - Define the minimal IPv4 sockaddr structures used by early network tools.
 */

#ifndef _ARMOS_NETINET_IN_H
#define _ARMOS_NETINET_IN_H

#include <stdint.h>
#include <sys/socket.h>

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define INADDR_ANY 0x00000000u

typedef uint16_t in_port_t;
typedef uint32_t in_addr_t;

struct in_addr {
    in_addr_t s_addr;
};

struct sockaddr_in {
    sa_family_t sin_family;
    in_port_t sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[8];
};

static inline uint16_t htons(uint16_t x)
{
    return (uint16_t)((x << 8) | (x >> 8));
}

static inline uint16_t ntohs(uint16_t x)
{
    return htons(x);
}

static inline uint32_t htonl(uint32_t x)
{
    return ((x & 0x000000FFu) << 24) |
           ((x & 0x0000FF00u) << 8) |
           ((x & 0x00FF0000u) >> 8) |
           ((x & 0xFF000000u) >> 24);
}

static inline uint32_t ntohl(uint32_t x)
{
    return htonl(x);
}

#endif /* _ARMOS_NETINET_IN_H */
