/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/ping.c
 * Layer: Userland / network utilities
 *
 * Responsibilities:
 * - Send bounded ICMP echo requests through the common ArmOS IPv4 stack.
 * - Report per-request latency and an aggregate packet-loss summary.
 *
 * Notes:
 * - This first implementation accepts numeric IPv4 destinations. DNS name
 *   resolution belongs to the resolver and socket API milestone.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PING_RESPONSE_SIZE 256
#define PING_DEFAULT_COUNT 4u
#define PING_DEFAULT_TIMEOUT_MS 1000u
#define PING_MAX_COUNT 1000u

static void usage(void)
{
    fprintf(stderr,
            "usage: ping [-c count] [-W timeout_seconds] "
            "[-I interface] IPv4-address\n");
}

static int parse_u32(const char *text, unsigned long maximum,
                     unsigned *value)
{
    char *end;
    unsigned long parsed;

    if (!text || !value)
        return -1;
    parsed = strtoul(text, &end, 10);
    if (end == text || *end != '\0' || parsed == 0u || parsed > maximum)
        return -1;
    *value = (unsigned)parsed;
    return 0;
}

static int ping_once(int fd, const char *interface, const char *address,
                     unsigned sequence, unsigned timeout_ms)
{
    char command[128];
    char response[PING_RESPONSE_SIZE];
    ssize_t count;
    size_t length = 0u;

    if (interface) {
        snprintf(command, sizeof(command), "ping %s %s %u %u",
                 interface, address, sequence, timeout_ms);
    } else {
        snprintf(command, sizeof(command), "ping %s %u %u",
                 address, sequence, timeout_ms);
    }
    if (write(fd, command, strlen(command)) != (ssize_t)strlen(command)) {
        fprintf(stderr, "ping: request failed: %s\n", strerror(errno));
        return -1;
    }

    while (length + 1u < sizeof(response)) {
        count = read(fd, response + length, sizeof(response) - length - 1u);
        if (count < 0) {
            fprintf(stderr, "ping: response failed: %s\n", strerror(errno));
            return -1;
        }
        if (count == 0)
            break;
        length += (size_t)count;
    }
    response[length] = '\0';
    if (length == 0u) {
        fprintf(stderr, "ping: empty kernel response\n");
        return -1;
    }
    if (strncmp(response, "64 bytes from ", 14u) == 0) {
        fputs(response, stdout);
        return 1;
    }
    if (strncmp(response, "timeout ", 8u) == 0) {
        printf("Request timeout for icmp_seq %u\n", sequence);
        return 0;
    }
    fprintf(stderr, "ping: %s", response);
    return -1;
}

int main(int argc, char **argv)
{
    const char *interface = NULL;
    const char *address = NULL;
    unsigned count = PING_DEFAULT_COUNT;
    unsigned timeout_ms = PING_DEFAULT_TIMEOUT_MS;
    unsigned transmitted = 0u;
    unsigned received = 0u;
    unsigned index;
    int fd;

    for (index = 1u; index < (unsigned)argc; index++) {
        if (strcmp(argv[index], "-c") == 0 && index + 1u < (unsigned)argc) {
            if (parse_u32(argv[++index], PING_MAX_COUNT, &count) < 0) {
                usage();
                return 1;
            }
        } else if (strcmp(argv[index], "-W") == 0 &&
                   index + 1u < (unsigned)argc) {
            unsigned seconds;

            if (parse_u32(argv[++index], 30u, &seconds) < 0) {
                usage();
                return 1;
            }
            timeout_ms = seconds * 1000u;
        } else if (strcmp(argv[index], "-I") == 0 &&
                   index + 1u < (unsigned)argc) {
            interface = argv[++index];
        } else if (argv[index][0] == '-' || address) {
            usage();
            return 1;
        } else {
            address = argv[index];
        }
    }
    if (!address) {
        usage();
        return 1;
    }

    fd = open("/dev/netctl", O_RDWR, 0);
    if (fd < 0) {
        fprintf(stderr, "ping: cannot open /dev/netctl: %s\n",
                strerror(errno));
        return 1;
    }

    printf("PING %s: 56 data bytes\n", address);
    for (index = 1u; index <= count; index++) {
        int result;

        transmitted++;
        result = ping_once(fd, interface, address, index, timeout_ms);
        if (result > 0)
            received++;
        else if (result < 0) {
            close(fd);
            return 1;
        }
        if (index != count)
            sleep(1u);
    }
    close(fd);

    printf("\n--- %s ping statistics ---\n", address);
    printf("%u packets transmitted, %u packets received, %u%% packet loss\n",
           transmitted, received,
           transmitted == 0u ? 0u :
           ((transmitted - received) * 100u) / transmitted);
    return received == 0u ? 1 : 0;
}
