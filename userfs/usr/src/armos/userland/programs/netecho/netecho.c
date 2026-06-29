/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/programs/netecho/netecho.c
 * Layer: Userland / network tests
 *
 * Responsibilities:
 * - Exercise the early ArmOS socket API with a tiny TCP echo server.
 * - Provide a nc-friendly validation target for VirtIO-net and TCP bring-up.
 */

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        printf("netecho: socket failed: %s\n", strerror(errno));
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(2323);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("netecho: bind failed: %s\n", strerror(errno));
        close(server);
        return 1;
    }

    if (listen(server, 1) < 0) {
        printf("netecho: listen failed: %s\n", strerror(errno));
        close(server);
        return 1;
    }

    printf("netecho: listening on 10.0.2.15:2323\n");
    printf("netecho: from host, run: nc 127.0.0.1 2323\n");
    printf("netecho: press Ctrl-C to stop\n");

    while (1) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int client = accept(server, (struct sockaddr *)&peer, &peer_len);
        if (client < 0) {
            printf("netecho: accept failed: %s\n", strerror(errno));
            continue;
        }

        printf("netecho: client connected\n");
        while (1) {
            char buf[256];
            int n = read(client, buf, sizeof(buf));
            if (n < 0) {
                printf("netecho: read failed: %s\n", strerror(errno));
                break;
            }
            if (n == 0) {
                printf("netecho: client closed\n");
                break;
            }

            printf("netecho: %.*s", n, buf);
            if (write(client, buf, (size_t)n) != n) {
                printf("netecho: write failed: %s\n", strerror(errno));
                break;
            }
        }
        close(client);
    }

    close(server);
    return 0;
}
