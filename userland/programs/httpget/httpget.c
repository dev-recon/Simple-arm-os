/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/programs/httpget/httpget.c
 * Layer: Userland / network tests
 *
 * Responsibilities:
 * - Validate DNS, TCP connect and socket read/write with an HTTP/1.1 client.
 * - Fetch plain HTTP resources through either VirtIO-net or Raspberry Pi Wi-Fi.
 *
 * Notes:
 * - HTTPS is intentionally out of scope until ArmOS gains a TLS library.
 * - Both fixed-length and chunked HTTP/1.1 response bodies are supported.
 */

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define HTTP_BUFFER_SIZE 4096u
#define HTTP_HEADER_MAX  16384u

typedef struct http_url {
    char host[256];
    char path[1024];
    char service[6];
    unsigned int port;
} http_url_t;

typedef struct http_reader {
    int socket;
    unsigned char buffer[HTTP_BUFFER_SIZE];
    size_t offset;
    size_t length;
} http_reader_t;

static void usage(void)
{
    fprintf(stderr, "usage: httpget [-o file] http://host[:port]/path\n");
}

static int parse_url(const char *text, http_url_t *url)
{
    const char *authority;
    const char *path;
    const char *colon;
    size_t host_length;
    unsigned long port = 80u;

    if (!text || !url || strncmp(text, "http://", 7u) != 0)
        return -1;
    authority = text + 7;
    path = strchr(authority, '/');
    if (!path)
        path = authority + strlen(authority);
    colon = NULL;
    {
        const char *cursor;

        for (cursor = authority; cursor < path; cursor++) {
            if (*cursor == ':')
                colon = cursor;
        }
    }
    host_length = (size_t)((colon ? colon : path) - authority);
    if (host_length == 0u || host_length >= sizeof(url->host))
        return -1;
    memset(url, 0, sizeof(*url));
    memcpy(url->host, authority, host_length);
    if (colon) {
        char *end;

        port = strtoul(colon + 1, &end, 10);
        if (end != path || port == 0u || port > 65535u)
            return -1;
    }
    url->port = (unsigned int)port;
    snprintf(url->service, sizeof(url->service), "%u", url->port);
    if (*path == '\0')
        strcpy(url->path, "/");
    else if (strlen(path) >= sizeof(url->path))
        return -1;
    else
        strcpy(url->path, path);
    return 0;
}

static int write_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *bytes = buffer;

    while (length != 0u) {
        ssize_t written = write(fd, bytes, length);

        if (written <= 0)
            return -1;
        bytes += written;
        length -= (size_t)written;
    }
    return 0;
}

static ssize_t reader_fill(http_reader_t *reader)
{
    ssize_t count = recv(reader->socket, reader->buffer,
                         sizeof(reader->buffer), 0);

    if (count > 0) {
        reader->offset = 0u;
        reader->length = (size_t)count;
    }
    return count;
}

static int reader_byte(http_reader_t *reader, unsigned char *value)
{
    if (reader->offset == reader->length && reader_fill(reader) <= 0)
        return -1;
    *value = reader->buffer[reader->offset++];
    return 0;
}

static int reader_line(http_reader_t *reader, char *line, size_t capacity)
{
    size_t length = 0u;
    unsigned char byte;

    while (length + 1u < capacity) {
        if (reader_byte(reader, &byte) < 0)
            return -1;
        if (byte == '\n') {
            if (length != 0u && line[length - 1u] == '\r')
                length--;
            line[length] = '\0';
            return 0;
        }
        line[length++] = (char)byte;
    }
    return -1;
}

static int copy_fixed(http_reader_t *reader, int output,
                      unsigned long length)
{
    while (length != 0u) {
        size_t available;
        size_t chunk;

        if (reader->offset == reader->length && reader_fill(reader) <= 0)
            return -1;
        available = reader->length - reader->offset;
        chunk = available;
        if (chunk > length)
            chunk = (size_t)length;
        if (write_all(output, reader->buffer + reader->offset, chunk) < 0)
            return -1;
        reader->offset += chunk;
        length -= chunk;
    }
    return 0;
}

static int copy_until_close(http_reader_t *reader, int output)
{
    for (;;) {
        size_t available = reader->length - reader->offset;
        ssize_t received;

        if (available != 0u) {
            if (write_all(output, reader->buffer + reader->offset,
                          available) < 0)
                return -1;
            reader->offset = reader->length;
        }
        received = reader_fill(reader);
        if (received == 0)
            return 0;
        if (received < 0)
            return -1;
    }
}

static int copy_chunked(http_reader_t *reader, int output)
{
    char line[128];

    for (;;) {
        char *end;
        unsigned long chunk;
        unsigned char byte;

        if (reader_line(reader, line, sizeof(line)) < 0)
            return -1;
        chunk = strtoul(line, &end, 16);
        if (end == line)
            return -1;
        if (chunk == 0u) {
            do {
                if (reader_line(reader, line, sizeof(line)) < 0)
                    return -1;
            } while (line[0] != '\0');
            return 0;
        }
        if (copy_fixed(reader, output, chunk) < 0)
            return -1;
        if (reader_byte(reader, &byte) < 0 || byte != '\r' ||
            reader_byte(reader, &byte) < 0 || byte != '\n')
            return -1;
    }
}

static int contains_token(const char *text, const char *token)
{
    size_t token_length = strlen(token);

    while (*text != '\0') {
        size_t index;

        for (index = 0u; index < token_length; index++) {
            char left = text[index];
            char right = token[index];

            if (left == '\0')
                break;
            if (left >= 'A' && left <= 'Z')
                left = (char)(left - 'A' + 'a');
            if (right >= 'A' && right <= 'Z')
                right = (char)(right - 'A' + 'a');
            if (left != right)
                break;
        }
        if (index == token_length)
            return 1;
        text++;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *output_path = NULL;
    const char *url_text;
    http_url_t url;
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    http_reader_t reader;
    char request[1536];
    char line[1024];
    unsigned long content_length = 0u;
    int have_content_length = 0;
    int chunked = 0;
    int output = STDOUT_FILENO;
    int socket_fd;
    int gai_result;
    int status = 1;

    if (argc == 4 && strcmp(argv[1], "-o") == 0) {
        output_path = argv[2];
        url_text = argv[3];
    } else if (argc == 2) {
        url_text = argv[1];
    } else {
        usage();
        return 2;
    }
    if (parse_url(url_text, &url) < 0) {
        fprintf(stderr, "httpget: invalid or unsupported URL\n");
        return 2;
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    gai_result = getaddrinfo(url.host, url.service, &hints, &addresses);
    if (gai_result != 0) {
        fprintf(stderr, "httpget: %s: %s\n", url.host,
                gai_strerror(gai_result));
        return 1;
    }
    socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd < 0) {
        fprintf(stderr, "httpget: socket: %s\n", strerror(errno));
        goto out_addresses;
    }
    if (connect(socket_fd, addresses->ai_addr, addresses->ai_addrlen) < 0) {
        fprintf(stderr, "httpget: connect: %s\n", strerror(errno));
        goto out_socket;
    }
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\nHost: %s%s%u\r\n"
             "User-Agent: ArmOS-httpget/0.1\r\n"
             "Accept: */*\r\nConnection: close\r\n\r\n",
             url.path, url.host, url.port == 80u ? "" : ":",
             url.port == 80u ? 0u : url.port);
    if (url.port == 80u) {
        snprintf(request, sizeof(request),
                 "GET %s HTTP/1.1\r\nHost: %s\r\n"
                 "User-Agent: ArmOS-httpget/0.1\r\n"
                 "Accept: */*\r\nConnection: close\r\n\r\n",
                 url.path, url.host);
    }
    if (send(socket_fd, request, strlen(request), 0) < 0) {
        fprintf(stderr, "httpget: send: %s\n", strerror(errno));
        goto out_socket;
    }
    memset(&reader, 0, sizeof(reader));
    reader.socket = socket_fd;
    if (reader_line(&reader, line, sizeof(line)) < 0 ||
        strncmp(line, "HTTP/1.", 7u) != 0) {
        fprintf(stderr, "httpget: invalid HTTP response\n");
        goto out_socket;
    }
    fprintf(stderr, "httpget: %s\n", line);
    for (;;) {
        if (reader_line(&reader, line, sizeof(line)) < 0) {
            fprintf(stderr, "httpget: truncated response headers\n");
            goto out_socket;
        }
        if (line[0] == '\0')
            break;
        if (contains_token(line, "content-length:")) {
            const char *value = strchr(line, ':');

            if (value) {
                content_length = strtoul(value + 1, NULL, 10);
                have_content_length = 1;
            }
        }
        if (contains_token(line, "transfer-encoding:") &&
            contains_token(line, "chunked"))
            chunked = 1;
    }
    if (output_path) {
        output = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (output < 0) {
            fprintf(stderr, "httpget: %s: %s\n", output_path,
                    strerror(errno));
            goto out_socket;
        }
    }
    if (chunked)
        status = copy_chunked(&reader, output);
    else if (have_content_length)
        status = copy_fixed(&reader, output, content_length);
    else
        status = copy_until_close(&reader, output);
    if (status < 0)
        fprintf(stderr, "httpget: response body failed: %s\n",
                strerror(errno));
    else
        status = 0;
    if (output_path)
        close(output);
out_socket:
    close(socket_fd);
out_addresses:
    freeaddrinfo(addresses);
    return status;
}
