/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/io_model.h
 * Layer: Kernel / generic I/O model
 *
 * Responsibilities:
 * - Define a bounded VFS namespace suitable for early userspace bring-up.
 * - Own process file descriptors and shared open-file descriptions.
 * - Provide regular-file, pipe and TTY operations without architecture types.
 *
 * Notes:
 * - The bootstrap namespace is read-only; writable files remain owned by the
 *   full mounted VFS.
 * - Storage is embedded so this layer can run before kmalloc is available.
 */

#ifndef _KERNEL_IO_MODEL_H
#define _KERNEL_IO_MODEL_H

#include <kernel/types.h>

#define IO_MODEL_MAX_NODES 8u
#define IO_MODEL_MAX_FILES 16u
#define IO_MODEL_MAX_FDS 16u
#define IO_MODEL_MAX_PIPES 4u
#define IO_MODEL_PIPE_CAPACITY 128u

#define IO_MODEL_O_RDONLY 0u
#define IO_MODEL_O_WRONLY 1u
#define IO_MODEL_O_RDWR   2u

typedef ssize_t (*io_model_tty_read_t)(void *owner, void *buffer,
                                       size_t length);
typedef ssize_t (*io_model_tty_write_t)(void *owner, const void *buffer,
                                        size_t length);

typedef struct io_model_node {
    const char *path;
    const uint8_t *data;
    size_t size;
} io_model_node_t;

typedef struct io_model_vfs {
    io_model_node_t nodes[IO_MODEL_MAX_NODES];
    unsigned int node_count;
} io_model_vfs_t;

typedef struct io_model_pipe {
    uint8_t data[IO_MODEL_PIPE_CAPACITY];
    size_t read_index;
    size_t write_index;
    size_t count;
    unsigned int readers;
    unsigned int writers;
    int allocated;
} io_model_pipe_t;

typedef enum io_model_file_kind {
    IO_MODEL_FILE_FREE = 0,
    IO_MODEL_FILE_RESERVED,
    IO_MODEL_FILE_REGULAR,
    IO_MODEL_FILE_TTY,
    IO_MODEL_FILE_PIPE_READ,
    IO_MODEL_FILE_PIPE_WRITE
} io_model_file_kind_t;

typedef struct io_model_file {
    io_model_file_kind_t kind;
    unsigned int references;
    unsigned int flags;
    size_t offset;
    const io_model_node_t *node;
    io_model_pipe_t *pipe;
} io_model_file_t;

typedef struct io_model_context {
    io_model_vfs_t *vfs;
    io_model_file_t files[IO_MODEL_MAX_FILES];
    io_model_file_t *fds[IO_MODEL_MAX_FDS];
    io_model_pipe_t pipes[IO_MODEL_MAX_PIPES];
    io_model_tty_read_t tty_read;
    io_model_tty_write_t tty_write;
    void *tty_owner;
} io_model_context_t;

void io_model_vfs_init(io_model_vfs_t *vfs);
int io_model_vfs_add_readonly(io_model_vfs_t *vfs, const char *path,
                              const void *data, size_t size);
int io_model_context_init(io_model_context_t *context, io_model_vfs_t *vfs,
                          io_model_tty_read_t tty_read,
                          io_model_tty_write_t tty_write, void *tty_owner);
int io_model_open(io_model_context_t *context, const char *path,
                  unsigned int flags);
int io_model_close(io_model_context_t *context, int fd);
ssize_t io_model_read(io_model_context_t *context, int fd, void *buffer,
                      size_t length);
ssize_t io_model_write(io_model_context_t *context, int fd,
                       const void *buffer, size_t length);
int io_model_pipe(io_model_context_t *context, int descriptors[2]);
int io_model_dup2(io_model_context_t *context, int old_fd, int new_fd);

#endif /* _KERNEL_IO_MODEL_H */
