/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/fs/io_model.c
 * Layer: Kernel / generic I/O model
 *
 * Responsibilities:
 * - Resolve immutable files in a bounded bootstrap VFS namespace.
 * - Allocate process descriptors backed by shared open-file descriptions.
 * - Implement byte-stream pipes and architecture-neutral TTY forwarding.
 *
 * Notes:
 * - Operations are serialized by the bootstrap runtime. The full SMP VFS
 *   supplies its own locking once ARM64 mounts persistent filesystems.
 */

#include <kernel/io_model.h>

static void clear_bytes(void *object, size_t size)
{
    uint8_t *bytes = object;
    size_t index;

    for (index = 0; index < size; index++)
        bytes[index] = 0;
}

static int strings_equal(const char *left, const char *right)
{
    if (!left || !right)
        return 0;
    while (*left && *right) {
        if (*left++ != *right++)
            return 0;
    }
    return *left == *right;
}

static io_model_file_t *allocate_file(io_model_context_t *context)
{
    unsigned int index;

    for (index = 0; index < IO_MODEL_MAX_FILES; index++) {
        if (context->files[index].kind == IO_MODEL_FILE_FREE) {
            clear_bytes(&context->files[index], sizeof(context->files[index]));
            context->files[index].kind = IO_MODEL_FILE_RESERVED;
            context->files[index].references = 1;
            return &context->files[index];
        }
    }
    return NULL;
}

static int allocate_fd(io_model_context_t *context, unsigned int first)
{
    unsigned int index;

    for (index = first; index < IO_MODEL_MAX_FDS; index++) {
        if (!context->fds[index])
            return (int)index;
    }
    return -1;
}

static void release_file(io_model_file_t *file)
{
    io_model_pipe_t *pipe;

    if (!file || file->references == 0)
        return;
    file->references--;
    if (file->references != 0)
        return;
    pipe = file->pipe;
    if (file->kind == IO_MODEL_FILE_PIPE_READ && pipe && pipe->readers)
        pipe->readers--;
    if (file->kind == IO_MODEL_FILE_PIPE_WRITE && pipe && pipe->writers)
        pipe->writers--;
    clear_bytes(file, sizeof(*file));
    if (pipe && pipe->readers == 0 && pipe->writers == 0)
        clear_bytes(pipe, sizeof(*pipe));
}

void io_model_vfs_init(io_model_vfs_t *vfs)
{
    if (vfs)
        clear_bytes(vfs, sizeof(*vfs));
}

int io_model_vfs_add_readonly(io_model_vfs_t *vfs, const char *path,
                              const void *data, size_t size)
{
    io_model_node_t *node;
    unsigned int index;

    if (!vfs || !path || path[0] != '/' || (!data && size != 0) ||
        vfs->node_count >= IO_MODEL_MAX_NODES)
        return -EINVAL;
    for (index = 0; index < vfs->node_count; index++) {
        if (strings_equal(vfs->nodes[index].path, path))
            return -EEXIST;
    }
    node = &vfs->nodes[vfs->node_count++];
    node->path = path;
    node->data = data;
    node->size = size;
    return 0;
}

int io_model_context_init(io_model_context_t *context, io_model_vfs_t *vfs,
                          io_model_tty_read_t tty_read,
                          io_model_tty_write_t tty_write, void *tty_owner)
{
    unsigned int fd;

    if (!context || !vfs || !tty_write)
        return -EINVAL;
    clear_bytes(context, sizeof(*context));
    context->vfs = vfs;
    context->tty_read = tty_read;
    context->tty_write = tty_write;
    context->tty_owner = tty_owner;
    for (fd = 0; fd < 3; fd++) {
        io_model_file_t *file = allocate_file(context);

        if (!file)
            return -ENFILE;
        file->kind = IO_MODEL_FILE_TTY;
        file->flags = fd == 0 ? IO_MODEL_O_RDONLY : IO_MODEL_O_WRONLY;
        context->fds[fd] = file;
    }
    return 0;
}

int io_model_open(io_model_context_t *context, const char *path,
                  unsigned int flags)
{
    const io_model_node_t *node = NULL;
    io_model_file_t *file;
    int fd;
    unsigned int index;

    if (!context || !path)
        return -EINVAL;
    if (flags != IO_MODEL_O_RDONLY)
        return -EROFS;
    for (index = 0; index < context->vfs->node_count; index++) {
        if (strings_equal(context->vfs->nodes[index].path, path)) {
            node = &context->vfs->nodes[index];
            break;
        }
    }
    if (!node)
        return -ENOENT;
    fd = allocate_fd(context, 3);
    if (fd < 0)
        return -EMFILE;
    file = allocate_file(context);
    if (!file)
        return -ENFILE;
    file->kind = IO_MODEL_FILE_REGULAR;
    file->flags = flags;
    file->node = node;
    context->fds[fd] = file;
    return fd;
}

int io_model_close(io_model_context_t *context, int fd)
{
    io_model_file_t *file;

    if (!context || fd < 0 || fd >= (int)IO_MODEL_MAX_FDS ||
        !context->fds[fd])
        return -EBADF;
    file = context->fds[fd];
    context->fds[fd] = NULL;
    release_file(file);
    return 0;
}

ssize_t io_model_read(io_model_context_t *context, int fd, void *buffer,
                      size_t length)
{
    io_model_file_t *file;
    uint8_t *output = buffer;
    size_t count;
    size_t index;

    if (!context || fd < 0 || fd >= (int)IO_MODEL_MAX_FDS ||
        !(file = context->fds[fd]))
        return -EBADF;
    if (!buffer && length != 0)
        return -EFAULT;
    if (file->kind == IO_MODEL_FILE_TTY)
        return context->tty_read ?
            context->tty_read(context->tty_owner, buffer, length) : -EAGAIN;
    if (file->kind == IO_MODEL_FILE_REGULAR) {
        if (file->offset >= file->node->size)
            return 0;
        count = file->node->size - file->offset;
        if (count > length)
            count = length;
        for (index = 0; index < count; index++)
            output[index] = file->node->data[file->offset + index];
        file->offset += count;
        return (ssize_t)count;
    }
    if (file->kind != IO_MODEL_FILE_PIPE_READ)
        return -EBADF;
    count = file->pipe->count;
    if (count > length)
        count = length;
    for (index = 0; index < count; index++) {
        output[index] = file->pipe->data[file->pipe->read_index];
        file->pipe->read_index =
            (file->pipe->read_index + 1) % IO_MODEL_PIPE_CAPACITY;
    }
    file->pipe->count -= count;
    if (count == 0 && file->pipe->writers != 0)
        return -EAGAIN;
    return (ssize_t)count;
}

ssize_t io_model_write(io_model_context_t *context, int fd,
                       const void *buffer, size_t length)
{
    io_model_file_t *file;
    const uint8_t *input = buffer;
    size_t available;
    size_t count;
    size_t index;

    if (!context || fd < 0 || fd >= (int)IO_MODEL_MAX_FDS ||
        !(file = context->fds[fd]))
        return -EBADF;
    if (!buffer && length != 0)
        return -EFAULT;
    if (file->kind == IO_MODEL_FILE_TTY)
        return context->tty_write(context->tty_owner, buffer, length);
    if (file->kind != IO_MODEL_FILE_PIPE_WRITE)
        return -EBADF;
    if (file->pipe->readers == 0)
        return -EPIPE;
    available = IO_MODEL_PIPE_CAPACITY - file->pipe->count;
    count = length < available ? length : available;
    for (index = 0; index < count; index++) {
        file->pipe->data[file->pipe->write_index] = input[index];
        file->pipe->write_index =
            (file->pipe->write_index + 1) % IO_MODEL_PIPE_CAPACITY;
    }
    file->pipe->count += count;
    return count != 0 || length == 0 ? (ssize_t)count : -EAGAIN;
}

int io_model_pipe(io_model_context_t *context, int descriptors[2])
{
    io_model_pipe_t *pipe = NULL;
    io_model_file_t *reader;
    io_model_file_t *writer;
    int read_fd;
    int write_fd;
    unsigned int index;

    if (!context || !descriptors)
        return -EFAULT;
    for (index = 0; index < IO_MODEL_MAX_PIPES; index++) {
        if (!context->pipes[index].allocated) {
            pipe = &context->pipes[index];
            break;
        }
    }
    if (!pipe)
        return -ENFILE;
    read_fd = -1;
    write_fd = -1;
    for (index = 3; index < IO_MODEL_MAX_FDS; index++) {
        if (context->fds[index])
            continue;
        if (read_fd < 0)
            read_fd = (int)index;
        else {
            write_fd = (int)index;
            break;
        }
    }
    if (write_fd < 0)
        return -EMFILE;
    reader = allocate_file(context);
    writer = allocate_file(context);
    if (!reader || !writer) {
        release_file(reader);
        release_file(writer);
        return -ENFILE;
    }
    clear_bytes(pipe, sizeof(*pipe));
    pipe->allocated = 1;
    pipe->readers = 1;
    pipe->writers = 1;
    reader->kind = IO_MODEL_FILE_PIPE_READ;
    reader->flags = IO_MODEL_O_RDONLY;
    reader->pipe = pipe;
    writer->kind = IO_MODEL_FILE_PIPE_WRITE;
    writer->flags = IO_MODEL_O_WRONLY;
    writer->pipe = pipe;
    context->fds[read_fd] = reader;
    context->fds[write_fd] = writer;
    descriptors[0] = read_fd;
    descriptors[1] = write_fd;
    return 0;
}

int io_model_dup2(io_model_context_t *context, int old_fd, int new_fd)
{
    io_model_file_t *file;

    if (!context || old_fd < 0 || old_fd >= (int)IO_MODEL_MAX_FDS ||
        new_fd < 0 || new_fd >= (int)IO_MODEL_MAX_FDS ||
        !(file = context->fds[old_fd]))
        return -EBADF;
    if (old_fd == new_fd)
        return new_fd;
    if (context->fds[new_fd])
        io_model_close(context, new_fd);
    file->references++;
    context->fds[new_fd] = file;
    return new_fd;
}
