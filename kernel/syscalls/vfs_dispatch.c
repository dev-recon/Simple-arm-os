/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/syscalls/vfs_dispatch.c
 * Layer: Kernel / generic syscall dispatch
 *
 * Responsibilities:
 * - Bind native-width syscall requests to the common VFS syscall functions.
 * - Keep architecture exception code independent of filesystem semantics.
 * - Provide a runtime-populated handler suitable for high-alias kernels.
 *
 * Notes:
 * - The syscall implementations remain the same functions used by ARM32.
 * - Unsupported numbers return ENOSYS so another common subsystem may own
 *   them as the ARM64 process model is consolidated.
 */

#include <kernel/syscalls.h>

syscall_result_t syscall_dispatch_vfs_handler(
    void *owner, const syscall_request_t *request)
{
    (void)owner;

    if (!request)
        return -EINVAL;

    switch (request->number) {
    case ARMOS_NR_READ:
        return sys_read((int)request->arguments[0],
                        (void *)request->arguments[1],
                        (size_t)request->arguments[2]);
    case ARMOS_NR_WRITE:
        return sys_write((int)request->arguments[0],
                         (const void *)request->arguments[1],
                         (size_t)request->arguments[2]);
    case ARMOS_NR_PIPE:
        return sys_pipe((int *)request->arguments[0]);
    case ARMOS_NR_DUP2:
        return sys_dup2((int)request->arguments[0],
                        (int)request->arguments[1]);
    case ARMOS_NR_OPEN:
        return sys_open_vfs((const char *)request->arguments[0],
                            (int)request->arguments[1],
                            (mode_t)request->arguments[2]);
    case ARMOS_NR_CLOSE:
        return sys_close((int)request->arguments[0]);
    case ARMOS_NR_CHDIR:
        return sys_chdir((const char *)request->arguments[0]);
    case ARMOS_NR_GETCWD:
        return sys_getcwd((char *)request->arguments[0],
                          (size_t)request->arguments[1]);
    case __NR_lseek:
        return sys_lseek((int)request->arguments[0],
                         (off_t)request->arguments[1],
                         (int)request->arguments[2]);
    case __NR_stat:
        return sys_stat_vfs((const char *)request->arguments[0],
                            (struct stat *)request->arguments[1]);
    case __NR_lstat:
        return sys_lstat_vfs((const char *)request->arguments[0],
                             (struct stat *)request->arguments[1]);
    case __NR_fstat:
        return sys_fstat((int)request->arguments[0],
                         (struct stat *)request->arguments[1]);
    case __NR_getdents:
        return sys_getdents((unsigned int)request->arguments[0],
                            (struct linux_dirent *)request->arguments[1],
                            (unsigned int)request->arguments[2]);
    default:
        return -ENOSYS;
    }
}
