/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/programs/hello64/main.c
 * Layer: Userland / ARM64 bootstrap validation
 *
 * Responsibilities:
 * - Validate the AArch64 newlib CRT and write syscall from a real ELF64 file.
 * - Return a deterministic status without requiring the persistent VFS.
 *
 * Notes:
 * - The broader hello program remains the writable-filesystem newlib test.
 */

#include <unistd.h>

int main(int argc, char **argv, char **envp)
{
    static const char message[] = "hello64: newlib ELF64 execution OK\n";
    ssize_t written;

    if (argc != 1 || !argv || !argv[0] || !envp || envp[0] != NULL)
        return 2;
    written = write(STDOUT_FILENO, message, sizeof(message) - 1);
    return written == (ssize_t)(sizeof(message) - 1) ? 0 : 3;
}
