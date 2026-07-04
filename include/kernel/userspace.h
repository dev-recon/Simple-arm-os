/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/userspace.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

#ifndef _KERNEL_USERSPACE_H_
#define _KERNEL_USERSPACE_H_

#include <kernel/types.h>
#include <kernel/memory.h>



bool is_valid_user_range(const void* ptr, size_t size);

int copy_to_user(void* to, const void* from, size_t n);

int copy_from_user(void* to, const void* from, size_t n);

/* === FONCTIONS COMPAGNONS UTILES === */

/* Version pour strings avec limite */
int strncpy_from_user(char* to, const char* from, size_t max_len);

/* Version pour copier vers user avec limite */
int copy_to_user_safe(void* to, const void* from, size_t n, size_t max_size);
/* === MACROS UTILITAIRES === */

/* Macros pour simplifier l'utilisation */
#define put_user(value, ptr) ({ \
    int __ret = -1; \
    if (is_valid_user_ptr(ptr)) { \
        *(ptr) = (value); \
        __ret = 0; \
    } \
    __ret; \
})

#define get_user(value, ptr) ({ \
    int __ret = -1; \
    if (is_valid_user_ptr(ptr)) { \
        (value) = *(ptr); \
        __ret = 0; \
    } \
    __ret; \
})

bool is_valid_user_ptr(const void* ptr);

char* copy_string_from_user(const char* user_str);
char** copy_argv_from_user(char* const user_argv[], uint32_t argc);
void cleanup_exec_args(char* filename, char** argv, char** envp);

int strnlen_user(const char* str, int maxlen);

int count_strings(char** strings);

char** setup_stack_strings(char** strings, char** stack_ptr, int count,
                           uint32_t temp_stack, uint32_t user_stack_page);
void copy_string_array(char** src, char** dest, int count);
int unmap_user_page(uint32_t* pgdir, vaddr_t vaddr, uint32_t asid);

int setup_user_stack(vm_space_t* vm, char** argv, char** envp);

vaddr_t map_user_to_kernel(uint32_t *pgdir, vaddr_t vaddr);

#endif   //  _KERNEL_USERSPACE_H_
