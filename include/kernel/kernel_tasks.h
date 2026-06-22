/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/kernel_tasks.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

#ifndef _KERNEL_TASKS_H
#define _KERNEL_TASKS_H

#include <kernel/types.h>

/* === FONCTIONS PUBLIQUES === */

/* Boucle principale du kernel */
void kernel_main_loop(void);

/* Creation des taches systeme */
void create_system_tasks(void);

/* Arret propre du systeme de taches */
void shutdown_task_system(void);

/* === TaCHES SYSTeME === */

/* Tache de monitoring systeme */
void system_monitor_task(void* arg);

/* Tache de test memoire */
void memory_test_task(void* arg);

/* Shell simple pour interaction */
void simple_shell_task2(void* arg);

/* === FONCTIONS UTILITAIRES === */

/* Processeur de commandes shell */
void shell_process_command(const char* cmd);

/* Statistiques et monitoring */
void print_system_stats(void);
void print_memory_stats(void);


void test_context_switch_minimal(void);
void minimal_test_func(void* arg);
/* Version encore plus simple pour identifier le probleme exact */
void ultra_simple_test(void);
void ultra_simple_func(void* arg);
void test_robust_context_switch(void);
void main_current_task_debug(void);


#endif /* _KERNEL_TASKS_H */