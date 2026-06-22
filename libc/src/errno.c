/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: libc/src/errno.c
 * Layer: Userland / legacy libc
 * Description: Legacy freestanding C runtime support kept for compatibility.
 */

#include <../include/errno.h>

/* Définition de la variable globale errno */
int errno = 0;