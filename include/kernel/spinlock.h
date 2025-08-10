/* include/kernel/spinlock.h - Spinlocks pour ARM Cortex-A15 */
#ifndef _KERNEL_SPINLOCK_H
#define _KERNEL_SPINLOCK_H

#include <kernel/types.h>

/**
 * Structure spinlock pour ARM32
 * Utilise les instructions atomiques ARM pour la synchronisation
 */
typedef struct spinlock {
    volatile uint32_t locked;    /* 0 = libre, 1 = verouille */
    uint32_t owner;             /* ID du proprietaire (pour debug) */
    uint32_t count;             /* Nombre de fois acquis (debug) */
    const char* name;           /* Nom du lock (debug) */
} __attribute__((aligned(4))) spinlock_t;

/**
 * Initialisation statique d'un spinlock
 * Usage: spinlock_t my_lock = SPINLOCK_INIT("my_lock");
 */
#define SPINLOCK_INIT(lock_name) { \
    .locked = 0, \
    .owner = 0, \
    .count = 0, \
    .name = lock_name \
}

/**
 * Declaration et definition d'un spinlock statique
 * Usage: DEFINE_SPINLOCK(my_lock);
 */
#define DEFINE_SPINLOCK(name) \
    spinlock_t name = SPINLOCK_INIT(#name)

/* Fonctions de base */
void init_spinlock(spinlock_t* lock);
void init_spinlock_named(spinlock_t* lock, const char* name);

void spin_lock(spinlock_t* lock);
void spin_unlock(spinlock_t* lock);
int spin_trylock(spinlock_t* lock);          /* Retourne 1 si acquis, 0 sinon */

/* Fonctions avec interruptions */
void spin_lock_irqsave(spinlock_t* lock, unsigned long* flags);
void spin_unlock_irqrestore(spinlock_t* lock, unsigned long flags);

/* Utilitaires de debug */
int spin_is_locked(spinlock_t* lock);
void spin_dump_info(spinlock_t* lock);
const char* spin_get_name(spinlock_t* lock);

/* Protection contre l'usage recursif */
#ifdef DEBUG_SPINLOCKS
#define spin_lock(lock) do { \
    spin_debug_check_recursive(lock); \
    spin_lock(lock); \
} while(0)
void spin_debug_check_recursive(spinlock_t* lock);
#endif

#endif /* _KERNEL_SPINLOCK_H */