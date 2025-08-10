/* kernel/sync/spinlock.c - Spinlocks pour ARM Cortex-A15 */
#include <kernel/spinlock.h>
#include <kernel/kprintf.h>
#include <kernel/string.h>

/**
 * Initialiser un spinlock
 */
void init_spinlock(spinlock_t* lock)
{
    if (!lock) return;
    
    lock->locked = 0;
    lock->owner = 0;
    lock->count = 0;
    lock->name = "unnamed";
}

/**
 * Initialiser un spinlock avec un nom
 */
void init_spinlock_named(spinlock_t* lock, const char* name)
{
    if (!lock) return;
    
    lock->locked = 0;
    lock->owner = 0;
    lock->count = 0;
    lock->name = name ? name : "unnamed";
}

/**
 * Acquerir un spinlock (attente active)
 * Utilise les instructions atomiques ARM
 */
void spin_lock(spinlock_t* lock)
{
    if (!lock) return;
    
    /* Boucle d'attente avec test-and-set atomique */
    while (__sync_lock_test_and_set(&lock->locked, 1)) {
        /* Attente active avec WFE (Wait For Event) pour economiser l'energie */
        __asm__ volatile("wfe" ::: "memory");
    }
    
    /* Barriere memoire pour empecher la reorganisation des acces */
    __asm__ volatile("dmb" ::: "memory");
    
    /* Mettre a jour les infos de debug */
    lock->owner = 0; /* Pour l'instant, mono-CPU */
    lock->count++;

    //spin_dump_info(lock);
}

/**
 * Liberer un spinlock
 */
void spin_unlock(spinlock_t* lock)
{
    if (!lock) return;
    
    /* Verifier qu'on detient bien le lock */
    if (!lock->locked) {
        KERROR("spin_unlock: Lock '%s' not held!\n", lock->name);
        return;
    }
    
    /* Nettoyer les infos de debug */
    lock->owner = 0;
    
    /* Barriere memoire avant liberation */
    __asm__ volatile("dmb" ::: "memory");
    
    /* Liberation atomique */
    __sync_lock_release(&lock->locked);
    
    /* Reveiller les autres CPU en attente */
    __asm__ volatile("sev" ::: "memory");
}

/**
 * Essayer d'acquerir un spinlock sans attendre
 * Retourne 1 si acquis, 0 sinon
 */
int spin_trylock(spinlock_t* lock)
{
    if (!lock) return 0;
    
    /* Tentative d'acquisition atomique */
    if (__sync_lock_test_and_set(&lock->locked, 1) == 0) {
        /* Lock acquis avec succes */
        __asm__ volatile("dmb" ::: "memory");
        lock->owner = 0;
        lock->count++;
        return 1;
    }
    
    /* Lock deja pris */
    return 0;
}

/**
 * Acquerir un spinlock en sauvegardant les interruptions
 */
void spin_lock_irqsave(spinlock_t* lock, unsigned long* flags)
{
    if (!lock || !flags) return;
    
    /* Sauvegarder l'etat des interruptions et les desactiver */
    __asm__ volatile(
        "mrs %0, cpsr\n\t"          /* Lire CPSR */
        "cpsid i"                   /* Desactiver IRQ */
        : "=r" (*flags)
        :
        : "memory"
    );
    
    /* Acquerir le lock */
    spin_lock(lock);
}

/**
 * Liberer un spinlock en restaurant les interruptions
 */
void spin_unlock_irqrestore(spinlock_t* lock, unsigned long flags)
{
    if (!lock) return;
    
    /* Liberer le lock */
    spin_unlock(lock);
    
    /* Restaurer l'etat des interruptions */
    __asm__ volatile(
        "msr cpsr_c, %0"
        :
        : "r" (flags)
        : "memory"
    );
}

/**
 * Verifier si un spinlock est acquis
 */
int spin_is_locked(spinlock_t* lock)
{
    if (!lock) return 0;
    
    return lock->locked != 0;
}

/**
 * Afficher les informations d'un spinlock (debug)
 */
void spin_dump_info(spinlock_t* lock)
{
    if (!lock) {
        KINFO("spin_dump_info: NULL lock\n");
        return;
    }
    
    KINFO("=== Spinlock Info ===\n");
    KINFO("  Name:     %s\n", lock->name);
    KINFO("  Locked:   %s\n", lock->locked ? "YES" : "NO");
    KINFO("  Owner:    %u\n", lock->owner);
    KINFO("  Count:    %u\n", lock->count);
    KINFO("  Address:  %p\n", lock);
    KINFO("====================\n");
}

/**
 * Obtenir le nom d'un spinlock
 */
const char* spin_get_name(spinlock_t* lock)
{
    return lock ? lock->name : "NULL";
}

#ifdef DEBUG_SPINLOCKS
/**
 * Verifier l'usage recursif d'un spinlock (debug uniquement)
 */
void spin_debug_check_recursive(spinlock_t* lock)
{
    if (!lock) return;
    
    if (lock->locked && lock->owner == 0) { /* Mono-CPU pour l'instant */
        KERROR("DEADLOCK: Recursive lock attempt on '%s'!\n", lock->name);
        
        /* Afficher les informations du lock */
        spin_dump_info(lock);
        
        /* Arreter le systeme en cas de deadlock */
        while (1) __asm__ volatile("wfe");
    }
}
#endif

/**
 * Test des spinlocks
 */
void test_spinlocks(void)
{
    DEFINE_SPINLOCK(test_lock);
    unsigned long flags;
    
    KINFO("=== Test des Spinlocks ===\n");
    
    /* Test basic */
    KINFO("Test 1: Acquisition/liberation basique\n");
    spin_dump_info(&test_lock);
    
    spin_lock(&test_lock);
    KINFO("Lock acquis\n");
    spin_dump_info(&test_lock);
    
    spin_unlock(&test_lock);
    KINFO("Lock libere\n");
    spin_dump_info(&test_lock);
    
    /* Test trylock */
    KINFO("Test 2: Try lock\n");
    if (spin_trylock(&test_lock)) {
        KINFO("Trylock reussi\n");
        spin_unlock(&test_lock);
    } else {
        KINFO("Trylock echoue\n");
    }
    
    /* Test avec interruptions */
    KINFO("Test 3: Lock avec interruptions\n");
    spin_lock_irqsave(&test_lock, &flags);
    KINFO("Lock avec IRQ save acquis\n");
    spin_unlock_irqrestore(&test_lock, flags);
    KINFO("Lock avec IRQ restore libere\n");
    
    KINFO("=== Tests termines ===\n");
}