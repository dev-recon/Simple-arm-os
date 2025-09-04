/* kernel/timer/timer.c - Version corrigee pour machine virt */
#include <kernel/timer.h>
#include <kernel/task.h>
#include <kernel/interrupt.h>
#include <kernel/process.h>
#include <kernel/kernel.h>
#include <kernel/kprintf.h>
#include <kernel/uart.h>


/* Flag pour savoir si le systeme de processus est pret */
static bool process_system_ready = false;
static uint32_t system_ticks = 0;

static uint64_t last_timer_count = 0;
static uint32_t software_system_ticks = 0;
static bool timer_software_initialized = false;


void init_timer_software(void)
{
    extern int kprintf(const char *format, ...);
    kprintf("[TIMER] Initializing SOFTWARE timer (no IRQ)...\n");
    
    /* Lire la fréquence du timer ARM Generic Timer */
    uint32_t timer_freq;
    __asm__ volatile("mrc p15, 0, %0, c14, c0, 0" : "=r"(timer_freq));
    
    if (timer_freq == 0) {
        timer_freq = 62500000;  /* 62.5MHz par défaut QEMU */
    }
    
    kprintf("[TIMER] Timer frequency: %u Hz\n", timer_freq);
    
    /* PAS d'activation du timer hardware */
    /* PAS d'activation IRQ 30 */
    /* PAS de programmation d'interruptions */
    
    /* Juste lire le compteur de base */
    last_timer_count = get_timer_count();
    software_system_ticks = 0;
    timer_software_initialized = true;
    
    kprintf("[TIMER] Software timer initialized (polling mode)\n");
    kprintf("[TIMER] Base count: %u%u\n", 
            (uint32_t)(last_timer_count >> 32), 
            (uint32_t)last_timer_count);
}

/* Fonction à appeler périodiquement pour mettre à jour les ticks */
void update_timer_software(void)
{
    if (!timer_software_initialized) {
        return;
    }
    
    /* Lire le compteur actuel */
    uint64_t current_count = get_timer_count();
    uint64_t elapsed = current_count - last_timer_count;
    
    /* Calculer combien de ticks de 10ms se sont écoulés */
    uint32_t timer_freq = get_timer_frequency();
    uint32_t tick_interval = timer_freq / 100;  /* 10ms en cycles */

    /* Conversion en 32-bit pour éviter division 64-bit */
    if (elapsed > 0xFFFFFFFF) {
        /* Si elapsed trop grand, traiter par chunks */
        elapsed = 0xFFFFFFFF;
    }

    uint32_t elapsed_32 = (uint32_t)elapsed;
    
    if (elapsed_32 >= tick_interval) {
        /* Calculer le nombre de ticks écoulés */
        uint32_t ticks_elapsed = (uint32_t)(elapsed_32 / tick_interval);
        
        software_system_ticks += ticks_elapsed;
        system_ticks = software_system_ticks;
        
        /* Mettre à jour la base pour le prochain calcul */
        last_timer_count += ticks_elapsed * tick_interval;
        
        /* Scheduling si nécessaire */
        if (process_system_ready && ticks_elapsed > 0) {
            /* Faire du scheduling pour chaque tick écoulé */
            for (uint32_t i = 0; i < ticks_elapsed; i++) {
                if (software_system_ticks % 10 == 0) {  /* Tous les 100ms */
                    //schedule();
                    yield();
                }
            }
        }
    }
}


void trigger_timer_interrupt(void)
{
    extern int kprintf(const char *format, ...);
    
    kprintf("[TIMER] Forcing timer interrupt...\n");
    
    /* Programmer une interruption dans 200 ticks */
    uint64_t current = get_timer_count();
    uint32_t target = (uint32_t)current + 200;
    
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 1" :: "r"(0));  /* Disable */
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 0" :: "r"(target));  /* Set */
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 1" :: "r"(1));  /* Enable */
    
    kprintf("[TIMER] Timer interrupt scheduled in 200 ticks\n");
}

void timer_set_timeout(uint64_t timeout_ticks)
{
    /* Desactiver le timer */
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 1" :: "r"(0));
    
    /* Calculer la nouvelle valeur de comparaison */
    uint64_t current = get_timer_count();
    uint32_t compare = (uint32_t)(current + timeout_ticks);
    
    /* Programmer la nouvelle valeur */
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 0" :: "r"(compare));
    
    /* Reactiver le timer */
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 1" :: "r"(1));
}

/* ARM Generic Timer - utilise par machine virt */
void init_timer(void)
{
    extern int kprintf(const char *format, ...);
    kprintf("[TIMER] Starting ARM Generic Timer initialization...\n");
    
    /* 1. Lire la frequence du timer */
    uint32_t timer_freq;
    __asm__ volatile("mrc p15, 0, %0, c14, c0, 0" : "=r"(timer_freq));
    
    if (timer_freq == 0) {
        kprintf("[TIMER] Warning: Timer frequency is 0, using default 62.5MHz\n");
        timer_freq = 62500000;  // Frequence par defaut QEMU
    }
    
    kprintf("[TIMER] Timer frequency: %u Hz\n", timer_freq);
    
    /* 2. Calculer l'interval pour 100Hz (10ms) */
    uint32_t interval = timer_freq / TIMER_FREQ;
    kprintf("[TIMER] Timer interval: %u ticks (%u ms)\n", interval, 1000/TIMER_FREQ);
    
    /* 3. Configurer le timer EL1 (non-secure) */
    
    /* Desactiver le timer pendant la configuration */
    uint32_t timer_ctrl = 0;
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 1" :: "r"(timer_ctrl));
    
    /* Programmer la valeur de comparaison */
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 0" :: "r"(interval));
    
    /* Activer le timer : Enable=1, Interrupt=0 (non masque) */
    timer_ctrl = 0x1;  // Enable bit
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 1" :: "r"(timer_ctrl));
    
    kprintf("[TIMER] ARM Generic Timer configured\n");
    
    /* 4. Activer l'IRQ 30 dans le GIC */
    kprintf("[TIMER] Enabling timer IRQ (30) in GIC...\n");

    /* 3. Activer l'IRQ du timer dans le GIC */
    gic_enable_irq_kernel(VIRT_TIMER_NS_EL1_IRQ);  // IRQ 30
    
    /* Programmer une interruption toutes les 10ms */
    uint32_t timeout = timer_freq / 100;  // 10ms
    timer_set_timeout(timeout);
    
    /* 5. Activer les interruptions au niveau CPU */
    __asm__ volatile("cpsie i" ::: "memory");
    
    kprintf("[TIMER] Timer initialization complete OK\n");
}

void timer_irq_handler(void)
{
    /* 1. Acquitter l'interruption ARM Generic Timer */
    uint32_t timer_ctrl;
    __asm__ volatile("mrc p15, 0, %0, c14, c2, 1" : "=r"(timer_ctrl));
    
    /* Clear l'interrupt status */
    timer_ctrl |= 0x4;  /* Set ISTATUS bit */
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 1" :: "r"(timer_ctrl));

    gic_ack_irq_kernel(IRQ_TIMER);
    
    /* 2. CORRECTION: Programmer le PROCHAIN timer (relatif) */
    uint32_t timer_freq = get_timer_frequency();
    uint32_t next_interval = timer_freq / TIMER_FREQ;  /* 10ms */
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 0" :: "r"(next_interval));
    
    /* 3. Réactiver le timer */
    timer_ctrl = 0x1;  /* Enable seulement */
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 1" :: "r"(timer_ctrl));
    
    /* 4. Incrément système */
    system_ticks++;
    
    /* 5. RÉDUIRE drastiquement les messages */
    if (system_ticks % 1000 == 0) {  /* Toutes les 10 secondes seulement */
        //uart_puts("[TIMER] System uptime: ");
        //uart_put_dec(system_ticks / 100);
        //uart_puts(" seconds\n");
        //kprintf("[TIMER] System uptime: %u seconds\n", system_ticks / 100);
    }
    
    /* 6. Scheduling sans messages debug */
    if (process_system_ready) {
        extern task_t* current_task;
        extern void schedule(void);
        
        if (current_task) {
            current_task->quantum_left--;
            if (current_task->quantum_left == 0) {
                current_task->quantum_left = 8;
                current_task->state = TASK_READY;
                schedule();
            }
        }
    }
}

void timer_irq_handler2(void)
{
    extern int kprintf(const char *format, ...);
    
    /* 1. Lire le registre de controle */
    uint32_t timer_ctrl;
    __asm__ volatile("mrc p15, 0, %0, c14, c2, 1" : "=r"(timer_ctrl));
    
    /* 2. Acquitter l'interruption en mettant le bit ISTATUS */
    timer_ctrl |= 0x4;  // Set ISTATUS bit to clear interrupt
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 1" :: "r"(timer_ctrl));
    
    /* 3. Reprogrammer le timer pour la prochaine interruption */
    uint32_t timer_freq = get_timer_frequency();
    uint32_t interval = timer_freq / TIMER_FREQ;
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 0" :: "r"(interval));
    
    /* 4. Reactiver le timer */
    timer_ctrl = 0x1;  // Enable bit seulement
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 1" :: "r"(timer_ctrl));
    
    /* 5. Increment system tick counter */
    system_ticks++;
    
    /* Afficher un message toutes les 100 ticks (1 seconde) */
    if (system_ticks % 100 == 0) {
        kprintf("[TIMER] System uptime: %u seconds\n", system_ticks / 100);
    }
    
    /* 6. Scheduling seulement si le systeme de processus est pret */
    if (process_system_ready) {
        /* Declarations externes pour eviter les includes problematiques */
        extern task_t* current_task;
        extern void schedule(void);
        extern void wake_up_sleeping_processes(void);
        
        /* Decrement current process quantum */
        if (current_task) {
            current_task->quantum_left--;
            
            if (current_task->quantum_left == 0) {
                current_task->quantum_left = 8; /* QUANTUM_TICKS */
                current_task->state = TASK_READY; /* PROC_READY */
                schedule();
            }
        }
        
        /* Wake up sleeping processes */
        wake_up_sleeping_processes();
    } else {
        /* Avant que les processus soient prets, juste compter les ticks */
        if (system_ticks % 500 == 0) { /* Toutes les 5 secondes */
            kprintf("[TIMER] Waiting for process system... (tick %u)\n", system_ticks);
        }
    }
}

/* Fonction pour activer le scheduling (appelee apres init_processes) */
void timer_enable_scheduling(void)
{
    extern int kprintf(const char *format, ...);
    kprintf("[TIMER] Process scheduling enabled OK\n");
    process_system_ready = true;
}

/* Fonction pour desactiver le scheduling */
void timer_disable_scheduling(void)
{
    process_system_ready = false;
}

uint32_t get_timer_frequency(void)
{
    uint32_t freq = 0;
    
    /* Lire la frequence du timer generique ARM */
    __asm__ volatile("mrc p15, 0, %0, c14, c0, 0" : "=r"(freq));
    
    if (freq == 0) {
        /* Valeur par defaut pour QEMU machine virt */
        freq = 62500000;  // 62.5MHz
    }
    
    return freq;
}

/* Fonction pour obtenir le compte du timer */
uint64_t get_timer_count(void)
{
    uint32_t low, high;
    
    /* Lire le compteur 64-bit du timer */
    __asm__ volatile("mrrc p15, 0, %0, %1, c14" : "=r"(low), "=r"(high));
    
    return ((uint64_t)high << 32) | low;
}

/* Fonction pour obtenir le nombre de ticks systeme */
uint32_t get_system_ticks(void)
{
    /* Mettre à jour avant de retourner */
    update_timer_software();
    return system_ticks;
}

/* Fonction pour obtenir le temps en millisecondes */
uint32_t get_time_ms(void)
{
    return (system_ticks * 1000) / TIMER_FREQ;
}

/* Fonction de debug pour verifier l'etat du timer */
void debug_timer_state(void)
{
    extern int kprintf(const char *format, ...);
    
    kprintf("[TIMER] === TIMER STATE DEBUG ===\n");
    
    /* Lire le registre de controle */
    uint32_t timer_ctrl;
    __asm__ volatile("mrc p15, 0, %0, c14, c2, 1" : "=r"(timer_ctrl));
    
    kprintf("[TIMER] Control register: 0x%08X\n", timer_ctrl);
    kprintf("[TIMER]   Enable: %s\n", (timer_ctrl & 0x1) ? "YES" : "NO");
    kprintf("[TIMER]   Mask: %s\n", (timer_ctrl & 0x2) ? "YES" : "NO");
    kprintf("[TIMER]   Status: %s\n", (timer_ctrl & 0x4) ? "PENDING" : "CLEAR");
    
    /* Lire la valeur de comparaison */
    uint32_t timer_value;
    __asm__ volatile("mrc p15, 0, %0, c14, c2, 0" : "=r"(timer_value));
    kprintf("[TIMER] Compare value: %u\n", timer_value);
    
    /* Lire le compteur actuel */
    uint64_t counter = get_timer_count();
    kprintf("[TIMER] Current count: %u%u\n", (uint32_t)(counter >> 32), (uint32_t)counter);
    
    kprintf("[TIMER] System ticks: %u\n", system_ticks);
    kprintf("[TIMER] Timer frequency: %u Hz\n", get_timer_frequency());
    
    kprintf("[TIMER] === END DEBUG ===\n");
}

/* Stub temporaire pour wake_up_sleeping_processes */
void wake_up_sleeping_processes(void)
{
    /* Cette fonction sera implementee dans process.c */
}



