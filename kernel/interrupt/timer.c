/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/interrupt/timer.c
 * Layer: Kernel / interrupts and exceptions
 *
 * Responsibilities:
 * - Handle IRQs, timer ticks, aborts, and crash diagnostics.
 * - Keep exception reports actionable during early kernel debugging.
 *
 * Notes:
 * - Handlers run in privileged exception modes with banked registers.
 */

#include <kernel/timer.h>
#include <kernel/task.h>
#include <kernel/interrupt.h>
#include <kernel/process.h>
#include <kernel/kernel.h>
#include <kernel/kprintf.h>
#include <kernel/uart.h>
#include <kernel/tty.h>
#include <kernel/smp.h>


/* Flag pour savoir si le systeme de processus est pret */
static bool process_system_ready = false;
static uint32_t system_ticks = 0;
static volatile uint32_t timer_cpu_ticks[ARMOS_MAX_CPUS];

static uint64_t last_timer_count = 0;
static uint32_t software_system_ticks = 0;
static bool timer_software_initialized = false;

static volatile bool in_critical_section_cpu[ARMOS_MAX_CPUS];

static uint32_t timer_interval_from_frequency(uint32_t timer_freq)
{
    return timer_freq / TIMER_FREQ;
}

static void timer_program_next_tick(uint32_t timer_freq)
{
    uint32_t next_interval = timer_interval_from_frequency(timer_freq);

    __asm__ volatile("mcr p15, 0, %0, c14, c2, 0" :: "r"(next_interval));
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 1" :: "r"(1u));
}


void set_critical_section(void){
    uint32_t cpu = smp_processor_id();
    if (cpu < ARMOS_MAX_CPUS)
        in_critical_section_cpu[cpu] = true;
}

void unset_critical_section(void){
    uint32_t cpu = smp_processor_id();
    if (cpu < ARMOS_MAX_CPUS)
        in_critical_section_cpu[cpu] = false;
}

bool get_critical_section(void)
{
    uint32_t cpu = smp_processor_id();
    return cpu < ARMOS_MAX_CPUS ? in_critical_section_cpu[cpu] : false;
}

void init_timer_software(void)
{
    extern int kprintf(const char *format, ...);
    KINFO("[TIMER] Initializing SOFTWARE timer (no IRQ)...\n");
    
    /* Lire la fréquence du timer ARM Generic Timer */
    uint32_t timer_freq;
    __asm__ volatile("mrc p15, 0, %0, c14, c0, 0" : "=r"(timer_freq));
    
    if (timer_freq == 0) {
        timer_freq = 62500000;  /* 62.5MHz par défaut QEMU */
    }
    
    KINFO("[TIMER] Timer frequency: %u Hz\n", timer_freq);
    
    /* PAS d'activation du timer hardware */
    /* PAS d'activation IRQ 30 */
    /* PAS de programmation d'interruptions */
    
    /* Juste lire le compteur de base */
    last_timer_count = get_timer_count();
    software_system_ticks = 0;
    timer_software_initialized = true;
    
    KINFO("[TIMER] Software timer initialized (polling mode)\n");
    KINFO("[TIMER] Base count: %u%u\n", 
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
        if (process_system_ready && ticks_elapsed > 0 && !get_critical_section()) {
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
    
    KINFO("[TIMER] Forcing timer interrupt...\n");
    
    /* Programmer une interruption dans 200 ticks */
    uint64_t current = get_timer_count();
    uint32_t target = (uint32_t)current + 200;
    
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 1" :: "r"(0));  /* Disable */
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 0" :: "r"(target));  /* Set */
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 1" :: "r"(1));  /* Enable */
    
    KINFO("[TIMER] Timer interrupt scheduled in 200 ticks\n");
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

void timer_init_local_cpu(void)
{
    uint32_t timer_ctrl = 0;
    uint32_t timer_freq = get_timer_frequency();

    /*
     * The ARM generic timer is per-CPU. This helper only programs the local
     * CP15 timer registers; the caller must enable the matching GIC PPI for
     * that CPU before expecting IRQ delivery.
     */
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 1" :: "r"(timer_ctrl));
    timer_program_next_tick(timer_freq);
}

/* ARM Generic Timer - utilise par machine virt */
void init_timer(void)
{
    extern int kprintf(const char *format, ...);
    KINFO("[TIMER] Starting ARM Generic Timer initialization...\n");
    
    /* 1. Lire la frequence du timer */
    uint32_t timer_freq;
    __asm__ volatile("mrc p15, 0, %0, c14, c0, 0" : "=r"(timer_freq));
    
    if (timer_freq == 0) {
        KWARN("[TIMER] Timer frequency is 0, using default 62.5MHz\n");
        timer_freq = 62500000;  // Frequence par defaut QEMU
    }
    
    KINFO("[TIMER] Timer frequency: %u Hz\n", timer_freq);
    
    /* 2. Calculer l'interval pour TIMER_FREQ Hz */
    uint32_t interval = timer_interval_from_frequency(timer_freq);
    KINFO("[TIMER] Timer interval: %u counter ticks (%u us)\n",
            interval, 1000000 / TIMER_FREQ);
    
    /* 3. Configurer le timer EL1 (non-secure) du CPU courant. */
    timer_init_local_cpu();
    
    KINFO("[TIMER] ARM Generic Timer configured\n");
    
    /* 4. Activer l'IRQ 30 dans le GIC */
    KINFO("[TIMER] Enabling timer IRQ (30) in GIC...\n");

    /* 3. Activer l'IRQ du timer dans le GIC */
    gic_enable_irq_kernel(VIRT_TIMER_NS_EL1_IRQ);  // IRQ 30
    
    /* Programmer une interruption periodique */
    uint32_t timeout = timer_freq / TIMER_FREQ;
    timer_set_timeout(timeout);
    
    /* 5. Activer les interruptions au niveau CPU */
    __asm__ volatile("cpsie i" ::: "memory");
    
    KINFO("[TIMER] Timer initialization complete OK\n");
}

void timer_irq_handler(void)
{
    uint32_t cpu_id = smp_processor_id();

    /* 1. Acquitter l'interruption ARM Generic Timer */
    uint32_t timer_ctrl;
    __asm__ volatile("mrc p15, 0, %0, c14, c2, 1" : "=r"(timer_ctrl));
    
    /* Clear l'interrupt status */
    timer_ctrl |= 0x4;  /* Set ISTATUS bit */
    __asm__ volatile("mcr p15, 0, %0, c14, c2, 1" :: "r"(timer_ctrl));

    gic_ack_irq_kernel(IRQ_TIMER);
    
    /* 2. CORRECTION: Programmer le PROCHAIN timer (relatif) */
    timer_program_next_tick(get_timer_frequency());
    
    /* 4. Per-CPU accounting, plus one global wall-clock on the boot CPU. */
    if (cpu_id < ARMOS_MAX_CPUS)
        timer_cpu_ticks[cpu_id]++;
    if (smp_is_boot_cpu())
        system_ticks++;

    /*
     * PL011 TX interrupts are edge/level sensitive enough to miss a wake-up in
     * QEMU under dense console bursts. Poll the TTY TX ring from the periodic
     * timer as a safety net. Keep this on the boot CPU so future local timers
     * do not make several CPUs compete for the same character backend.
     */
    if (smp_is_boot_cpu() && tty_has_pending_output())
        tty_drain_output();
    
    /* 5. RÉDUIRE drastiquement les messages */
    if (system_ticks % (TIMER_FREQ * 10) == 0) {  /* Toutes les 10 secondes seulement */
        //KINFO("[TIMER] System uptime: %u seconds -> %s\n", system_ticks / TIMER_FREQ, current_task->name);
    }
    
    /* 6. Scheduling sans messages debug */
    if (process_system_ready) {
        task_t* current = task_current_on_cpu(cpu_id);
        
        if (current && !task_is_idle_task(current) && current->state == TASK_RUNNING) {
            current->total_runtime++;
            if (current->sched_debt < 0xffffffffu)
                current->sched_debt++;
        }

        if (current && !task_is_idle_task(current) && !get_critical_section()) {
            current->quantum_left--;

            if (current->quantum_left == 0) {
                current->quantum_left = QUANTUM_TICKS;
                //current_task->state = TASK_READY;
                scheduler_request_resched_current_cpu();
                //KDEBUG("YIELDING BECAUSE OF TIMER\n");
                //yield();
            }
        }
    }
}

/* Fonction pour activer le scheduling (appelee apres init_processes) */
void timer_enable_scheduling(void)
{
    extern int kprintf(const char *format, ...);
    KINFO("[TIMER] Process scheduling enabled OK\n");
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
    //update_timer_software();
    return system_ticks;
}

uint32_t timer_cpu_tick_count(uint32_t cpu_id)
{
    if (cpu_id >= ARMOS_MAX_CPUS)
        return 0;
    return timer_cpu_ticks[cpu_id];
}

/* Fonction pour obtenir le temps en millisecondes */
uint32_t get_time_ms(void)
{
    return (get_system_ticks() * 1000) / TIMER_FREQ;
}

/* Fonction de debug pour verifier l'etat du timer */
void debug_timer_state(void)
{
    extern int kprintf(const char *format, ...);
    
    KINFO("[TIMER] === TIMER STATE DEBUG ===\n");
    
    /* Lire le registre de controle */
    uint32_t timer_ctrl;
    __asm__ volatile("mrc p15, 0, %0, c14, c2, 1" : "=r"(timer_ctrl));
    
    KINFO("[TIMER] Control register: 0x%08X\n", timer_ctrl);
    KINFO("[TIMER]   Enable: %s\n", (timer_ctrl & 0x1) ? "YES" : "NO");
    KINFO("[TIMER]   Mask: %s\n", (timer_ctrl & 0x2) ? "YES" : "NO");
    KINFO("[TIMER]   Status: %s\n", (timer_ctrl & 0x4) ? "PENDING" : "CLEAR");
    
    /* Lire la valeur de comparaison */
    uint32_t timer_value;
    __asm__ volatile("mrc p15, 0, %0, c14, c2, 0" : "=r"(timer_value));
    KINFO("[TIMER] Compare value: %u\n", timer_value);
    
    /* Lire le compteur actuel */
    uint64_t counter = get_timer_count();
    KINFO("[TIMER] Current count: %u%u\n", (uint32_t)(counter >> 32), (uint32_t)counter);
    
    KINFO("[TIMER] System ticks: %u\n", system_ticks);
    KINFO("[TIMER] Timer frequency: %u Hz\n", get_timer_frequency());
    
    KINFO("[TIMER] === END DEBUG ===\n");
}

/* Stub temporaire pour wake_up_sleeping_processes */
void wake_up_sleeping_processes(void)
{
    /* Cette fonction sera implementee dans process.c */
}



/* Nombre de jours par mois (annee non bissextile) */
static const int days_in_month[] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

bool is_leap_year(int year)
{
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

int get_days_in_month(int month, int year)
{
    if (month < 1 || month > 12)
        return 0;

    if (month == 2 && is_leap_year(year))
        return 29;

    return days_in_month[month - 1];
}

/* Convertir timestamp Unix en structure datetime */
void unix_to_datetime(uint32_t unix_time, datetime_t* dt) {
    /* Nombre de secondes par jour */
    const uint32_t SECONDS_PER_DAY = 86400;
    
    /* Epoch Unix commence le 1er janvier 1970 */
    uint32_t days_since_epoch = unix_time / SECONDS_PER_DAY;
    uint32_t seconds_today = unix_time % SECONDS_PER_DAY;
    
    /* Calculer l'heure, minute, seconde */
    dt->hour = seconds_today / 3600;
    dt->minute = (seconds_today % 3600) / 60;
    dt->second = seconds_today % 60;
    
    /* Calculer l'année */
    int year = 1970;
    uint32_t days_remaining = days_since_epoch;
    
    while (days_remaining >= (is_leap_year(year) ? 366 : 365)) {
        if (is_leap_year(year)) {
            days_remaining -= 366;
        } else {
            days_remaining -= 365;
        }
        year++;
    }
    dt->year = year;
    
    /* Calculer le mois et le jour */
    int month = 1;
    while (days_remaining >= (uint32_t)get_days_in_month(month, year)) {
        days_remaining -= get_days_in_month(month, year);
        month++;
    }
    dt->month = month;
    dt->day = days_remaining + 1;  /* +1 car les jours commencent à 1 */
}


/* Si vous avez un RTC sur votre board */
uint32_t get_current_time(void) {
    /* PL031 runtime via l'alias MMIO prive TTBR1. */
    volatile uint32_t* rtc_base = (uint32_t*)KERNEL_MMIO_RTC_BASE;
    
    /* Le PL031 donne directement un timestamp Unix */
    return rtc_base[0];  /* RTC Data Register */
}
