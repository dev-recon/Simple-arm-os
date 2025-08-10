#ifndef _KERNEL_TIMER_H
#define _KERNEL_TIMER_H

#include <kernel/types.h>

/* Timer SP804 pour machine virt (si utilise) */
#define TIMER_BASE_SP804    0x10011000

#define TIMER_FREQ 100  /* 100Hz */

/* Macros conditionnelles pour eviter les redefinitions */
#ifndef TIMER_LOAD
#define TIMER_LOAD  (*(volatile uint32_t*)(TIMER_BASE_SP804 + 0x00))
#endif

#ifndef TIMER_CTRL
#define TIMER_CTRL  (*(volatile uint32_t*)(TIMER_BASE_SP804 + 0x08))
#endif

#ifndef TIMER_INTCLR
#define TIMER_INTCLR (*(volatile uint32_t*)(TIMER_BASE_SP804 + 0x0C))
#endif

#define TIMER_MIS   (*(volatile uint32_t*)(TIMER_BASE_SP804 + 0x10))

/* ARM Generic Timer pour machine virt (prefere) */
#define ARM_GENERIC_TIMER_FREQ_REG  14, 0, 0   /* CNTFRQ */
#define ARM_GENERIC_TIMER_COUNT_REG 14         /* CNTPCT */
#define ARM_GENERIC_TIMER_CTL_REG   14, 2, 1   /* CNTP_CTL */
#define ARM_GENERIC_TIMER_TVAL_REG  14, 2, 0   /* CNTP_TVAL */

/* Frequence fixe pour QEMU machine virt */
#define QEMU_TIMER_FREQ 62500000

/* Timer functions */
void init_timer(void);
void init_timer_software(void);
void update_timer_software(void);
void timer_irq_handler(void);
uint32_t get_timer_frequency(void);
void wake_up_sleeping_processes(void);
void timer_enable_scheduling(void);
uint64_t get_timer_count(void); 

/* Fonctions de lecture du timer */
uint32_t get_timer_frequency(void);
uint64_t get_timer_count(void);      /* <- Ajoutez cette ligne */
uint32_t get_system_ticks(void);
uint32_t get_time_ms(void);


/* ARM Generic Timer functions pour machine virt */
uint64_t get_generic_timer_count(void);
void set_generic_timer_compare(uint64_t compare_value);
void enable_generic_timer(void);
void disable_generic_timer(void);
void timer_set_timeout(uint64_t timeout_ticks);

/* Fonctions de debug */
void debug_timer_state(void);
void trigger_timer_interrupt(void);
void test_timer_functionality(void);

#endif