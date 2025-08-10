/* include/kernel/interrupt.h */
#ifndef _KERNEL_INTERRUPT_H
#define _KERNEL_INTERRUPT_H

#include <kernel/types.h>

/* IRQ numbers */
#define IRQ_TIMER           30
#define IRQ_KEYBOARD        33
#define IRQ_ATA             34

/* Adresses CORRECTES pour QEMU VExpress-A9 */
//#define GICD_BASE 0x1E001000  /* GIC Distributor - VExpress-A9 */
//#define GICC_BASE 0x1E000100  /* GIC CPU Interface - VExpress-A9 */

/* GIC functions */
void init_gic(void);
void enable_irq(uint32_t irq);
void disable_irq(uint32_t irq);
void clear_irq(uint32_t irq);

/* IRQ handler */
void irq_c_handler(void);
void fiq_c_handler(void);


void complete_gic_debug(void);

#endif