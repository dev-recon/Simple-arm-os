/* mmio.h - Header pour les fonctions PUT32/GET32 - VERSION CORRIGeE */

#ifndef MMIO_H
#define MMIO_H

#include <kernel/types.h>
#include <kernel/interrupt.h>

/* Declarations des fonctions assembleur - compatible avec kernel.h */
extern void PUT32(uint32_t address, uint32_t value);
extern uint32_t GET32(uint32_t address);

/* Wrappers pour compatibilite de types */
static inline void PUT8_MMIO(uint32_t address, uint8_t value) {
    PUT8(address, (unsigned int)value);
}

static inline uint8_t GET8_MMIO(uint32_t address) {
    return (uint8_t)GET8(address);
}

static inline void PUT16_MMIO(uint32_t address, uint16_t value) {
    PUT16(address, (unsigned int)value);
}

static inline uint16_t GET16_MMIO(uint32_t address) {
    return (uint16_t)GET16(address);
}

/* Versions avec barrieres renforcees */
extern void PUT32_STRONG(uint32_t address, uint32_t value);
extern uint32_t GET32_STRONG(uint32_t address);

/* Fonction de test MMIO */
extern uint32_t TEST_MMIO(uint32_t address);

/* Macros pour faciliter l'utilisation */
#define MMIO_WRITE32(addr, val)    PUT32((uint32_t)(addr), (uint32_t)(val))
#define MMIO_READ32(addr)          GET32((uint32_t)(addr))
#define MMIO_WRITE8(addr, val)     PUT8_MMIO((uint32_t)(addr), (uint8_t)(val))
#define MMIO_READ8(addr)           GET8_MMIO((uint32_t)(addr))

/* Macros pour registres specifiques - adapte pour machine virt */
#define GICD_BASE               VIRT_GIC_DIST_BASE
#define GICC_BASE               VIRT_GIC_CPU_BASE

#define GICD_WRITE(offset, val)    PUT32(GICD_BASE + (offset), (val))
#define GICD_READ(offset)          GET32(GICD_BASE + (offset))
#define GICC_WRITE(offset, val)    PUT32(GICC_BASE + (offset), (val))
#define GICC_READ(offset)          GET32(GICC_BASE + (offset))

/* Test et debug */
#define TEST_REGISTER_WRITE(addr)  TEST_MMIO((uint32_t)(addr))

/* Fonctions GIC inline - renommees pour eviter conflits */
static inline void gic_write_itargetsr_mmio(uint32_t irq, uint8_t cpu_mask)
{
    uint32_t addr = GICD_BASE + 0x800 + irq;
    PUT8_MMIO(addr, cpu_mask);
}

static inline void gic_set_irq_target_mmio(uint32_t irq, uint8_t cpu_mask)
{
    uint32_t addr = GICD_BASE + 0x800 + irq;  /* GICD_ITARGETSR */
    PUT8_MMIO(addr, cpu_mask);
}

static inline uint8_t gic_get_irq_target_mmio(uint32_t irq)
{
    uint32_t addr = GICD_BASE + 0x800 + irq;  /* GICD_ITARGETSR */
    return GET8_MMIO(addr);
}

static inline uint8_t gic_read_itargetsr_mmio(uint32_t irq)
{
    uint32_t addr = GICD_BASE + 0x800 + irq;
    return GET8_MMIO(addr);
}

static inline void gic_enable_irq_mmio(uint32_t irq)
{
    uint32_t reg = irq / 32;
    uint32_t bit = irq % 32;
    uint32_t addr = GICD_BASE + 0x100 + (reg * 4);
    
    uint32_t current = GET32(addr);
    PUT32(addr, current | (1 << bit));
}

static inline void gic_set_irq_pending_mmio(uint32_t irq)
{
    uint32_t reg = irq / 32;
    uint32_t bit = irq % 32;
    uint32_t addr = GICD_BASE + 0x200 + (reg * 4);
    
    PUT32(addr, (1 << bit));
}

static inline uint32_t gic_get_pending_irq_mmio(void)
{
    return GET32(GICC_BASE + 0x0C);  /* GICC_IAR */
}

static inline void gic_ack_irq_mmio(uint32_t irq_id)
{
    PUT32(GICC_BASE + 0x10, irq_id);  /* GICC_EOIR */
}

static inline void gic_set_priority_mmio(uint32_t irq, uint8_t priority)
{
    uint32_t addr = GICD_BASE + 0x400 + irq;  /* GICD_IPRIORITYR */
    PUT8_MMIO(addr, priority);
}

static inline void gic_configure_irq_type_mmio(uint32_t irq, bool edge_triggered)
{
    if (irq < 16) return;  /* SGI/PPI ne sont pas configurables */
    
    uint32_t cfg_reg = (irq - 16) / 16;
    uint32_t cfg_bit = ((irq - 16) % 16) * 2;
    uint32_t addr = GICD_BASE + 0x400 + (cfg_reg * 4);  /* GICD_ICFGR */
    
    uint32_t cfg_val = GET32(addr);
    if (edge_triggered) {
        cfg_val |= (0x2 << cfg_bit);   /* Edge-triggered */
    } else {
        cfg_val &= ~(0x2 << cfg_bit);  /* Level-sensitive */
    }
    PUT32(addr, cfg_val);
}

#endif /* MMIO_H */