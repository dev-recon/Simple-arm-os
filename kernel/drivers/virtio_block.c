/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/drivers/virtio_block.c
 * Layer: Kernel / VirtIO drivers
 *
 * Responsibilities:
 * - Negotiate VirtIO device features and queues.
 * - Provide block, GPU, or input transport services.
 *
 * Notes:
 * - Device ordering and cache coherency matter under preemption.
 */

#include <kernel/kernel.h>
#include <kernel/types.h>
#include <kernel/virtio_block.h>
#include <kernel/memory.h>
#include <kernel/string.h>
#include <kernel/kprintf.h>
#include <kernel/interrupt.h>
#include <kernel/task.h>
#include <kernel/timer.h>
#include <kernel/spinlock.h>
#include <asm/arm.h>


void vq_debug_print(vq_legacy_t *vq) {
    kprintf("VQ debug: pa_base=0x%08x va_base=0x%08X\n", vq->pa_base, (uintptr_t)vq->va_base);
    kprintf("pa_desc=0x%08x pa_avail=0x%08x pa_used=0x%08x\n", vq->pa_desc, vq->pa_avail, vq->pa_used);
    kprintf("va_desc=0x%08X va_avail=0x%08X va_used=0x%08X\n",
            (uintptr_t)vq->va_desc, (uintptr_t)vq->va_avail, (uintptr_t)vq->va_used);
    kprintf("sizes: desc=0x%x avail=0x%x used=0x%x qsize=%u last_used_idx=%u\n",
            vq->desc_size, vq->avail_size, vq->used_size, vq->qsize, vq->last_used_idx);
}

void virtio_blk_read_capacity(volatile uint32_t *mmio_base,
                              uint64_t *capacity_512b,
                              uint32_t *sector_size)
{
    /* Recomposition 64-bit à partir de deux reads 32-bit */
    uint32_t cap_lo = mmio_read32(mmio_base, VBLK_CFG_CAPACITY_LO);
    uint32_t cap_hi = mmio_read32(mmio_base, VBLK_CFG_CAPACITY_HI);
    *capacity_512b = ((uint64_t)cap_hi << 32) | cap_lo;

    /* Taille logique du secteur : 512 par défaut.
       Si tu as négocié VIRTIO_BLK_F_BLK_SIZE, lis VBLK_CFG_BLK_SIZE. */
    uint32_t blk_sz = mmio_read32(mmio_base, VBLK_CFG_BLK_SIZE);
    if (blk_sz == 0) blk_sz = 512;
    *sector_size = blk_sz;
}

vq_legacy_t global_vq = {0};
uint32_t ata_sector_size = 0;
static uint64_t virtio_capacity_sectors = 0;
static bool virtio_blk_failed = false;
static bool virtio_blk_readonly = false;
static bool virtio_blk_flush_supported = false;
static spinlock_t virtio_blk_lock = SPINLOCK_INIT("virtio_blk");
static volatile bool virtio_blk_busy = false;
static task_t *virtio_blk_owner = NULL;

typedef struct {
    volatile bool active;
    volatile bool completed;
    uint16_t prev_used_idx;
    vq_legacy_t *vq;
    task_t *waiter;
} virtio_blk_pending_t;

static virtio_blk_pending_t virtio_blk_pending = {0};

static void virtio_blk_acquire(void)
{
    while (1) {
        task_t *task = task_current_local();
        unsigned long flags;

        spin_lock_irqsave(&virtio_blk_lock, &flags);
        if (!virtio_blk_busy) {
            virtio_blk_busy = true;
            virtio_blk_owner = task;
            spin_unlock_irqrestore(&virtio_blk_lock, flags);
            return;
        }
        spin_unlock_irqrestore(&virtio_blk_lock, flags);

        /*
         * Block operations can sleep in wait_for_used(). Never hold a
         * spinlock while another request is in flight; wait cooperatively.
         */
        if (!task) {
            asm volatile("yield" ::: "memory");
            continue;
        }

        yield();
    }
}

static void virtio_blk_release(void)
{
    task_t *task = task_current_local();
    unsigned long flags;

    spin_lock_irqsave(&virtio_blk_lock, &flags);
    if (!virtio_blk_busy) {
        KERROR("virtio_blk: release without owner\n");
    } else if (virtio_blk_owner && task && virtio_blk_owner != task) {
        KERROR("virtio_blk: release by non-owner\n");
    }
    virtio_blk_busy = false;
    virtio_blk_owner = NULL;
    spin_unlock_irqrestore(&virtio_blk_lock, flags);
}

#define VIRTIO_FALLBACK_PHY_ADDR 0x0A003E00u
volatile uint32_t *virtio_mmio_base =
    (volatile uint32_t *)KERNEL_MMIO_VIRTIO_ADDR(VIRTIO_FALLBACK_PHY_ADDR);
static uint32_t virtio_blk_irq = VIRTIO_BLK_IRQ;

static inline uint32_t fdt32_to_cpu(uint32_t x)
{
    return __builtin_bswap32(x);
}

static bool virtio_blk_decode_reg(const uint32_t *reg, uint32_t len, uint32_t *out_phys)
{
    if (!reg || !out_phys)
        return false;

    if (len >= 16) {
        uint32_t addr_hi = fdt32_to_cpu(reg[0]);
        uint32_t addr_lo = fdt32_to_cpu(reg[1]);
        if (addr_hi != 0)
            return false;
        *out_phys = addr_lo;
        return true;
    }

    if (len >= 8) {
        *out_phys = fdt32_to_cpu(reg[0]);
        return true;
    }

    return false;
}

static bool virtio_blk_irq_from_mmio(uint32_t phys_base, uint32_t *out_irq)
{
    if (!out_irq)
        return false;
    if (phys_base < VIRT_VIRTIO_BASE)
        return false;
    if (((phys_base - VIRT_VIRTIO_BASE) % VIRT_VIRTIO_SIZE) != 0)
        return false;

    uint32_t index = (phys_base - VIRT_VIRTIO_BASE) / VIRT_VIRTIO_SIZE;
    *out_irq = VIRT_VIRTIO_IRQ(index);
    return true;
}

static bool virtio_blk_decode_interrupts(const uint32_t *intr, uint32_t len, uint32_t *out_irq)
{
    if (!intr || !out_irq || len < 4)
        return false;

    if (len >= 12) {
        uint32_t type = fdt32_to_cpu(intr[0]);
        uint32_t irq = fdt32_to_cpu(intr[1]);
        if (type == 0) {
            /*
             * QEMU virt exposes GIC interrupt specifiers.  This kernel's GIC
             * routing currently uses the local virtio-mmio IDs (16+n), so this
             * value is informational unless it matches that numbering.
             */
            *out_irq = irq;
            return true;
        }
    }

    *out_irq = fdt32_to_cpu(intr[0]);
    return true;
}

static bool virtio_blk_probe_from_dtb(uint32_t *out_phys, uint32_t *out_irq)
{
    void *dtb_ptr = (void *)dtb_address;
    if (!dtb_ptr || !out_phys || !out_irq)
        return false;

    struct fdt_header *fdt = (struct fdt_header *)dtb_ptr;
    if (fdt32_to_cpu(fdt->magic) != FDT_MAGIC)
        return false;

    uint8_t *struct_block = (uint8_t *)dtb_ptr + fdt32_to_cpu(fdt->off_dt_struct);
    uint32_t *token = (uint32_t *)struct_block;

    while (1) {
        uint32_t tag = fdt32_to_cpu(*token++);
        switch (tag) {
            case FDT_BEGIN_NODE: {
                void *node_ptr = (void *)(token - 1);
                const char *name = (const char *)token;
                size_t len = strlen(name);
                token += (len + 4) / 4;

                if (!fdt_node_matches(name, "virtio_mmio"))
                    break;

                uint32_t reg_len = 0;
                uint32_t *reg = (uint32_t *)fdt_get_property(dtb_ptr, node_ptr, "reg", &reg_len);
                uint32_t phys = 0;
                if (!virtio_blk_decode_reg(reg, reg_len, &phys))
                    break;

                volatile uint32_t *base = (volatile uint32_t *)KERNEL_MMIO_VIRTIO_ADDR(phys);
                if (mmio_read32(base, VIRTIO_MMIO_MAGIC) != 0x74726976)
                    break;
                if (mmio_read32(base, VIRTIO_MMIO_DEVICE_ID) != VIRTIO_ID_BLOCK)
                    break;

                uint32_t irq = VIRTIO_BLK_IRQ;
                uint32_t mmio_irq = 0;
                uint32_t dtb_irq = 0;
                bool have_mmio_irq = virtio_blk_irq_from_mmio(phys, &mmio_irq);

                uint32_t intr_len = 0;
                uint32_t *intr = (uint32_t *)fdt_get_property(dtb_ptr, node_ptr, "interrupts", &intr_len);
                bool have_dtb_irq = virtio_blk_decode_interrupts(intr, intr_len, &dtb_irq);

                if (have_mmio_irq) {
                    irq = mmio_irq;
                    if (have_dtb_irq && dtb_irq != mmio_irq) {
                        KDEBUG("VirtIO blk DTB interrupt=%u, local IRQ=%u; using local IRQ\n",
                               dtb_irq, mmio_irq);
                    }
                } else if (have_dtb_irq) {
                    irq = dtb_irq;
                }

                *out_phys = phys;
                *out_irq = irq;
                return true;
            }
            case FDT_PROP: {
                uint32_t prop_len = fdt32_to_cpu(*token++);
                token++;
                token += (prop_len + 3) / 4;
                break;
            }
            case FDT_END_NODE:
            case FDT_NOP:
                break;
            case FDT_END:
                return false;
            default:
                return false;
        }
    }
}

static uint32_t virtio_blk_resolve_mmio_base(uint32_t requested_base)
{
    uint32_t phys = 0;
    uint32_t irq = 0;

    if (virtio_blk_probe_from_dtb(&phys, &irq)) {
        virtio_mmio_base = (volatile uint32_t *)KERNEL_MMIO_VIRTIO_ADDR(phys);
        virtio_blk_irq = irq;
        KINFO("VirtIO block from DTB: phys=0x%08X mmio=%p irq=%u\n",
              phys, virtio_mmio_base, virtio_blk_irq);
        return (uint32_t)virtio_mmio_base;
    }

    virtio_mmio_base = (volatile uint32_t *)requested_base;
    virtio_blk_irq = VIRTIO_BLK_IRQ;
    KINFO("VirtIO block DTB probe failed, using fallback mmio=%p irq=%u\n",
          virtio_mmio_base, virtio_blk_irq);
    return requested_base;
}


// Alloue N pages contiguës physiquement et retourne VA=PA (si kernel mappe identitairement ≥0x40000000)
static void *alloc_dma_pages(size_t npages, uint32_t *out_pa) {
    uint32_t pa = (uint32_t)allocate_pages(npages); // <- ta fonction
    if (!pa) return NULL;
    if (out_pa) *out_pa = pa;
    // Sur ton kernel, TTBR1 mappe les sections 1:1 : VA == PA dans la RAM noyau
    return (void*)pa;
}


static bool vq_alloc_legacy(vq_legacy_t *vq, uint16_t qsize /*ex: 128*/) {
    // tailles des structures (virtio split ring legacy)
    uint32_t desc_sz  = 16u * qsize;                   // struct virtq_desc[Q]
    uint32_t avail_sz = ALIGN_UP(6u + 2u*qsize, 2u);   // virtq_avail header + ring
    uint32_t used_sz  = ALIGN_UP(6u + 8u*qsize, VQ_ALIGN); // used doit être aligné à VQ_ALIGN

    uint32_t total = ALIGN_UP(desc_sz, 16) + ALIGN_UP(avail_sz, 2) + ALIGN_UP(used_sz, VQ_ALIGN);

    // nb pages
    size_t npages = (total + PAGE_SIZE - 1) / PAGE_SIZE;

    uint32_t pa_base = 0;
    void *va_base = alloc_dma_pages(npages, &pa_base);
    if (!va_base) return false;

    // layout : [desc][avail][used aligné VQ_ALIGN]
    uint32_t off = 0;

    vq->pa_base = pa_base;
    vq->va_base = (uintptr_t)va_base;

    vq->pa_desc = pa_base + off;
    //vq->va_desc = (uint8_t*)va_base + off;
    vq->va_desc = (uintptr_t)((uint8_t*)va_base + off);
    vq->desc_size = desc_sz;
    off = ALIGN_UP(off + desc_sz, 16);

    vq->pa_avail = pa_base + off;
    //vq->va_avail = (uint8_t*)va_base + off;
    vq->va_avail = (uintptr_t)((uint8_t*)va_base + off);
    vq->avail_size = avail_sz;
    off = ALIGN_UP(off + avail_sz, 2);

    off = ALIGN_UP(off, VQ_ALIGN);
    vq->pa_used = pa_base + off;
    //vq->va_used = (uint8_t*)va_base + off;
    vq->va_used = (uintptr_t)((uint8_t*)va_base + off);
    vq->used_size = used_sz;

    vq->qsize = qsize;
    vq->last_used_idx = 0;

    // Optionnel: zeroise
    memset((void *)vq->va_base, 0, npages * PAGE_SIZE);

    // Maintenance cache avant de donner au device
    clean_dcache_by_mva((void *)vq->va_base, npages * PAGE_SIZE);
    return true;
}

static void virtio_blk_mark_failed(volatile uint32_t *mmio_base, const char *reason)
{
    virtio_blk_failed = true;
    KERROR("virtio_blk: marking device failed: %s\n", reason ? reason : "unknown");
    if (mmio_base)
        mmio_write32(mmio_base, VIRTIO_MMIO_STATUS,
                     mmio_read32(mmio_base, VIRTIO_MMIO_STATUS) | VIRTIO_STATUS_FAILED);
}

static void virtio_blk_ack_interrupts(volatile uint32_t *mmio_base)
{
    uint32_t irq_status = mmio_read32(mmio_base, VIRTIO_MMIO_INTERRUPT_STATUS);
    if (irq_status)
        mmio_write32(mmio_base, VIRTIO_MMIO_INTERRUPT_ACK, irq_status);
}

static bool virtio_blk_request_in_bounds(uint64_t sector, uint32_t nsectors)
{
    if (virtio_blk_failed || ata_sector_size != 512 || virtio_capacity_sectors == 0)
        return false;
    if (nsectors == 0)
        return false;
    if (sector >= virtio_capacity_sectors)
        return false;
    if ((uint64_t)nsectors > virtio_capacity_sectors - sector)
        return false;
    return true;
}

static inline void virtio_dma_to_device(const void *addr, size_t size)
{
    clean_dcache_by_mva(addr, size);
}

static inline void virtio_dma_from_device(void *addr, size_t size)
{
    clean_invalidate_dcache_by_mva(addr, size);
}

void virtio_mmio_dump32(uintptr_t base)
{
    kprintf("=== VIRTIO MMIO DUMP (32-bit) @ 0x%08X ===\n", (uint32_t)base);
    // Registres legacy lisibles typiques
    struct { const char* name; uint32_t off; } regs[] = {
        {"MAGIC",          0x000},
        {"VERSION",        0x004},
        {"DEVICE_ID",      0x008},
        {"VENDOR_ID",      0x00C},
        {"DEVICE_FEATURES",0x010},   // lisible
        {"QUEUE_SEL",      0x030},   // R/W
        {"QUEUE_NUM_MAX",  0x034},   // lisible
        {"QUEUE_NUM",      0x038},   // R/W
        {"STATUS",         0x070},   // legacy: 0x070 (v1)
        {"INT_STATUS",     0x060},   // legacy: 0x060
        {"QUEUE_NOTIFY",   0x050},   // write-only normalement → lira 0
    };
    for (unsigned i = 0; i < sizeof(regs)/sizeof(regs[0]); i++) {
        uint32_t v = mmio_read32((void*)base, regs[i].off);
        kprintf("  %-16s @ +0x%03X = 0x%08X\n", regs[i].name, regs[i].off, v);
    }
}


bool virtio_blk_init_legacy(uint32_t base_addr)
{
    
    base_addr = virtio_blk_resolve_mmio_base(base_addr);
    volatile uint32_t *base = (volatile uint32_t *)base_addr;
    virtio_blk_failed = false;
    virtio_blk_readonly = false;
    virtio_blk_flush_supported = false;
    virtio_capacity_sectors = 0;

    uint32_t magic   = mmio_read32(base, VIRTIO_MMIO_MAGIC);
    uint32_t version = mmio_read32(base, VIRTIO_MMIO_VERSION);
    uint32_t devid   = mmio_read32(base, VIRTIO_MMIO_DEVICE_ID);

    KDEBUG("virtio-mmio magic 0x%08X @0x%08X\n", magic, base_addr);

    if (magic != 0x74726976) {
        KERROR("virtio-mmio bad magic 0x%08X @0x%08X\n", magic, base_addr);
        virtio_mmio_dump32(base_addr);
        return false;
    }

    KDEBUG("VirtIO version = %u\n", version);

    if (version != 1) {
        KERROR("VirtIO unsupported MMIO version=%u (legacy driver expects 1)\n", version);
        virtio_mmio_dump32(base_addr);
        return false;
    }

    if (devid != 2) {
        KERROR("VirtIO device ID=%u (expected 2=blk)\n", devid);
        virtio_mmio_dump32(base_addr);
        return false;
    }


    // Reset
    mmio_write32(base, VIRTIO_MMIO_STATUS, 0);

    // ACK + DRIVER
    mmio_write32(base, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_ACK);
    mmio_write32(base, VIRTIO_MMIO_STATUS, mmio_read32(base, VIRTIO_MMIO_STATUS) | VIRTIO_STATUS_DRIVER);

    uint32_t device_features = mmio_read32(base, VIRTIO_MMIO_DEVICE_FEATURES);
    virtio_blk_readonly = (device_features & (1u << VIRTIO_BLK_F_RO)) != 0;
    virtio_blk_flush_supported = (device_features & (1u << VIRTIO_BLK_F_FLUSH)) != 0;
    if (virtio_blk_readonly)
        KINFO("VirtIO block device is read-only\n");

    uint32_t driver_features = virtio_blk_flush_supported ? (1u << VIRTIO_BLK_F_FLUSH) : 0;
    mmio_write32(base, VIRTIO_MMIO_DRIVER_FEATURES, driver_features);

    // FEATURES_OK
    mmio_write32(base, VIRTIO_MMIO_STATUS, mmio_read32(base, VIRTIO_MMIO_STATUS) | VIRTIO_STATUS_FEATURES_OK);
    if (!(mmio_read32(base, VIRTIO_MMIO_STATUS) & VIRTIO_STATUS_FEATURES_OK)) {
        // Le device a rejeté nos features
        virtio_blk_mark_failed(base, "feature negotiation rejected");
        return false;
    }

    mmio_write32(base, VIRTIO_REG_GUEST_PAGE_SIZE, PAGE_SIZE);

    // Queue 0
    mmio_write32(base, VIRTIO_MMIO_QUEUE_SEL, 0);
    uint32_t qmax = mmio_read32(base, VIRTIO_MMIO_QUEUE_NUM_MAX);
    if (qmax == 0) {
        virtio_blk_mark_failed(base, "queue 0 unavailable");
        return false;
    }

    uint16_t qsize = (VQ_SIZE <= qmax) ? VQ_SIZE : (uint16_t)qmax;
    mmio_write32(base, VIRTIO_MMIO_QUEUE_NUM, qsize);
    mmio_write32(base, VIRTIO_MMIO_QUEUE_ALIGN_OFF, VQ_ALIGN);

    uint32_t align_rb = mmio_read32(base, VIRTIO_MMIO_QUEUE_ALIGN_OFF);
    if (align_rb != 0 && align_rb != VQ_ALIGN)
        KWARN("VirtIO QueueAlign readback=0x%X (expected 0x%X)\n", align_rb, VQ_ALIGN);

        /* Setup virtqueue */
    KDEBUG("Setting up virtqueue...\n");
    //if (!setup_virtqueue()) {
    //    KERROR("Failed to setup virtqueue\n");
    //    mmio_write32(base, VIRTIO_MMIO_STATUS,VIRTIO_STATUS_FAILED);
    //    return false;
    //}

    // Allouer le ring legacy
    //vq_legacy_t vq = {0};
    if (!vq_alloc_legacy(&global_vq, qsize)) {
        virtio_blk_mark_failed(base, "virtqueue allocation failed");
        return false;
    }

    // IMPORTANT: legacy → on programme la PFN (= base_phys >> 12)
    mmio_write32(base, VIRTIO_MMIO_QUEUE_PFN, global_vq.pa_base >> 12);

    /* Enable IRQ */
    KDEBUG("Configuring VirtIO IRQs...\n");
    enable_irq(virtio_blk_irq);
    KINFO("VirtIO IRQ %u enabled\n", virtio_blk_irq);

    // DRIVER_OK
    mmio_write32(base, VIRTIO_MMIO_STATUS, mmio_read32(base, VIRTIO_MMIO_STATUS) | VIRTIO_STATUS_DRIVER_OK);

    /* Read device capacity */
    KDEBUG("Reading device capacity...\n");

    uint64_t capacity;
    uint32_t sector_size;

    virtio_blk_read_capacity(base, &capacity, &sector_size);
    if (capacity == 0) {
        KERROR("VirtIO block device reports zero capacity\n");
        virtio_blk_mark_failed(base, "zero capacity");
        return false;
    }
    if (sector_size != 512) {
        KERROR("VirtIO block sector_size=%u unsupported by current block layer\n", sector_size);
        virtio_blk_mark_failed(base, "unsupported sector size");
        return false;
    }

    ata_sector_size = sector_size;
    virtio_capacity_sectors = capacity;
    
    KINFO("Device capacity: %u sectors (%u MB)\n", 
          (uint32_t)capacity, 
          (uint32_t)(capacity * sector_size / (1024*1024)));
    
    /* Finalize initialization */
    //ata_device.initialized = true;
    //ata_device.next_request_id = 1;

    return true;
}


/* Helpers pour accéder aux structures dans la zone allouée */
static inline struct vring_desc *vq_desc_ptr(vq_legacy_t *vq, unsigned i) {
    //return (struct vring_desc *)((uint8_t *)vq->va_desc + i * sizeof(struct vring_desc));
    return (struct vring_desc *)((uint8_t *)(uintptr_t)vq->va_desc + i * sizeof(struct vring_desc));

}
static inline struct vring_avail *vq_avail_ptr(vq_legacy_t *vq) {
    //return (struct vring_avail *)(vq->va_avail);
    return (struct vring_avail *)((uint8_t *)(uintptr_t)vq->va_avail);
}
static inline struct vring_used *vq_used_ptr(vq_legacy_t *vq) {
    //return (struct vring_used *)(vq->va_used);
    return (struct vring_used *)((uint8_t *)(uintptr_t)vq->va_used);
}

/* Lit le compteur physique 64-bit du generic timer ARM (toujours actif sur A15). */
static inline uint64_t vblk_cntpct(void) {
    uint32_t lo, hi;
    asm volatile("mrrc p15, 0, %0, %1, c14" : "=r"(lo), "=r"(hi));
    return ((uint64_t)hi << 32) | lo;
}

void virtio_block_irq_handler(void)
{
    virtio_blk_ack_interrupts(virtio_mmio_base);

    if (!virtio_blk_pending.active || !virtio_blk_pending.vq)
        return;

    /*
     * Completion IRQ: on ne prend pas virtio_blk_lock ici, car le thread qui a
     * soumis la requete le garde jusqu'a la fin. Le handler observe seulement
     * le used ring et reveille la tache bloquee.
     */
    vq_legacy_t *vq = virtio_blk_pending.vq;
    invalidate_dcache_by_mva((void *)(uintptr_t)vq->va_used,
        sizeof(struct vring_used) + vq->qsize * sizeof(struct vring_used_elem));
    asm volatile("dmb ish" ::: "memory");

    if (vq_used_ptr(vq)->idx != virtio_blk_pending.prev_used_idx) {
        virtio_blk_pending.completed = true;
        if (virtio_blk_pending.waiter &&
            (virtio_blk_pending.waiter->state == TASK_BLOCKED ||
             virtio_blk_pending.waiter->state == TASK_INTERRUPTIBLE ||
             virtio_blk_pending.waiter->state == TASK_UNINTERRUPTIBLE)) {
            virtio_blk_pending.waiter->wakeup_time = 0;
            add_to_ready_queue(virtio_blk_pending.waiter);
        }
    }
}

static bool virtio_blk_used_advanced(vq_legacy_t *vq, uint16_t prev_idx)
{
    invalidate_dcache_by_mva((void *)(uintptr_t)vq->va_used,
        sizeof(struct vring_used) + vq->qsize * sizeof(struct vring_used_elem));
    asm volatile("dmb ish" ::: "memory");

    return vq_used_ptr(vq)->idx != prev_idx;
}

static void virtio_blk_prepare_wait(vq_legacy_t *vq, uint16_t prev_idx)
{
    virtio_blk_pending.active = true;
    virtio_blk_pending.completed = false;
    virtio_blk_pending.prev_used_idx = prev_idx;
    virtio_blk_pending.vq = vq;
    virtio_blk_pending.waiter = task_current_local();
    asm volatile("dmb ish" ::: "memory");
}

static void virtio_blk_finish_wait(void)
{
    virtio_blk_pending.active = false;
    virtio_blk_pending.completed = false;
    virtio_blk_pending.prev_used_idx = 0;
    virtio_blk_pending.vq = NULL;
    virtio_blk_pending.waiter = NULL;
    asm volatile("dmb ish" ::: "memory");
}

/* Attente IRQ-backed avec timeout: l'IRQ reveille vite, le timer borne l'attente. */
static int wait_for_used(vq_legacy_t *vq, uint16_t prev_idx, unsigned timeout_ms)
{
    const uint32_t spin_budget = 512;
    uint32_t freq;
    uint32_t spins = 0;
    asm volatile("mrc p15, 0, %0, c14, c0, 0" : "=r"(freq));
    if (freq == 0) freq = 62500000; /* 62.5 MHz défaut QEMU */

    uint64_t timeout_ticks = (uint64_t)timeout_ms * (uint64_t)(freq / 1000);
    uint64_t t0 = vblk_cntpct();
    uint32_t wake_deadline = get_system_ticks() + 2;

    while (1) {
        if (virtio_blk_pending.completed || virtio_blk_used_advanced(vq, prev_idx))
            return 0;

        if ((vblk_cntpct() - t0) >= timeout_ticks) {
            KERROR("virtio_blk: timeout waiting used ring\n");
            return -1;
        }

        if (spins++ < spin_budget) {
            asm volatile("yield" ::: "memory");
            continue;
        }
        spins = 0;

        task_t *task = task_current_local();
        if (!task) {
            wait_for_interrupt();
            continue;
        }

        uint32_t irq_flags = disable_interrupts_save();
        if (virtio_blk_pending.completed || virtio_blk_used_advanced(vq, prev_idx)) {
            restore_interrupts(irq_flags);
            return 0;
        }

        /*
         * A submitted block request cannot be safely aborted in this simple
         * single-request virtqueue. Wait non-interruptibly until completion or
         * timeout; pending signals will be handled when the syscall returns.
         */
        task_set_uninterruptible(task);
        task->wakeup_time = wake_deadline;
        restore_interrupts(irq_flags);

        schedule();

        wake_deadline = get_system_ticks() + 2;
    }
}

/* Fonction générique de soumission synchrone (1 request) */
static int virtio_blk_submit_one(vq_legacy_t *vq,
                                volatile uint32_t *mmio_base,
                                struct virtio_blk_req *hdr, uint32_t hdr_pa,
                                void *data_va, uint32_t data_pa, uint32_t data_len, int data_is_write,
                                uint8_t *status_va, uint32_t status_pa, unsigned timeout_ms)
{
    /* choix des descripteurs : on utilise 3 descripteurs fixes : 0,1,2 (simple) */
    const unsigned d0 = 0, d1 = 1, d2 = 2;
    if (virtio_blk_failed) return -1;
    if (vq->qsize < 3) return -1;

    uint32_t dev_status = mmio_read32(mmio_base, VIRTIO_MMIO_STATUS);
    if (dev_status & VIRTIO_STATUS_DEVICE_NEEDS_RESET) {
        virtio_blk_mark_failed(mmio_base, "device needs reset");
        return -1;
    }

    *status_va = 0xFF;

    /* remplissage des descriptors (phys addrs) */
    struct vring_desc *desc0 = vq_desc_ptr(vq, d0);
    struct vring_desc *desc1 = vq_desc_ptr(vq, d1);
    struct vring_desc *desc2 = vq_desc_ptr(vq, d2);

    /* header */
    desc0->addr  = (uint64_t)hdr_pa;                        /* UN store 64-bit */
    desc0->len   = (uint32_t)sizeof(struct virtio_blk_req);/* must be non-zero */
    desc0->flags = (uint16_t)VRING_DESC_F_NEXT;
    desc0->next  = (uint16_t)d1;

    /* data */
    desc1->addr  = (uint64_t)data_pa;
    desc1->len   = (uint32_t)data_len;
    desc1->flags = (uint16_t)((data_is_write ? VRING_DESC_F_WRITE : 0) | VRING_DESC_F_NEXT);
    /* note: data_is_write==1 means device will write into the buffer => WRITE flag set */
    desc1->next  = (uint16_t)d2;

    /* status: device writes 1 byte status */
    desc2->addr  = (uint64_t)status_pa;
    desc2->len   = (uint32_t)1;
    desc2->flags = (uint16_t)VRING_DESC_F_WRITE;
    desc2->next  = (uint16_t)0;


    /* --- Flush descriptors ENTIER (important) --- */
    clean_dcache_by_mva((void *)vq->va_desc, sizeof(struct vring_desc) * vq->qsize); /* ou au moins 3*16 */
    asm volatile("dmb ish" ::: "memory"); /* ensure desc visible */

    /* DMA ownership:
     * - header is read by the device
     * - data is read or written depending on request type
     * - status is written by the device
     */
    virtio_dma_to_device(hdr, sizeof(struct virtio_blk_req));
    if (data_is_write) {
        virtio_dma_from_device(data_va, data_len);
    } else {
        virtio_dma_to_device(data_va, data_len);
    }
    virtio_dma_from_device(status_va, 1);
    asm volatile("dmb ish" ::: "memory");

    /* --- Publier avail entry de façon sûre --- */
    uint16_t prev_used = vq->last_used_idx;
    virtio_blk_prepare_wait(vq, prev_used);

    uint16_t old_idx = vq_avail_ptr(vq)->idx;
    uint16_t slot = old_idx % vq->qsize;
    vq_avail_ptr(vq)->ring[slot] = d0;

    /* flush ring slot (ou entire avail) */
    clean_dcache_by_mva((void *)vq->va_avail, vq->avail_size);
    asm volatile("dmb ish" ::: "memory");

    /* incrément idx */
    vq_avail_ptr(vq)->idx = old_idx + 1;
    clean_dcache_by_mva((void *)&vq_avail_ptr(vq)->idx, sizeof(vq_avail_ptr(vq)->idx));
    asm volatile("dsb ishst" ::: "memory");

    /* debug post-publish: re-read desc fields (après flush so they reflect final memory) */
    mmio_write32(mmio_base, VIRTIO_MMIO_QUEUE_NOTIFY, 0);

    asm volatile("dsb ishst" ::: "memory");
    asm volatile("isb" ::: "memory");

    /* wait for completion by polling used.idx (blocking) */
    if (wait_for_used(vq, prev_used, timeout_ms) != 0) {
        virtio_blk_finish_wait();
        virtio_blk_mark_failed(mmio_base, "request timeout");
        return -1;
    }

    virtio_blk_finish_wait();

    /* read the used element (invalidate used memory then read) */
    invalidate_dcache_by_mva((void *)vq->va_used, sizeof(struct vring_used) + vq->qsize * sizeof(struct vring_used_elem));
    struct vring_used *used = vq_used_ptr(vq);
    uint16_t new_used_idx = used->idx;
    uint16_t used_delta = (uint16_t)(new_used_idx - prev_used);
    if (used_delta != 1) {
        virtio_blk_mark_failed(mmio_base, "unexpected used ring advance");
        return -1;
    }

    uint16_t used_pos = prev_used % vq->qsize;
    struct vring_used_elem *ue = &used->ring[used_pos];
    if (ue->id != d0) {
        virtio_blk_mark_failed(mmio_base, "unexpected used descriptor id");
        return -1;
    }

    /* mark last seen */
    vq->last_used_idx = new_used_idx;
    virtio_blk_ack_interrupts(mmio_base);

    /* read status */
    invalidate_dcache_by_mva(status_va, 1);
    uint8_t status = *status_va;


    if (status != VIRTIO_BLK_S_OK) {
        KERROR("virtio_blk: device returned status=0x%02X\n", status);
        return -1;
    }

    return 0;
}

static int virtio_blk_submit_flush(vq_legacy_t *vq,
                                  volatile uint32_t *mmio_base,
                                  struct virtio_blk_req *hdr, uint32_t hdr_pa,
                                  uint8_t *status_va, uint32_t status_pa,
                                  unsigned timeout_ms)
{
    const unsigned d0 = 0, d2 = 2;
    if (virtio_blk_failed) return -1;
    if (!virtio_blk_flush_supported) return 0;
    if (vq->qsize < 3) return -1;

    uint32_t dev_status = mmio_read32(mmio_base, VIRTIO_MMIO_STATUS);
    if (dev_status & VIRTIO_STATUS_DEVICE_NEEDS_RESET) {
        virtio_blk_mark_failed(mmio_base, "device needs reset before flush");
        return -1;
    }

    *status_va = 0xFF;
    hdr->type = VIRTIO_BLK_T_FLUSH;
    hdr->reserved = 0;
    hdr->sector = 0;

    struct vring_desc *desc0 = vq_desc_ptr(vq, d0);
    struct vring_desc *desc2 = vq_desc_ptr(vq, d2);

    desc0->addr  = (uint64_t)hdr_pa;
    desc0->len   = (uint32_t)sizeof(struct virtio_blk_req);
    desc0->flags = (uint16_t)VRING_DESC_F_NEXT;
    desc0->next  = (uint16_t)d2;

    desc2->addr  = (uint64_t)status_pa;
    desc2->len   = 1;
    desc2->flags = (uint16_t)VRING_DESC_F_WRITE;
    desc2->next  = 0;

    clean_dcache_by_mva((void *)vq->va_desc, sizeof(struct vring_desc) * vq->qsize);
    virtio_dma_to_device(hdr, sizeof(struct virtio_blk_req));
    virtio_dma_from_device(status_va, 1);
    asm volatile("dmb ish" ::: "memory");

    uint16_t prev_used = vq->last_used_idx;
    virtio_blk_prepare_wait(vq, prev_used);

    uint16_t old_idx = vq_avail_ptr(vq)->idx;
    vq_avail_ptr(vq)->ring[old_idx % vq->qsize] = d0;
    clean_dcache_by_mva((void *)vq->va_avail, vq->avail_size);
    asm volatile("dmb ish" ::: "memory");

    vq_avail_ptr(vq)->idx = old_idx + 1;
    clean_dcache_by_mva((void *)&vq_avail_ptr(vq)->idx, sizeof(vq_avail_ptr(vq)->idx));
    asm volatile("dsb ishst" ::: "memory");

    mmio_write32(mmio_base, VIRTIO_MMIO_QUEUE_NOTIFY, 0);
    asm volatile("dsb ishst; isb" ::: "memory");

    if (wait_for_used(vq, prev_used, timeout_ms) != 0) {
        virtio_blk_finish_wait();
        virtio_blk_mark_failed(mmio_base, "flush timeout");
        return -1;
    }

    virtio_blk_finish_wait();
    invalidate_dcache_by_mva((void *)vq->va_used,
        sizeof(struct vring_used) + vq->qsize * sizeof(struct vring_used_elem));

    struct vring_used *used = vq_used_ptr(vq);
    uint16_t new_used_idx = used->idx;
    if ((uint16_t)(new_used_idx - prev_used) != 1) {
        virtio_blk_mark_failed(mmio_base, "unexpected used ring advance after flush");
        return -1;
    }
    if (used->ring[prev_used % vq->qsize].id != d0) {
        virtio_blk_mark_failed(mmio_base, "unexpected flush descriptor id");
        return -1;
    }

    vq->last_used_idx = new_used_idx;
    virtio_blk_ack_interrupts(mmio_base);

    invalidate_dcache_by_mva(status_va, 1);
    if (*status_va != VIRTIO_BLK_S_OK) {
        KERROR("virtio_blk: flush status=0x%02X\n", *status_va);
        return -1;
    }

    return 0;
}




/* API haut niveau : lire N secteurs (bloquants). buf est un VA noyau ; on copie via DMA buffer. */
int virtio_blk_read_sectors(volatile uint32_t *mmio_base,
                            vq_legacy_t *vq,
                            uint64_t sector,
                            uint32_t nsectors,
                            void *buf /* va kernel */,
                            unsigned timeout_ms)
{
    uint32_t sector_size = ata_sector_size;
    if (!mmio_base || !vq) return -1;
    if (!buf) return -1;
    if (!virtio_blk_request_in_bounds(sector, nsectors)) return -1;
    if (nsectors > 0xFFFFFFFFu / sector_size) return -1;
    uint32_t bytes = nsectors * sector_size;
    if (bytes == 0) return -1;

    virtio_blk_acquire();
    if (virtio_blk_failed) {
        virtio_blk_release();
        return -1;
    }

    /* allocation DMA pour header+status (1 page) */
    uint32_t hdr_pa = 0;
    void *hdr_va = alloc_dma_pages(1, &hdr_pa);
    if (!hdr_va) {
        virtio_blk_release();
        return -1;
    }
    struct virtio_blk_req *hdr = (struct virtio_blk_req *)hdr_va;
    uint8_t *status_va = ((uint8_t*)hdr_va) + 512; /* statut à offset arbitraire dans la page */
    uint32_t status_pa = hdr_pa + 512;

    /* allocation DMA pour data */
    size_t npages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    uint32_t data_pa = 0;
    void *data_va = alloc_dma_pages(npages, &data_pa);
    if (!data_va) {
        free_pages(hdr_va, 1);
        virtio_blk_release();
        return -1;
    }

    /* Fill header */
    hdr->type = VIRTIO_BLK_T_IN;
    hdr->reserved = 0;
    hdr->sector = sector;

    /* sync caches */
    /* data_va need not be filled for read */

    /* submit request (device will fill data_va and status) */
    int r = virtio_blk_submit_one(vq, mmio_base, hdr, hdr_pa, data_va, data_pa, bytes, /*data_is_write=*/1, status_va, status_pa, timeout_ms);
    if (r != 0) {
        /*
         * Ne pas liberer apres un timeout: sans annulation/reset du device,
         * il pourrait encore referencer ces buffers DMA.
         */
        if (!virtio_blk_failed) {
            free_pages(data_va, npages);
            free_pages(hdr_va, 1);
        }
        virtio_blk_release();
        return -1;
    }

    /* copy back to user buffer */
    invalidate_dcache_by_mva(data_va, bytes);
    memcpy(buf, data_va, bytes);

    free_pages(data_va, npages);
    free_pages(hdr_va, 1);
    virtio_blk_release();
    return 0;
}

/* API haut niveau : écrire N secteurs (bloquants). buf est VA noyau */
int virtio_blk_write_sectors(volatile uint32_t *mmio_base,
                             vq_legacy_t *vq,
                             uint64_t sector,
                             uint32_t nsectors,
                             const void *buf /* va kernel */,
                             unsigned timeout_ms)
{
    uint32_t sector_size = ata_sector_size;
    if (!mmio_base || !vq) return -1;
    if (!buf) return -1;
    if (!virtio_blk_request_in_bounds(sector, nsectors)) return -1;
    if (nsectors > 0xFFFFFFFFu / sector_size) return -1;
    uint32_t bytes = nsectors * sector_size;
    if (bytes == 0) return -1;
    if (virtio_blk_readonly) return -1;

    virtio_blk_acquire();
    if (virtio_blk_failed) {
        virtio_blk_release();
        return -1;
    }

    /* allocation DMA pour header+status (1 page) */
    uint32_t hdr_pa = 0;
    void *hdr_va = alloc_dma_pages(1, &hdr_pa);
    if (!hdr_va) {
        virtio_blk_release();
        return -1;
    }
    struct virtio_blk_req *hdr = (struct virtio_blk_req *)hdr_va;
    uint8_t *status_va = ((uint8_t*)hdr_va) + 512;
    uint32_t status_pa = hdr_pa + 512;

    /* allocation DMA pour data */
    size_t npages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    uint32_t data_pa = 0;
    void *data_va = alloc_dma_pages(npages, &data_pa);
    if (!data_va) {
        free_pages(hdr_va, 1);
        virtio_blk_release();
        return -1;
    }

    /* copy user data into DMA buffer */
    memcpy(data_va, buf, bytes);

    /* Fill header */
    hdr->type = VIRTIO_BLK_T_OUT;
    hdr->reserved = 0;
    hdr->sector = sector;

    /* submit request (device will read data_va and write status) */
    int r = virtio_blk_submit_one(vq, mmio_base, hdr, hdr_pa, data_va, data_pa, bytes, /*data_is_write=*/0, status_va, status_pa, timeout_ms);
    if (r != 0) {
        /* Voir le chemin read: un timeout ne prouve pas que le DMA est fini. */
        if (!virtio_blk_failed) {
            free_pages(data_va, npages);
            free_pages(hdr_va, 1);
        }
        virtio_blk_release();
        return -1;
    }

    free_pages(data_va, npages);
    free_pages(hdr_va, 1);
    virtio_blk_release();
    return 0;
}

int blk_read_sectors(uint64_t lba, uint32_t count, void* buffer) {

    return virtio_blk_read_sectors( virtio_mmio_base, &global_vq, lba, count, buffer, VIRTIO_BLOCK_TIMEOUT);
}

int blk_write_sectors(uint64_t lba, uint32_t count, void* buffer) {

    return virtio_blk_write_sectors( virtio_mmio_base, &global_vq, lba, count, buffer, VIRTIO_BLOCK_TIMEOUT);
}

int blk_read_sector(uint64_t lba, void* buffer) {

    return virtio_blk_read_sectors( virtio_mmio_base, &global_vq, lba, 1, buffer, VIRTIO_BLOCK_TIMEOUT);
}

int blk_write_sector(uint64_t lba, void* buffer) {

    return virtio_blk_write_sectors( virtio_mmio_base, &global_vq, lba, 1, buffer, VIRTIO_BLOCK_TIMEOUT);
}

bool blk_is_initialized(void) {
    return ata_sector_size > 0 && virtio_capacity_sectors > 0 && !virtio_blk_failed;
}

uint64_t blk_get_capacity_sectors(void)
{
    return virtio_capacity_sectors;
}

uint32_t blk_get_sector_size(void)
{
    return ata_sector_size;
}

bool blk_is_readonly(void)
{
    return virtio_blk_readonly;
}

int virtio_blk_flush(void)
{
    if (!blk_is_initialized())
        return -1;
    if (!virtio_blk_flush_supported)
        return 0;

    virtio_blk_acquire();
    if (virtio_blk_failed) {
        virtio_blk_release();
        return -1;
    }

    uint32_t hdr_pa = 0;
    void *hdr_va = alloc_dma_pages(1, &hdr_pa);
    if (!hdr_va) {
        virtio_blk_release();
        return -1;
    }

    struct virtio_blk_req *hdr = (struct virtio_blk_req *)hdr_va;
    uint8_t *status_va = ((uint8_t *)hdr_va) + 512;
    uint32_t status_pa = hdr_pa + 512;

    int ret = virtio_blk_submit_flush(&global_vq, virtio_mmio_base, hdr, hdr_pa,
                                      status_va, status_pa, VIRTIO_BLOCK_TIMEOUT);
    if (!virtio_blk_failed)
        free_pages(hdr_va, 1);

    virtio_blk_release();
    return ret;
}

void virtio_blk_shutdown(void)
{
    if (!blk_is_initialized())
        return;

    int ret = virtio_blk_flush();
    if (ret < 0)
        KERROR("virtio_blk: flush failed during shutdown\n");

    virtio_blk_ack_interrupts(virtio_mmio_base);
    mmio_write32(virtio_mmio_base, VIRTIO_MMIO_STATUS, 0);
    asm volatile("dsb sy; isb" ::: "memory");
}

uint32_t virtio_blk_get_irq(void)
{
    return virtio_blk_irq;
}


void read_sector0_and_print(void)
{
    if (ata_sector_size == 0) {
        // Remplace par ta condition réelle, ex: ata_device.initialized
        // if (!ata_device.initialized) { KERROR("blk not initialized\n"); return; }
        KERROR("blk not initialized\n");
        return;
    }

    uint32_t sec_size = ata_sector_size ? ata_sector_size : 512;
    if (sec_size > 4096) {
        KERROR("unexpected sector_size=%u\n", sec_size);
        return;
    }

    /* buffer noyau pour recevoir le secteur (ici on assume qu'un buffer sur la pile est OK) */
    uint8_t buf[4096];   /* large enough pour la plupart des tailles de secteurs */
    memset(buf, 0, sec_size);

    int ret = virtio_blk_read_sectors(virtio_mmio_base, &global_vq, /*sector=*/0, /*nsectors=*/1, buf, /*timeout_ms=*/VIRTIO_BLOCK_TIMEOUT);
    if (ret != 0) {
        KERROR("virtio read sector 0 failed (ret=%d)\n", ret);
        return;
    }

    /* Hex dump (ligne de 16 octets) */
    kprintf("Sector 0 (%u bytes) hex dump:\n", sec_size);
    for (unsigned i = 0; i < sec_size; i += 16) {
        kprintf("%04x: ", i);
        for (unsigned j = 0; j < 16 && (i + j) < sec_size; ++j)
            kprintf("%02x ", buf[i + j]);
        kprintf("\n");
    }

    /* Parser la table de partitions MBR si secteur de 512 octets (entries à offset 446) */
    if (sec_size >= 512) {
        const unsigned part_base = 446;
        kprintf("\nMBR partitions (offset %u):\n", part_base);
        for (int p = 0; p < 4; ++p) {
            unsigned off = part_base + p * 16;
            uint8_t boot = buf[off + 0];
            uint8_t type = buf[off + 4];
            uint32_t start_lba = 0;
            uint32_t num_sectors = 0;
            memcpy(&start_lba, &buf[off + 8], 4);   // little-endian on x86/virtio
            memcpy(&num_sectors, &buf[off + 12], 4);
            kprintf("Part %d: boot=0x%02x type=0x%02x start=%u size=%u\n",
                    p, boot, type, (unsigned)start_lba, (unsigned)num_sectors);
        }

        /* signature 0x55AA check */
        if (buf[510] == 0x55 && buf[511] == 0xAA) {
            kprintf("MBR signature OK (0x55AA)\n");
        } else {
            kprintf("No valid MBR signature (0x%02x%02x)\n", buf[510], buf[511]);
        }
    } else {
        kprintf("sector size < 512, skipping MBR parse\n");
    }
}
