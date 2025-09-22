#include <kernel/kernel.h>
#include <kernel/types.h>
#include <kernel/virtio_block.h>
#include <kernel/memory.h>
#include <kernel/string.h>
#include <kernel/kprintf.h>
#include <kernel/interrupt.h>
#include <kernel/task.h>
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

#define VIRTIO_PHY_ADDR 0x0A003E00u
volatile uint32_t *virtio_mmio_base = (volatile uint32_t *)VIRTIO_PHY_ADDR;


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

    // Optionnel: zeroise
    memset((void *)vq->va_base, 0, npages * PAGE_SIZE);

    // Maintenance cache avant de donner au device
    clean_dcache_by_mva((void *)vq->va_base, npages * PAGE_SIZE);
    return true;
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
        {"QUEUE_NUM_MAX",  0x02C},   // lisible
        {"QUEUE_NUM",      0x030},   // R/W
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
    
    volatile uint32_t *base = (volatile uint32_t *)base_addr;

    virtio_mmio_dump32(base_addr);

    uint32_t magic   = mmio_read32(base, VIRTIO_MMIO_MAGIC);
    uint32_t version = mmio_read32(base, VIRTIO_MMIO_VERSION);
    uint32_t devid   = mmio_read32(base, VIRTIO_MMIO_DEVICE_ID);

    KDEBUG("virtio-mmio magic 0x%08X @0x%08X\n", magic, base_addr);

    if (magic != 0x74726976) {
        KERROR("virtio-mmio bad magic 0x%08X @0x%08X\n", magic, base_addr);
        return false;
    }

    KDEBUG("VirtIO version = %u\n", version);

    if (devid != 2) {
        KWARN("VirtIO device ID=%u (expected 2=blk), continuing but likely wrong base/DT\n", devid);
    }


    // Reset
    mmio_write32(base, VIRTIO_MMIO_STATUS, 0);

    // ACK + DRIVER
    mmio_write32(base, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_ACK);
    mmio_write32(base, VIRTIO_MMIO_STATUS, mmio_read32(base, VIRTIO_MMIO_STATUS) | VIRTIO_STATUS_DRIVER);


    // FEATURES_OK
    mmio_write32(base, VIRTIO_MMIO_STATUS, mmio_read32(base, VIRTIO_MMIO_STATUS) | VIRTIO_STATUS_FEATURES_OK);
    if (!(mmio_read32(base, VIRTIO_MMIO_STATUS) & VIRTIO_STATUS_FEATURES_OK)) {
        // Le device a rejeté nos features
        mmio_write32(base, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_FAILED);
        return false;
    }

    mmio_write32(base, VIRTIO_REG_GUEST_PAGE_SIZE, PAGE_SIZE);

    // Queue 0
    mmio_write32(base, VIRTIO_MMIO_QUEUE_SEL, 0);
    uint32_t qmax = mmio_read32(base, VIRTIO_MMIO_QUEUE_NUM_MAX);
    if (qmax == 0) return false;

    uint16_t qsize = (VQ_SIZE <= qmax) ? VQ_SIZE : (uint16_t)qmax;
    mmio_write32(base, VIRTIO_MMIO_QUEUE_NUM, qsize);
    mmio_write32(base, VIRTIO_MMIO_QUEUE_ALIGN_OFF, VQ_ALIGN);

    uint32_t align_rb = mmio_read32(base, VIRTIO_MMIO_QUEUE_ALIGN_OFF);
    kprintf("DBG: wrote QUEUE_ALIGN=0x%x readback=0x%x\n", VQ_ALIGN, align_rb);

        /* Setup virtqueue */
    KDEBUG("Setting up virtqueue...\n");
    //if (!setup_virtqueue()) {
    //    KERROR("Failed to setup virtqueue\n");
    //    mmio_write32(base, VIRTIO_MMIO_STATUS,VIRTIO_STATUS_FAILED);
    //    return false;
    //}

    // Allouer le ring legacy
    //vq_legacy_t vq = {0};
    if (!vq_alloc_legacy(&global_vq, qsize)) return false;

    // IMPORTANT: legacy → on programme la PFN (= base_phys >> 12)
    mmio_write32(base, VIRTIO_MMIO_QUEUE_PFN, global_vq.pa_base >> 12);

        /* Enable IRQ */
    KDEBUG("Configuring VirtIO IRQs...\n");
    enable_irq(VIRTIO_BLK_IRQ);
    enable_irq(48);
    enable_irq(79);
    KINFO("VirtIO IRQ %d enabled\n", VIRTIO_BLK_IRQ);

    // DRIVER_OK
    mmio_write32(base, VIRTIO_MMIO_STATUS, mmio_read32(base, VIRTIO_MMIO_STATUS) | VIRTIO_STATUS_DRIVER_OK);

    /* Read device capacity */
    KDEBUG("Reading device capacity...\n");

    uint64_t capacity;
    uint32_t sector_size;

    virtio_blk_read_capacity(base, &capacity, &sector_size);
    //ata_device.capacity = capacity;
    ata_sector_size = sector_size;
    
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

/* simple wait/poll with timeout (ms) */
static int wait_for_used(vq_legacy_t *vq, uint16_t prev_idx, unsigned timeout_ms)
{
    unsigned waited = 0;
    while (vq_used_ptr(vq)->idx == prev_idx) {
            /* Invalidate the used area to see device updates */
        invalidate_dcache_by_mva((void *)(uintptr_t)vq->va_used, vq->used_size);
        asm volatile("dmb ish" ::: "memory");

        task_sleep_ms(1);
        waited++;
        if (waited > timeout_ms) return -1;
        /* invalidation mémoire du used header pour voir les updates */
        invalidate_dcache_by_mva((void *)(uintptr_t)vq->va_used, sizeof(struct vring_used) + vq->qsize * sizeof(struct vring_used_elem));

    }
    return 0;
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
    if (vq->qsize < 3) return -1;

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

    /* flush header/data/status buffers */
    clean_dcache_by_mva(hdr, sizeof(struct virtio_blk_req));
    clean_dcache_by_mva(data_va, data_len);
    clean_dcache_by_mva(status_va, 1);
    asm volatile("dmb ish" ::: "memory");

    /* --- Publier avail entry de façon sûre --- */
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
    uint16_t prev_used = vq->last_used_idx;
    if (wait_for_used(vq, prev_used, timeout_ms) != 0) {
        KERROR("virtio_blk: timeout waiting used ring\n");
        return -1;
    }

    /* read the used element (invalidate used memory then read) */
    invalidate_dcache_by_mva((void *)vq->va_used, sizeof(struct vring_used) + vq->qsize * sizeof(struct vring_used_elem));
    struct vring_used *used = vq_used_ptr(vq);
    uint16_t new_used_idx = used->idx;
    /* find the used element for our id (it should be at (new_used_idx-1) mod qsize) */
    //uint16_t used_pos = (new_used_idx - 1) % vq->qsize;
    //struct vring_used_elem *ue = &used->ring[used_pos];

    /* mark last seen */
    vq->last_used_idx = new_used_idx;

    /* read status */
    invalidate_dcache_by_mva(status_va, 1);
    uint8_t status = *status_va;


    if (status != 0) {
        KERROR("virtio_blk: device returned status=0x%02X\n", status);
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
    (void) timeout_ms;
    uint32_t sector_size = ata_sector_size;
    uint32_t bytes = nsectors * sector_size;
    if (bytes == 0) return -1;

    /* allocation DMA pour header+status (1 page) */
    uint32_t hdr_pa = 0;
    void *hdr_va = alloc_dma_pages(1, &hdr_pa);
    if (!hdr_va) return -1;
    struct virtio_blk_req *hdr = (struct virtio_blk_req *)hdr_va;
    uint8_t *status_va = ((uint8_t*)hdr_va) + 512; /* statut à offset arbitraire dans la page */
    uint32_t status_pa = hdr_pa + 512;

    /* allocation DMA pour data */
    size_t npages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    uint32_t data_pa = 0;
    void *data_va = alloc_dma_pages(npages, &data_pa);
    if (!data_va) return -1;

    /* Fill header */
    hdr->type = VIRTIO_BLK_T_IN;
    hdr->reserved = 0;
    hdr->sector = sector;

    /* sync caches */
    /* data_va need not be filled for read */

    /* submit request (device will fill data_va and status) */
    int r = virtio_blk_submit_one(vq, mmio_base, hdr, hdr_pa, data_va, data_pa, bytes, /*data_is_write=*/1, status_va, status_pa, timeout_ms);
    if (r != 0) {
        return -1;
    }

    /* copy back to user buffer */
    invalidate_dcache_by_mva(data_va, bytes);
    memcpy(buf, data_va, bytes);

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
    (void) timeout_ms;
    uint32_t sector_size = ata_sector_size;
    uint32_t bytes = nsectors * sector_size;
    if (bytes == 0) return -1;

    /* allocation DMA pour header+status (1 page) */
    uint32_t hdr_pa = 0;
    void *hdr_va = alloc_dma_pages(1, &hdr_pa);
    if (!hdr_va) return -1;
    struct virtio_blk_req *hdr = (struct virtio_blk_req *)hdr_va;
    uint8_t *status_va = ((uint8_t*)hdr_va) + 512;
    uint32_t status_pa = hdr_pa + 512;

    /* allocation DMA pour data */
    size_t npages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    uint32_t data_pa = 0;
    void *data_va = alloc_dma_pages(npages, &data_pa);
    if (!data_va) return -1;

    /* copy user data into DMA buffer */
    memcpy(data_va, buf, bytes);

    /* Fill header */
    hdr->type = VIRTIO_BLK_T_OUT;
    hdr->reserved = 0;
    hdr->sector = sector;

    /* submit request (device will read data_va and write status) */
    int r = virtio_blk_submit_one(vq, mmio_base, hdr, hdr_pa, data_va, data_pa, bytes, /*data_is_write=*/0, status_va, status_pa, timeout_ms);
    if (r != 0) {
        return -1;
    }

    return 0;
}

int blk_read_sectors(uint64_t lba, uint32_t count, void* buffer) {

    return virtio_blk_read_sectors( virtio_mmio_base, &global_vq, lba, count, buffer, 1000);
}

int blk_write_sectors(uint64_t lba, uint32_t count, void* buffer) {

    return virtio_blk_write_sectors( virtio_mmio_base, &global_vq, lba, count, buffer, 1000);
}

int blk_read_sector(uint64_t lba, void* buffer) {

    return virtio_blk_read_sectors( virtio_mmio_base, &global_vq, lba, 1, buffer, 1000);
}

int blk_write_sector(uint64_t lba, void* buffer) {

    return virtio_blk_write_sectors( virtio_mmio_base, &global_vq, lba, 1, buffer, 1000);
}

bool blk_is_initialized(void) {
    return ata_sector_size > 0;
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

    int ret = virtio_blk_read_sectors(virtio_mmio_base, &global_vq, /*sector=*/0, /*nsectors=*/1, buf, /*timeout_ms=*/5000);
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
