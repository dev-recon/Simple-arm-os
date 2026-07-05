/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/drivers/virtio_gpu.c
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
#include <kernel/virtio_gpu.h>
#include <kernel/virtio_block.h>
#include <kernel/display.h>
#include <kernel/memory.h>
#include <kernel/string.h>
#include <kernel/kprintf.h>
#include <kernel/timer.h>
#include <kernel/spinlock.h>
#include <kernel/task.h>
#include <asm/arm.h>

#define VIRTIO_ID_GPU 16

#define VIRTIO_GPU_F_VIRGL    0
#define VIRTIO_GPU_F_EDID     1

#define VIRTIO_GPU_CMD_GET_DISPLAY_INFO        0x0100
#define VIRTIO_GPU_CMD_RESOURCE_CREATE_2D      0x0101
#define VIRTIO_GPU_CMD_RESOURCE_UNREF          0x0102
#define VIRTIO_GPU_CMD_SET_SCANOUT             0x0103
#define VIRTIO_GPU_CMD_RESOURCE_FLUSH          0x0104
#define VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D     0x0105
#define VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING 0x0106

#define VIRTIO_GPU_RESP_OK_NODATA              0x1100
#define VIRTIO_GPU_RESP_OK_DISPLAY_INFO        0x1101

#define VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM       1

#define VIRTIO_GPU_RESOURCE_ID                 1
#define VIRTIO_GPU_SCANOUT_ID                  0
#define VIRTIO_GPU_VQ_SIZE                     8
#define VIRTIO_GPU_TIMEOUT_MS                  1000

/* VirtIO MMIO interrupt status bits. */
#define VIRTIO_GPU_INT_USED_RING               0x1u
#define VIRTIO_GPU_INT_CONFIG                  0x2u

typedef struct {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} __attribute__((packed)) virtio_gpu_rect_t;

typedef struct {
    uint32_t type;
    uint32_t flags;
    uint64_t fence_id;
    uint32_t ctx_id;
    uint32_t padding;
} __attribute__((packed)) virtio_gpu_ctrl_hdr_t;

typedef struct {
    virtio_gpu_rect_t r;
    uint32_t enabled;
    uint32_t flags;
} __attribute__((packed)) virtio_gpu_display_one_t;

typedef struct {
    virtio_gpu_ctrl_hdr_t hdr;
    virtio_gpu_display_one_t pmodes[16];
} __attribute__((packed)) virtio_gpu_resp_display_info_t;

typedef struct {
    virtio_gpu_ctrl_hdr_t hdr;
    uint32_t resource_id;
    uint32_t format;
    uint32_t width;
    uint32_t height;
} __attribute__((packed)) virtio_gpu_resource_create_2d_t;

typedef struct {
    virtio_gpu_ctrl_hdr_t hdr;
    virtio_gpu_rect_t r;
    uint32_t scanout_id;
    uint32_t resource_id;
} __attribute__((packed)) virtio_gpu_set_scanout_t;

typedef struct {
    uint64_t addr;
    uint32_t length;
    uint32_t padding;
} __attribute__((packed)) virtio_gpu_mem_entry_t;

typedef struct {
    virtio_gpu_ctrl_hdr_t hdr;
    uint32_t resource_id;
    uint32_t nr_entries;
} __attribute__((packed)) virtio_gpu_resource_attach_backing_t;

typedef struct {
    virtio_gpu_ctrl_hdr_t hdr;
    virtio_gpu_rect_t r;
    uint64_t offset;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed)) virtio_gpu_transfer_to_host_2d_t;

typedef struct {
    virtio_gpu_ctrl_hdr_t hdr;
    virtio_gpu_rect_t r;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed)) virtio_gpu_resource_flush_t;

typedef struct {
    paddr_t phys;
    uint32_t irq;
    volatile uint32_t *mmio;
    vq_legacy_t vq;
    uint16_t next_desc;
    uint32_t framebuffer_size;
    bool initialized;
} virtio_gpu_state_t;

static virtio_gpu_state_t gpu = {0};
static spinlock_t gpu_lock = SPINLOCK_INIT("virtio_gpu");
static volatile bool gpu_busy = false;
static task_t *gpu_owner = NULL;

static struct vring_desc *gpu_desc_ptr(vq_legacy_t *vq, unsigned i)
{
    return (struct vring_desc *)((uint8_t *)(uintptr_t)vq->va_desc +
                                 i * sizeof(struct vring_desc));
}

static struct vring_avail *gpu_avail_ptr(vq_legacy_t *vq)
{
    return (struct vring_avail *)((uint8_t *)(uintptr_t)vq->va_avail);
}

static struct vring_used *gpu_used_ptr(vq_legacy_t *vq)
{
    return (struct vring_used *)((uint8_t *)(uintptr_t)vq->va_used);
}

static void *gpu_alloc_dma_pages(size_t npages, paddr_t *out_pa)
{
    paddr_t pa = (paddr_t)allocate_pages(npages);
    if (!pa)
        return NULL;
    if (out_pa)
        *out_pa = pa;
    return (void *)phys_to_virt(pa);
}

static bool gpu_vq_alloc(vq_legacy_t *vq, uint16_t qsize)
{
    uint32_t desc_sz = 16u * qsize;
    uint32_t avail_sz = ALIGN_UP(6u + 2u * qsize, 2u);
    uint32_t used_sz = ALIGN_UP(6u + 8u * qsize, VQ_ALIGN);
    uint32_t total = ALIGN_UP(desc_sz, 16) +
                     ALIGN_UP(avail_sz, 2) +
                     ALIGN_UP(used_sz, VQ_ALIGN);
    size_t npages = (total + PAGE_SIZE - 1) / PAGE_SIZE;
    paddr_t pa_base = 0;
    uint8_t *va_base = gpu_alloc_dma_pages(npages, &pa_base);
    uint32_t off = 0;

    if (!va_base)
        return false;

    memset(va_base, 0, npages * PAGE_SIZE);

    vq->pa_base = pa_base;
    vq->va_base = (uintptr_t)va_base;

    vq->pa_desc = pa_base + off;
    vq->va_desc = (uintptr_t)(va_base + off);
    vq->desc_size = desc_sz;
    off = ALIGN_UP(off + desc_sz, 16);

    vq->pa_avail = pa_base + off;
    vq->va_avail = (uintptr_t)(va_base + off);
    vq->avail_size = avail_sz;
    off = ALIGN_UP(off + avail_sz, 2);

    off = ALIGN_UP(off, VQ_ALIGN);
    vq->pa_used = pa_base + off;
    vq->va_used = (uintptr_t)(va_base + off);
    vq->used_size = used_sz;
    vq->qsize = qsize;
    vq->last_used_idx = 0;

    clean_dcache_by_mva(va_base, npages * PAGE_SIZE);
    return true;
}

static bool gpu_probe_from_dtb(paddr_t *out_phys, uint32_t *out_irq)
{
    paddr_t phys = 0;
    bool edge = true;

    if (!fdt_find_virtio_mmio_device(VIRTIO_ID_GPU, &phys, out_irq, &edge))
        return false;

    *out_phys = phys;
    return true;
}

static int gpu_wait_used(uint16_t prev_used)
{
    uint32_t freq = get_cntfrq();
    if (freq == 0)
        freq = QEMU_TIMER_FREQ;

    uint64_t timeout_ticks = (uint64_t)VIRTIO_GPU_TIMEOUT_MS * (uint64_t)(freq / 1000);
    uint64_t start = get_cntpct();

    while ((get_cntpct() - start) < timeout_ticks) {
        invalidate_dcache_by_mva((void *)(uintptr_t)gpu.vq.va_used,
            sizeof(struct vring_used) + gpu.vq.qsize * sizeof(struct vring_used_elem));
        asm volatile("dmb ish" ::: "memory");
        if (gpu_used_ptr(&gpu.vq)->idx != prev_used)
            return 0;
        asm volatile("yield" ::: "memory");
    }

    return -1;
}

static int gpu_acquire(void)
{
    while (1) {
        task_t *task = task_current_local();
        unsigned long flags;

        spin_lock_irqsave(&gpu_lock, &flags);
        if (!gpu_busy) {
            gpu_busy = true;
            gpu_owner = task;
            spin_unlock_irqrestore(&gpu_lock, flags);
            return 0;
        }
        if (gpu_owner && task && gpu_owner == task) {
            KERROR("virtio_gpu: recursive command submission by %s\n",
                   task->name);
            spin_unlock_irqrestore(&gpu_lock, flags);
            return -1;
        }
        spin_unlock_irqrestore(&gpu_lock, flags);

        /*
         * The legacy control queue is shared by all console paths.  Under SMP,
         * displayd, tty writes, and boot-time drawing can all request flushes;
         * only one command chain may own next_desc/avail/last_used at a time.
         */
        if (task)
            yield();
        else
            asm volatile("yield" ::: "memory");
    }
}

static void gpu_release(void)
{
    task_t *task = task_current_local();
    unsigned long flags;

    spin_lock_irqsave(&gpu_lock, &flags);
    if (!gpu_busy) {
        KERROR("virtio_gpu: release without owner\n");
    } else if (gpu_owner && task && gpu_owner != task) {
        KERROR("virtio_gpu: release by non-owner\n");
    }
    gpu_busy = false;
    gpu_owner = NULL;
    spin_unlock_irqrestore(&gpu_lock, flags);
}

static int gpu_submit(void *cmd, uint32_t cmd_len, void *resp, uint32_t resp_len)
{
    int ret = -1;

    if (!gpu.initialized || !cmd || cmd_len == 0 || !resp || resp_len == 0)
        return -1;
    if (gpu.vq.qsize < 2)
        return -1;
    if (gpu_acquire() < 0)
        return -1;

    unsigned d0 = gpu.next_desc;
    unsigned d1 = (gpu.next_desc + 1) % gpu.vq.qsize;
    gpu.next_desc = (gpu.next_desc + 2) % gpu.vq.qsize;

    struct vring_desc *desc0 = gpu_desc_ptr(&gpu.vq, d0);
    struct vring_desc *desc1 = gpu_desc_ptr(&gpu.vq, d1);

    memset(resp, 0, resp_len);

    desc0->addr = (uint64_t)virt_to_phys((vaddr_t)cmd);
    desc0->len = cmd_len;
    desc0->flags = VRING_DESC_F_NEXT;
    desc0->next = d1;

    desc1->addr = (uint64_t)virt_to_phys((vaddr_t)resp);
    desc1->len = resp_len;
    desc1->flags = VRING_DESC_F_WRITE;
    desc1->next = 0;

    clean_dcache_by_mva((void *)gpu.vq.va_desc, sizeof(struct vring_desc) * gpu.vq.qsize);
    clean_dcache_by_mva(cmd, cmd_len);
    clean_invalidate_dcache_by_mva(resp, resp_len);
    asm volatile("dmb ish" ::: "memory");

    uint16_t prev_used = gpu.vq.last_used_idx;
    struct vring_avail *avail = gpu_avail_ptr(&gpu.vq);
    uint16_t old_idx = avail->idx;
    avail->ring[old_idx % gpu.vq.qsize] = d0;
    clean_dcache_by_mva((void *)gpu.vq.va_avail, gpu.vq.avail_size);
    asm volatile("dmb ish" ::: "memory");
    avail->idx = old_idx + 1;
    clean_dcache_by_mva(&avail->idx, sizeof(avail->idx));
    asm volatile("dsb ishst" ::: "memory");

    mmio_write32(gpu.mmio, VIRTIO_MMIO_QUEUE_NOTIFY, 0);

    if (gpu_wait_used(prev_used) < 0) {
        KERROR("virtio_gpu: command timeout type=0x%08X\n",
               ((virtio_gpu_ctrl_hdr_t *)cmd)->type);
        goto out;
    }

    struct vring_used *used = gpu_used_ptr(&gpu.vq);
    if ((uint16_t)(used->idx - prev_used) != 1) {
        KERROR("virtio_gpu: unexpected used ring advance\n");
        goto out;
    }
    if (used->ring[prev_used % gpu.vq.qsize].id != d0) {
        KERROR("virtio_gpu: unexpected used descriptor id\n");
        goto out;
    }

    gpu.vq.last_used_idx = used->idx;
    invalidate_dcache_by_mva(resp, resp_len);

    /*
     * Only acknowledge the used-ring bit here. Acking the whole status word
     * would silently consume config-change events (QEMU window resize),
     * which virtio_gpu_check_resize() polls for separately.
     */
    uint32_t irq_status = mmio_read32(gpu.mmio, VIRTIO_MMIO_INTERRUPT_STATUS);
    if (irq_status & VIRTIO_GPU_INT_USED_RING)
        mmio_write32(gpu.mmio, VIRTIO_MMIO_INTERRUPT_ACK, VIRTIO_GPU_INT_USED_RING);
    ret = 0;

out:
    gpu_release();
    return ret;
}

static int gpu_submit_simple(void *cmd, uint32_t cmd_len, const char *name)
{
    virtio_gpu_ctrl_hdr_t resp;

    if (gpu_submit(cmd, cmd_len, &resp, sizeof(resp)) < 0)
        return -1;

    if (resp.type != VIRTIO_GPU_RESP_OK_NODATA) {
        KERROR("virtio_gpu: %s response=0x%08X\n", name, resp.type);
        return -1;
    }

    return 0;
}

static void gpu_fill_hdr(virtio_gpu_ctrl_hdr_t *hdr, uint32_t type)
{
    memset(hdr, 0, sizeof(*hdr));
    hdr->type = type;
}

static int gpu_get_display_info(void)
{
    virtio_gpu_ctrl_hdr_t cmd;
    virtio_gpu_resp_display_info_t resp;

    gpu_fill_hdr(&cmd, VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
    if (gpu_submit(&cmd, sizeof(cmd), &resp, sizeof(resp)) < 0)
        return -1;
    if (resp.hdr.type != VIRTIO_GPU_RESP_OK_DISPLAY_INFO) {
        KERROR("virtio_gpu: display info response=0x%08X\n", resp.hdr.type);
        return -1;
    }

    KINFO("VirtIO GPU scanout0: enabled=%u %ux%u at %u,%u\n",
          resp.pmodes[0].enabled, resp.pmodes[0].r.width,
          resp.pmodes[0].r.height, resp.pmodes[0].r.x,
          resp.pmodes[0].r.y);
    return 0;
}

static int gpu_create_resource(void)
{
    virtio_gpu_resource_create_2d_t cmd;
    gpu_fill_hdr(&cmd.hdr, VIRTIO_GPU_CMD_RESOURCE_CREATE_2D);
    cmd.resource_id = VIRTIO_GPU_RESOURCE_ID;
    cmd.format = VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM;
    cmd.width = FB_WIDTH;
    cmd.height = FB_HEIGHT;
    return gpu_submit_simple(&cmd, sizeof(cmd), "resource_create_2d");
}

static int gpu_attach_backing(void)
{
    struct {
        virtio_gpu_resource_attach_backing_t cmd;
        virtio_gpu_mem_entry_t entry;
    } __attribute__((packed)) req;

    memset(&req, 0, sizeof(req));
    gpu_fill_hdr(&req.cmd.hdr, VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING);
    req.cmd.resource_id = VIRTIO_GPU_RESOURCE_ID;
    req.cmd.nr_entries = 1;
    req.entry.addr = (uint64_t)framebuffer_phys;
    req.entry.length = gpu.framebuffer_size;
    req.entry.padding = 0;

    return gpu_submit_simple(&req, sizeof(req), "resource_attach_backing");
}

static int gpu_set_scanout(void)
{
    virtio_gpu_set_scanout_t cmd;
    gpu_fill_hdr(&cmd.hdr, VIRTIO_GPU_CMD_SET_SCANOUT);
    cmd.r.x = 0;
    cmd.r.y = 0;
    cmd.r.width = FB_WIDTH;
    cmd.r.height = FB_HEIGHT;
    cmd.scanout_id = VIRTIO_GPU_SCANOUT_ID;
    cmd.resource_id = VIRTIO_GPU_RESOURCE_ID;
    return gpu_submit_simple(&cmd, sizeof(cmd), "set_scanout");
}

int virtio_gpu_flush_rect(uint32_t x, uint32_t y, uint32_t width, uint32_t height)
{
    if (!gpu.initialized)
        return -1;

    if (x >= FB_WIDTH || y >= FB_HEIGHT || width == 0 || height == 0)
        return 0;

    if (x + width > FB_WIDTH)
        width = FB_WIDTH - x;
    if (y + height > FB_HEIGHT)
        height = FB_HEIGHT - y;

    for (uint32_t row = 0; row < height; row++) {
        uint8_t *line = framebuffer_base +
            ((y + row) * FB_WIDTH + x) * (FB_BPP / 8);
        clean_dcache_by_mva(line, width * (FB_BPP / 8));
    }

    virtio_gpu_transfer_to_host_2d_t tx;
    gpu_fill_hdr(&tx.hdr, VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D);
    tx.r.x = x;
    tx.r.y = y;
    tx.r.width = width;
    tx.r.height = height;
    tx.offset = ((uint64_t)y * FB_WIDTH + x) * (FB_BPP / 8);
    tx.resource_id = VIRTIO_GPU_RESOURCE_ID;
    tx.padding = 0;
    if (gpu_submit_simple(&tx, sizeof(tx), "transfer_to_host_2d") < 0)
        return -1;

    virtio_gpu_resource_flush_t fl;
    gpu_fill_hdr(&fl.hdr, VIRTIO_GPU_CMD_RESOURCE_FLUSH);
    fl.r.x = x;
    fl.r.y = y;
    fl.r.width = width;
    fl.r.height = height;
    fl.resource_id = VIRTIO_GPU_RESOURCE_ID;
    fl.padding = 0;
    return gpu_submit_simple(&fl, sizeof(fl), "resource_flush");
}

int virtio_gpu_flush(void)
{
    return virtio_gpu_flush_rect(0, 0, FB_WIDTH, FB_HEIGHT);
}

/*
 * Poll and handle a display configuration change (QEMU window resize).
 *
 * The scanout resolution stays fixed at FB_WIDTHxFB_HEIGHT (the host scales
 * the window); what a resize can disturb is the host-side scanout state.
 * Re-asserting the scanout prepares the next full repaint. Must be called from
 * task context (displayd): it submits synchronous GPU commands.
 *
 * Returns true when a config change was seen and handled; the caller should
 * mark the whole framebuffer dirty so the next frame repaints everything.
 */
bool virtio_gpu_check_resize(void)
{
    uint32_t irq_status;

    if (!gpu.initialized)
        return false;

    irq_status = mmio_read32(gpu.mmio, VIRTIO_MMIO_INTERRUPT_STATUS);
    if (!(irq_status & VIRTIO_GPU_INT_CONFIG))
        return false;

    mmio_write32(gpu.mmio, VIRTIO_MMIO_INTERRUPT_ACK, VIRTIO_GPU_INT_CONFIG);

    gpu_get_display_info();
    if (gpu_set_scanout() < 0) {
        KERROR("virtio_gpu: scanout re-assert failed after resize\n");
        return false;
    }

    return true;
}

static void gpu_draw_text_px(uint32_t x, uint32_t y, const char *s,
                             uint32_t fg, uint32_t bg)
{
    while (*s) {
        draw_char(x, y, *s++, fg, bg);
        x += 8;
    }
}

static void gpu_draw_ascii_grid(uint32_t x0, uint32_t y0)
{
    const uint32_t cell_w = 60;
    const uint32_t cell_h = 44;
    const uint32_t dim = 0xFF9AA7B2;
    const uint32_t bg = 0xFF101820;
    static const uint32_t palette[] = {
        0xFFFFFFFF, 0xFFFF5252, 0xFFFFC107, 0xFF4CAF50,
        0xFF00BCD4, 0xFF42A5F5, 0xFF7E57C2, 0xFFFF80AB
    };
    char label[4];

    for (uint32_t ch = 32; ch <= 126; ch++) {
        uint32_t i = ch - 32;
        uint32_t x = x0 + (i % 16) * cell_w;
        uint32_t y = y0 + (i / 16) * cell_h;
        uint32_t fg = palette[i % (sizeof(palette) / sizeof(palette[0]))];

        label[0] = (char)('0' + ((ch / 100) % 10));
        label[1] = (char)('0' + ((ch / 10) % 10));
        label[2] = (char)('0' + (ch % 10));
        label[3] = '\0';

        gpu_draw_text_px(x, y, label, dim, bg);
        draw_char(x + 24, y + 14, (char)ch, fg, bg);
    }
}

void virtio_gpu_draw_test_pattern(void)
{
    if (!framebuffer_base)
        return;

    uint32_t *fb = (uint32_t *)framebuffer_base;
    for (uint32_t y = 0; y < FB_HEIGHT; y++) {
        for (uint32_t x = 0; x < FB_WIDTH; x++) {
            uint8_t r = (uint8_t)((x * 255) / FB_WIDTH);
            uint8_t g = (uint8_t)((y * 255) / FB_HEIGHT);
            uint8_t b = (uint8_t)(((x ^ y) * 255) / (FB_WIDTH > FB_HEIGHT ? FB_WIDTH : FB_HEIGHT));
            fb[y * FB_WIDTH + x] = 0xFF000000u |
                                    ((uint32_t)r << 16) |
                                    ((uint32_t)g << 8) |
                                    b;
        }
    }

    const uint32_t title_fg = 0xFFFFFFFF;
    const uint32_t title_bg = 0xFF263238;
    const uint32_t text_fg = 0xFFE0E0E0;
    const uint32_t text_bg = 0xFF101820;
    const uint32_t green = 0xFF4CAF50;
    const uint32_t amber = 0xFFFFC107;

    gpu_draw_text_px(32, 32, "ArmOS virtio-gpu framebuffer", title_fg, title_bg);
    gpu_draw_text_px(32, 56, "Meslo 12x24 boot test", green, text_bg);
    gpu_draw_text_px(32, 88, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", text_fg, text_bg);
    gpu_draw_text_px(32, 112, "abcdefghijklmnopqrstuvwxyz", text_fg, text_bg);
    gpu_draw_text_px(32, 136, "0123456789  !?.,;:-_+=*/\\|()[]{}<>@#$%^&~", amber, text_bg);
    gpu_draw_text_px(32, 176, "white  red    amber  green  cyan   blue   violet pink", title_fg, text_bg);
    gpu_draw_text_px(32, 200, "The quick brown fox jumps over the lazy dog.", 0xFFFFFFFF, 0xFF263238);
    gpu_draw_text_px(32, 224, "The quick brown fox jumps over the lazy dog.", 0xFFFF5252, text_bg);
    gpu_draw_text_px(32, 248, "The quick brown fox jumps over the lazy dog.", 0xFFFFC107, text_bg);
    gpu_draw_text_px(32, 272, "The quick brown fox jumps over the lazy dog.", 0xFF4CAF50, text_bg);
    gpu_draw_text_px(32, 296, "The quick brown fox jumps over the lazy dog.", 0xFF00BCD4, text_bg);
    gpu_draw_text_px(32, 320, "The quick brown fox jumps over the lazy dog.", 0xFF42A5F5, text_bg);
    gpu_draw_text_px(32, 344, "The quick brown fox jumps over the lazy dog.", 0xFF7E57C2, text_bg);
    gpu_draw_text_px(32, 368, "The quick brown fox jumps over the lazy dog.", 0xFFFF80AB, text_bg);
    gpu_draw_text_px(32, 408, "ASCII 32..126, colored per glyph:", title_fg, text_bg);
    gpu_draw_ascii_grid(32, 440);
}

bool virtio_gpu_is_initialized(void)
{
    return gpu.initialized;
}

bool virtio_gpu_init(void)
{
    paddr_t phys = 0;
    uint32_t irq = 0;

    memset(&gpu, 0, sizeof(gpu));

    if (!framebuffer_base) {
        return false;
    }

    if (!gpu_probe_from_dtb(&phys, &irq)) {
        return false;
    }

    gpu.phys = phys;
    gpu.irq = irq;
    gpu.mmio = (volatile uint32_t *)KERNEL_MMIO_VIRTIO_ADDR(phys);
    gpu.framebuffer_size = FB_WIDTH * FB_HEIGHT * (FB_BPP / 8);

    KINFO("VirtIO GPU found: phys=0x%08X mmio=%p irq=%u\n",
          gpu.phys, gpu.mmio, gpu.irq);

    uint32_t magic = mmio_read32(gpu.mmio, VIRTIO_MMIO_MAGIC);
    uint32_t version = mmio_read32(gpu.mmio, VIRTIO_MMIO_VERSION);
    uint32_t devid = mmio_read32(gpu.mmio, VIRTIO_MMIO_DEVICE_ID);
    if (magic != 0x74726976 || version != 1 || devid != VIRTIO_ID_GPU) {
        KERROR("virtio_gpu: bad device magic=0x%08X version=%u id=%u\n",
               magic, version, devid);
        return false;
    }

    mmio_write32(gpu.mmio, VIRTIO_MMIO_STATUS, 0);
    mmio_write32(gpu.mmio, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_ACK);
    mmio_write32(gpu.mmio, VIRTIO_MMIO_STATUS,
                 mmio_read32(gpu.mmio, VIRTIO_MMIO_STATUS) | VIRTIO_STATUS_DRIVER);
    mmio_write32(gpu.mmio, VIRTIO_MMIO_DRIVER_FEATURES, 0);
    mmio_write32(gpu.mmio, VIRTIO_MMIO_STATUS,
                 mmio_read32(gpu.mmio, VIRTIO_MMIO_STATUS) | VIRTIO_STATUS_FEATURES_OK);
    if (!(mmio_read32(gpu.mmio, VIRTIO_MMIO_STATUS) & VIRTIO_STATUS_FEATURES_OK)) {
        KERROR("virtio_gpu: features rejected\n");
        return false;
    }

    mmio_write32(gpu.mmio, VIRTIO_REG_GUEST_PAGE_SIZE, PAGE_SIZE);
    mmio_write32(gpu.mmio, VIRTIO_MMIO_QUEUE_SEL, 0);
    uint32_t qmax = mmio_read32(gpu.mmio, VIRTIO_MMIO_QUEUE_NUM_MAX);
    if (qmax < 2) {
        KERROR("virtio_gpu: control queue unavailable\n");
        return false;
    }
    uint16_t qsize = VIRTIO_GPU_VQ_SIZE <= qmax ? VIRTIO_GPU_VQ_SIZE : (uint16_t)qmax;
    mmio_write32(gpu.mmio, VIRTIO_MMIO_QUEUE_NUM, qsize);
    mmio_write32(gpu.mmio, VIRTIO_MMIO_QUEUE_ALIGN_OFF, VQ_ALIGN);

    if (!gpu_vq_alloc(&gpu.vq, qsize)) {
        KERROR("virtio_gpu: virtqueue allocation failed\n");
        return false;
    }
    mmio_write32(gpu.mmio, VIRTIO_MMIO_QUEUE_PFN, gpu.vq.pa_base >> 12);

    gpu.initialized = true;
    mmio_write32(gpu.mmio, VIRTIO_MMIO_STATUS,
                 mmio_read32(gpu.mmio, VIRTIO_MMIO_STATUS) | VIRTIO_STATUS_DRIVER_OK);

    gpu_get_display_info();
    if (gpu_create_resource() < 0 ||
        gpu_attach_backing() < 0 ||
        gpu_set_scanout() < 0) {
        gpu.initialized = false;
        mmio_write32(gpu.mmio, VIRTIO_MMIO_STATUS,
                     mmio_read32(gpu.mmio, VIRTIO_MMIO_STATUS) | VIRTIO_STATUS_FAILED);
        return false;
    }

    clear_screen();
    if (virtio_gpu_flush() < 0) {
        KWARN("VirtIO GPU initialized but initial flush failed\n");
        return false;
    }

    KINFO("VirtIO GPU initialized: %ux%ux%u\n", FB_WIDTH, FB_HEIGHT, FB_BPP);
    return true;
}
