#ifndef _KERNEL_ATA_H
#define _KERNEL_ATA_H

#include <kernel/types.h>
#include <kernel/kernel.h>
#include <kernel/task.h>

/* VirtIO Block Device - CORRECTION ADRESSE */
//#define VIRTIO_BLK_IRQ      17  /* IRQ 17 pour machine virt */

/* VirtIO registers - CORRECTIONS */
#define VIRTIO_MAGIC        0x000
#define VIRTIO_VERSION      0x004
#define VIRTIO_DEVICE_ID    0x008
#define VIRTIO_VENDOR_ID    0x00C
#define VIRTIO_DEVICE_FEATURES  0x010  /* HOST_FEAT corrige */
#define VIRTIO_GUEST_FEATURES   0x020  /* GUEST_FEAT corrige */
#define VIRTIO_GUEST_PAGE_SIZE  0x028
#define VIRTIO_QUEUE_SEL    0x030
#define VIRTIO_QUEUE_SIZE   0x034
#define VIRTIO_QUEUE_PFN    0x040
#define VIRTIO_QUEUE_NOTIFY 0x050
#define VIRTIO_INTERRUPT_STATUS 0x060  /* AJOUTe */
#define VIRTIO_INTERRUPT_ACK    0x064  /* AJOUTe */
#define VIRTIO_STATUS       0x070

/* Status bits */
//#define VIRTIO_STATUS_ACK       1
//#define VIRTIO_STATUS_DRIVER    2
//#define VIRTIO_STATUS_DRIVER_OK 4
//#define VIRTIO_STATUS_FEATURES_OK  8
//#define VIRTIO_STATUS_FAILED    128

/* Block operations */
#define VIRTIO_BLK_T_IN     0
#define VIRTIO_BLK_T_OUT    1
#define VIRTIO_BLK_S_OK     0
#define VIRTIO_BLK_S_IOERR  1

/* VirtQ descriptor flags */
#define VIRTQ_DESC_F_NEXT     1
#define VIRTQ_DESC_F_WRITE    2

/* ============================================================================
 * STRUCTURES VIRTIO - VERSION CORRIGeE
 * ============================================================================ */

/* 1. VirtIO descriptor */
typedef struct {
    uint64_t addr;                       /* 8 bytes - offset 0 OK */
    uint32_t len;                        /* 4 bytes - offset 8 OK */
    uint16_t flags;                      /* 2 bytes - offset 12 OK */
    uint16_t next;                       /* 2 bytes - offset 14 OK */
} __attribute__((packed)) virtq_desc_t;

/* 2. VirtIO used ring element */
typedef struct {
    uint32_t id;                         /* 4 bytes - offset 0 */
    uint32_t len;                        /* 4 bytes - offset 4 */
} __attribute__((packed)) virtq_used_elem_t;

/* 3. VirtIO available ring structure */
typedef struct {
    uint16_t flags;                      /* 2 bytes - offset 0 */
    uint16_t idx;                        /* 2 bytes - offset 2 */
    /* Le ring suit immediatement apres cette structure */
    /* uint16_t used_event suit le ring */
} __attribute__((packed)) virtq_avail_t;

/* 4. VirtIO used ring structure */
typedef struct {
    uint16_t flags;                      /* 2 bytes - offset 0 */
    uint16_t idx;                        /* 2 bytes - offset 2 */
    /* Le ring suit immediatement apres cette structure */
    /* uint16_t avail_event suit le ring */
} __attribute__((packed)) virtq_used_t;

/* 5. Fonctions d'acces aux rings - VERSION CORRIGeE */
static inline uint16_t* virtq_avail_get_ring(virtq_avail_t* avail)
{
    /* Le ring commence apres flags (2) + idx (2) = 4 bytes */
    return (uint16_t*)((uint8_t*)avail + sizeof(virtq_avail_t));
}

static inline virtq_used_elem_t* virtq_used_get_ring(virtq_used_t* used)
{
    /* Le ring commence apres flags (2) + idx (2) = 4 bytes */
    return (virtq_used_elem_t*)((uint8_t*)used + sizeof(virtq_used_t));
}

/* 6. VirtIO queue structure */
typedef struct {
    /* Pointeurs vers les structures */
    virtq_desc_t* desc;                  /* 4 bytes - offset 0 */
    virtq_avail_t* avail;               /* 4 bytes - offset 4 */
    virtq_used_t* used;                  /* 4 bytes - offset 8 */
    
    uint32_t padding1;                   /* 4 bytes - padding pour alignement */
    
    /* Proprietes de la queue */
    uint16_t queue_size;                 /* 2 bytes - offset 16 */
    uint16_t free_head;                  /* 2 bytes - offset 18 */
    uint16_t num_free;                   /* 2 bytes - offset 20 */
    uint16_t last_used_idx;             /* 2 bytes - offset 22 */
} __attribute__((aligned(8))) virtqueue_t;

/* 7. I/O Request structure */
typedef struct io_request {
    uint64_t lba;                        /* 8 bytes - offset 0 OK */
    uint32_t request_id;                 /* 4 bytes - offset 8 OK */
    uint32_t sector_count;               /* 4 bytes - offset 12 OK */
    void* buffer;                        /* 4 bytes - offset 16 OK */
    int result;                          /* 4 bytes - offset 20 OK */
    task_t* waiting_process;            /* 4 bytes - offset 24 OK */
    struct io_request* next;             /* 4 bytes - offset 28 OK */
    uint16_t virtq_desc_id;             /* 2 bytes - offset 32 OK */
    bool write;                          /* 1 byte  - offset 34 */
    bool completed;                      /* 1 byte  - offset 35 */
    uint8_t padding[4];                  /* 4 bytes - padding pour atteindre 40 bytes */
} __attribute__((aligned(8))) io_request_t;

/* 8. ATA Device structure */
typedef struct {
    /* Champs 8 bytes EN PREMIER */
    uint64_t capacity;                   /* 8 bytes - offset 0 OK */
    
    /* Pointeurs 4 bytes */
    volatile uint32_t* regs;             /* 4 bytes - offset 8 */
    io_request_t* pending_requests;      /* 4 bytes - offset 12 */
    
    /* Champs 4 bytes */
    uint32_t sector_size;                /* 4 bytes - offset 16 */
    uint32_t next_request_id;            /* 4 bytes - offset 20 */
    
    /* Structures alignees */
    virtqueue_t queue;                   /* 24 bytes - offset 24 */
    
    /* Spinlock */
    spinlock_t lock;                     /* 16 bytes - offset 48 */
    
    /* Boolean et padding */
    bool initialized;                    /* 1 byte */
    uint8_t padding[15];                 /* 15 bytes pour aligner sur 32 */
    
    /* Table des requetes a LA FIN */
    io_request_t* desc_to_request[256];  /* 1024 bytes */
} __attribute__((aligned(32))) ata_device_t;

/* ============================================================================
 * MACROS POUR COMPATIBILITe
 * ============================================================================ */

/* Macros pour verifier l'alignement au runtime */
#define CHECK_ALIGNMENT(type, align) \
    static_assert(sizeof(type) % (align) == 0, #type " not properly aligned")

#define VERIFY_STRUCT_ALIGNMENT() do { \
    CHECK_ALIGNMENT(io_request_t, 8); \
    CHECK_ALIGNMENT(virtq_desc_t, 8); \
    CHECK_ALIGNMENT(virtqueue_t, 8); \
    CHECK_ALIGNMENT(ata_device_t, 32); \
} while(0)

/* Macros pour migration plus facile */
#define VIRTQ_USED_RING(used_ptr) virtq_used_get_ring(used_ptr)
#define VIRTQ_AVAIL_RING(avail_ptr) virtq_avail_get_ring(avail_ptr)

/* ============================================================================
 * FONCTIONS PUBLIQUES
 * ============================================================================ */

/* ATA functions principales */
bool init_ata(void);
int ata_read_sectors(uint64_t lba, uint32_t count, void* buffer);
int ata_write_sectors(uint64_t lba, uint32_t count, const void* buffer);
void ata_irq_handler(void);
bool ata_is_initialized(void);
uint64_t ata_get_capacity_sectors(void);
uint32_t ata_get_sector_size(void);
bool ata_is_ready(void);

/* Fonctions pour basculer entre simulation et VirtIO reel */
void ata_set_real_mode(bool enable_real);
void ata_test_both_modes(void);

/* Fonctions de diagnostic et test */
void ata_simple_test(void);  /* NOUVELLE FONCTION SIMPLE */
void virtio_diagnose_device_state(void);
void virtio_comprehensive_test(void);
bool virtio_reconfigure_device(void);

#endif /* _KERNEL_ATA_H */