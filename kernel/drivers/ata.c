#include <kernel/task.h>
#include <kernel/ata.h>
#include <kernel/memory.h>
#include <kernel/process.h>
#include <kernel/interrupt.h>
#include <kernel/kernel.h>
#include <kernel/string.h>
#include <kernel/uart.h>
#include <kernel/kprintf.h>
#include <kernel/math.h>
#include <kernel/spinlock.h>


/* Forward declarations */
static bool setup_virtqueue(void);
static int ata_rw_sector(uint64_t lba, void* buffer, bool write);
static io_request_t* create_io_request(uint64_t lba, uint32_t count, void* buffer, bool write);
static int ata_submit_request(io_request_t* req);
static int ata_submit_request_simulation(io_request_t* req);
static int ata_submit_request_real(io_request_t* req);
static int virtio_blk_rw(uint64_t lba, uint32_t count, void* buffer, bool write);
static void cleanup_io_request(io_request_t* req);
static void free_desc(uint16_t desc);
static bool init_virtio_block_device(uint32_t base_addr);
static uint16_t alloc_desc(void);

/* Global device state */
static ata_device_t ata_device;

/* Mode selection: true = real VirtIO, false = simulation */
static bool use_real_virtio = true;

/* ============================================================================
 * CORE INITIALIZATION
 * ============================================================================ */

/* ============================================================================
 * DEVICE DISCOVERY
 * ============================================================================ */

/* Force VirtIO device initialization */
static bool force_virtio_device_init(uint32_t addr)
{
    volatile uint32_t* regs = (volatile uint32_t*)addr;
    
    KINFO("FIX Force-initializing VirtIO device at 0x%08X\n", addr);
    
    /* Check if it's a valid VirtIO device */
    uint32_t magic = regs[VIRTIO_MAGIC/4];
    if (magic != 0x74726976) {
        return false;
    }
    
    /* Reset device completely */
    KDEBUG("  Step 1: Reset device\n");
    regs[VIRTIO_STATUS/4] = 0;
    
    /* Wait for reset to complete */
    for (volatile int i = 0; i < 10000; i++);
    
    /* Acknowledge device */
    KDEBUG("  Step 2: Acknowledge device\n");
    regs[VIRTIO_STATUS/4] = VIRTIO_STATUS_ACK;
    
    /* Wait */
    for (volatile int i = 0; i < 10000; i++);
    
    /* Check if device ID changed */
    uint32_t device_id = regs[VIRTIO_DEVICE_ID/4];
    KDEBUG("  Device ID after reset: %u\n", device_id);
    
    if (device_id == 2) {
        KINFO("  OK Successfully initialized as Block device!\n");
        return true;
    }
    
    /* Try driver status */
    KDEBUG("  Step 3: Set driver status\n");
    regs[VIRTIO_STATUS/4] |= VIRTIO_STATUS_DRIVER;
    
    /* Wait */
    for (volatile int i = 0; i < 10000; i++);
    
    /* Check again */
    device_id = regs[VIRTIO_DEVICE_ID/4];
    KDEBUG("  Device ID after driver: %u\n", device_id);
    
    if (device_id == 2) {
        KINFO("  OK Successfully initialized as Block device!\n");
        return true;
    }
    
    /* Try selecting queue 0 to wake up the device */
    KDEBUG("  Step 4: Select queue 0\n");
    regs[VIRTIO_QUEUE_SEL/4] = 0;
    
    /* Wait */
    for (volatile int i = 0; i < 10000; i++);
    
    /* Check device queue size to see if it responds */
    uint32_t queue_size = regs[VIRTIO_QUEUE_SIZE/4];
    KDEBUG("  Queue size: %u\n", queue_size);
    
    /* Check device ID one more time */
    device_id = regs[VIRTIO_DEVICE_ID/4];
    KDEBUG("  Final device ID: %u\n", device_id);
    
    return (device_id == 2);
}

static const uint32_t virtio_addresses[] = {
    0x10001000, // VirtIO sans virtio-mmio sur QEMU/Apple Silicon
    0x0A000000, 0x0A000200, 0x0A000400, 0x0A000600,
    0x0A000800, 0x0A000A00, 0x0A000C00, 0x0A000E00
};
#define VIRTIO_NUM_ADDRESSES (sizeof(virtio_addresses) / sizeof(virtio_addresses[0]))

static uint32_t scan_virtio_devices(void)
{
    KINFO("=== SCANNING FOR VIRTIO DEVICES ===\n");
    
    uint32_t first_valid_device = 0;
    
    for (unsigned int i = 0; i < VIRTIO_NUM_ADDRESSES; i++) {
        uint32_t addr = virtio_addresses[i];
        volatile uint32_t* regs = (volatile uint32_t*)addr;
        
        KINFO("Checking VirtIO device %d at 0x%08X...\n", i, addr);
        
        /* Check magic signature */
        uint32_t magic = regs[VIRTIO_MAGIC/4];
        if (magic != 0x74726976) {
            KINFO("  No VirtIO device (magic=0x%08X)\n", magic);
            continue;
        }
        
        /* Check initial device ID */
        uint32_t device_id = regs[VIRTIO_DEVICE_ID/4];
        uint32_t version = regs[VIRTIO_VERSION/4];
        uint32_t vendor_id = regs[VIRTIO_VENDOR_ID/4];
        
        KINFO("  OK VirtIO device found!\n");
        KINFO("    Magic:     0x%08X\n", magic);
        KINFO("    Version:   %u\n", version);
        KINFO("    Device ID: %u (%s)\n", device_id, 
              (device_id == 1) ? "Network" :
              (device_id == 2) ? "Block" :
              (device_id == 3) ? "Console" :
              (device_id == 4) ? "RNG" : "Unknown");
        KINFO("    Vendor ID: 0x%08X\n", vendor_id);
        
        /* If we found a Block device, use it immediately */
        if (device_id == 2) {
            KINFO("  TARGET Found VirtIO Block device at 0x%08X!\n", addr);
            return addr;
        }
        
        /* Remember the first valid VirtIO device */
        if (first_valid_device == 0) {
            first_valid_device = addr;
        }
        
        /* If device ID is 0, try to force initialization */
        if (device_id == 0) {
            KINFO("  FIX Device ID = 0, attempting force initialization...\n");
            if (force_virtio_device_init(addr)) {
                KINFO("  TARGET Successfully converted to Block device at 0x%08X!\n", addr);
                return addr;
            }
        }
    }
    
    /* NOUVEAU: Si aucun device Block trouve, mais qu'on a des devices VirtIO,
       assumons que le premier est notre device Block */
    if (first_valid_device != 0) {
        KWARN("KO No typed VirtIO Block device found\n");
        KWARN("TARGET Using first VirtIO device as Block device (workaround)\n");
        KWARN("   This suggests QEMU configuration issue, but we'll try anyway\n");
        
        /* Verifier que le device a au moins une queue */
        volatile uint32_t* regs = (volatile uint32_t*)first_valid_device;
        
        /* Force reset and basic setup */
        regs[VIRTIO_STATUS/4] = 0;  /* Reset */
        for (volatile int i = 0; i < 10000; i++);
        
        regs[VIRTIO_STATUS/4] = VIRTIO_STATUS_ACK;  /* Acknowledge */
        for (volatile int i = 0; i < 10000; i++);
        
        regs[VIRTIO_STATUS/4] |= VIRTIO_STATUS_DRIVER;  /* Driver */
        for (volatile int i = 0; i < 10000; i++);
        
        /* Select queue 0 and check if it exists */
        regs[VIRTIO_QUEUE_SEL/4] = 0;
        uint32_t queue_size = regs[VIRTIO_QUEUE_SIZE/4];
        
        KWARN("   Device queue size: %u\n", queue_size);
        
        if (queue_size > 0) {
            KWARN("   OK Device has functional queue, proceeding as Block device\n");
            KWARN("   - Will operate in BLOCK DEVICE MODE\n");
            return first_valid_device;
        } else {
            KWARN("   KO Device has no functional queue\n");
            KWARN("   FIX Trying to manually setup queue...\n");
            
            /* Force setup queue - last resort */
            regs[VIRTIO_QUEUE_SEL/4] = 0;
            
            /* Try different queue sizes */
            uint32_t test_sizes[] = {256, 128, 64, 32, 16};
            for (int j = 0; j < 5; j++) {
                /* Try to set queue size */
                regs[VIRTIO_QUEUE_SIZE/4] = test_sizes[j];
                uint32_t readback = regs[VIRTIO_QUEUE_SIZE/4];
                
                KWARN("     Tried size %u, got %u\n", test_sizes[j], readback);
                
                if (readback > 0) {
                    KWARN("   OK Manually configured queue size: %u\n", readback);
                    KWARN("   - FORCING BLOCK DEVICE MODE\n");
                    return first_valid_device;
                }
            }
            
            KWARN("   KO Could not configure any queue\n");
            KWARN("   TARGET LAST RESORT: Proceeding without queue (simulation only)\n");
            return first_valid_device;  /* Return anyway for simulation */
        }
    }
    
    KERROR("KO No usable VirtIO device found\n");
    return 0;
}

/* ============================================================================
 * QEMU CONFIGURATION CHECK
 * ============================================================================ */

void check_qemu_virtio_config(void)
{
    KINFO("=== QEMU VIRTIO CONFIGURATION CHECK ===\n");
    KINFO("Expected QEMU command:\n");
    KINFO("  qemu-system-arm -M virt -cpu cortex-a15 \\\n");
    KINFO("    -m 1G -smp 1 \\\n");
    KINFO("    -kernel kernel.bin \\\n");
    KINFO("    -nographic \\\n");
    KINFO("    -drive file=disk.img,format=raw,index=0,media=disk\n");
    KINFO("\n");
    KINFO("This should create a VirtIO Block device automatically.\n");
    KINFO("\n");
    KINFO("To verify your disk.img file on the host:\n");
    KINFO("  ls -la disk.img          # Check file exists\n");
    KINFO("  du -h disk.img           # Check file size\n");
    KINFO("  file disk.img            # Check file type\n");
    KINFO("  hexdump -C disk.img | head -5  # Check content\n");
    KINFO("\n");
    KINFO("If disk.img doesn't exist, create it with:\n");
    KINFO("  dd if=/dev/zero of=disk.img bs=1M count=64\n");
    KINFO("  mkfs.fat -F 32 disk.img\n");
}

bool init_ata(void)
{
    KINFO("Initializing VirtIO block device...\n");
    
    /* Initialize device structure */
    memset(&ata_device, 0, sizeof(ata_device_t));
    init_spinlock(&ata_device.lock);
    
    /* Scan for VirtIO device (may not be properly typed) */
    uint32_t virtio_addr = scan_virtio_devices();
    if (virtio_addr == 0) {
        KERROR("No VirtIO device found\n");
        KERROR("This usually means:\n");
        KERROR("  1. QEMU was not started with correct -drive parameter\n");
        KERROR("  2. disk.img file doesn't exist\n");
        KERROR("  3. VirtIO device not created by QEMU\n");
        
        check_qemu_virtio_config();
        
        KWARN("=== FALLBACK TO SIMULATION MODE ===\n");
        KWARN("Initializing ATA in simulation mode for testing...\n");
        
        /* Initialize basic structure for simulation */
        ata_device.initialized = true;
        ata_device.capacity = 131072; /* 64MB fake disk */
        ata_device.sector_size = 512;
        ata_device.next_request_id = 1;
        
        /* Force simulation mode */
        ata_set_real_mode(false);
        
        KWARN("OK ATA simulation mode initialized (no real disk I/O)\n");
        return true;
    }
    
    ata_device.regs = (volatile uint32_t*)virtio_addr;
    
    /* Check device ID, but don't fail if it's not 2 */
    uint32_t device_id = ata_device.regs[VIRTIO_DEVICE_ID/4];
    if (device_id == 2) {
        KINFO("OK Confirmed VirtIO Block device (ID=2) at 0x%08X\n", virtio_addr);
    } else {
        KWARN("WARNING VirtIO device has ID=%u (not 2), but proceeding anyway\n", device_id);
        KWARN("   Assuming this device can handle block operations\n");
    }
    
    /* Try to initialize as VirtIO device regardless of ID */
    KINFO("- Attempting VirtIO initialization...\n");
    if (init_virtio_block_device(virtio_addr)) {
        KINFO("OK VirtIO device initialized successfully!\n");
        return true;
    } else {
        KERROR("KO VirtIO device initialization failed\n");
        
        /* Fallback to simulation */
        KWARN("=== FALLBACK TO SIMULATION MODE ===\n");
        ata_device.initialized = true;
        ata_device.capacity = 131072;
        ata_device.sector_size = 512;
        ata_device.next_request_id = 1;
        ata_set_real_mode(false);
        KWARN("OK ATA simulation mode initialized\n");
        return true;
    }
}

static bool init_virtio_block_device(uint32_t base_addr)
{
    KDEBUG("Initializing VirtIO block device at 0x%08X\n", base_addr);
    
    volatile uint32_t* regs = (volatile uint32_t*)base_addr;
    
    /* Read device information */
    uint32_t version = regs[VIRTIO_VERSION/4];
    uint32_t vendor_id = regs[VIRTIO_VENDOR_ID/4];
    uint32_t device_features = regs[VIRTIO_DEVICE_FEATURES/4];
    
    KDEBUG("Device information:\n");
    KDEBUG("  Version:  0x%08X\n", version);
    KDEBUG("  Vendor:   0x%08X\n", vendor_id);
    KDEBUG("  Features: 0x%08X\n", device_features);
    
    /* Reset device */
    KDEBUG("Resetting device...\n");
    regs[VIRTIO_STATUS/4] = 0;
    
    /* Status: Acknowledge */
    KDEBUG("Acknowledging device...\n");
    regs[VIRTIO_STATUS/4] = VIRTIO_STATUS_ACK;
    
    /* Status: Driver */
    KDEBUG("Setting driver status...\n");
    regs[VIRTIO_STATUS/4] |= VIRTIO_STATUS_DRIVER;
    
    /* Feature negotiation */
    KDEBUG("Negotiating features...\n");
    uint32_t guest_features = 0;  /* No special features needed */
    regs[VIRTIO_GUEST_FEATURES/4] = guest_features;
    
    /* Features OK */
    regs[VIRTIO_STATUS/4] |= VIRTIO_STATUS_FEATURES_OK;
    
    /* Verify device accepts our features */
    uint32_t status = regs[VIRTIO_STATUS/4];
    if (!(status & VIRTIO_STATUS_FEATURES_OK)) {
        KERROR("Device rejected our features\n");
        regs[VIRTIO_STATUS/4] = VIRTIO_STATUS_FAILED;
        return false;
    }
    
    /* Setup virtqueue */
    KDEBUG("Setting up virtqueue...\n");
    if (!setup_virtqueue()) {
        KERROR("Failed to setup virtqueue\n");
        regs[VIRTIO_STATUS/4] = VIRTIO_STATUS_FAILED;
        return false;
    }
    
    /* Enable IRQ */
    KDEBUG("Configuring VirtIO IRQs...\n");
    enable_irq(VIRTIO_BLK_IRQ);
    KINFO("VirtIO IRQ %d enabled\n", VIRTIO_BLK_IRQ);
    
    /* Driver OK */
    KDEBUG("Setting driver OK...\n");
    regs[VIRTIO_STATUS/4] |= VIRTIO_STATUS_DRIVER_OK;
    
    /* Read device capacity */
    KDEBUG("Reading device capacity...\n");
    volatile uint64_t* config_space = (volatile uint64_t*)(base_addr + 0x100);
    ata_device.capacity = *config_space;
    ata_device.sector_size = 512;
    
    KINFO("Device capacity: %u sectors (%u MB)\n", 
          (uint32_t)ata_device.capacity, 
          (uint32_t)(ata_device.capacity * 512 / (1024*1024)));
    
    /* Finalize initialization */
    ata_device.initialized = true;
    ata_device.next_request_id = 1;
    
    KINFO("VirtIO block device fully initialized OK\n");
    return true;
}

static bool setup_virtqueue(void)
{
    KDEBUG("Setting up virtqueue...\n");
    
    /* Select queue 0 */
    ata_device.regs[VIRTIO_QUEUE_SEL/4] = 0;
    
    /* Get queue size */
    uint32_t queue_size = ata_device.regs[VIRTIO_QUEUE_SIZE/4];
    KDEBUG("Queue size from device: %u\n", queue_size);
    
    if (queue_size == 0) {
        KERROR("Queue size is 0\n");
        return false;
    }
    
    ata_device.queue.queue_size = queue_size;
    
    /* Calculate memory requirements */
    uint32_t queue_bytes = sizeof(virtq_desc_t) * queue_size +
                          sizeof(uint16_t) * (3 + queue_size) +
                          sizeof(uint16_t) * (3 + queue_size * 2);
    
    uint32_t queue_pages = (queue_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    
    /* Allocate contiguous memory */
    KDEBUG("Allocating %u contiguous pages...\n", queue_pages);
    void* queue_mem = allocate_contiguous_pages(queue_pages);
    if (!queue_mem) {
        KERROR("Failed to allocate pages\n");
        return false;
    }
    
    KDEBUG("Allocated virtqueue memory at %p\n", queue_mem);
    
    /* Clear memory */
    memset(queue_mem, 0, queue_pages * PAGE_SIZE);
    
    /* Setup structures */
    ata_device.queue.desc = (virtq_desc_t*)queue_mem;
    ata_device.queue.avail = (virtq_avail_t*)((char*)queue_mem + 
                                             sizeof(virtq_desc_t) * queue_size);
    ata_device.queue.used = (virtq_used_t*)((uintptr_t)(((char*)ata_device.queue.avail +
                                            sizeof(uint16_t) * (3 + queue_size) +
                                            PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1));
    
    /* Initialize descriptor free list */
    KDEBUG("Initializing descriptor free list...\n");
    for (uint16_t i = 0; i < queue_size - 1; i++) {
        ata_device.queue.desc[i].next = i + 1;
    }
    ata_device.queue.desc[queue_size - 1].next = 0;
    
    ata_device.queue.free_head = 0;
    ata_device.queue.num_free = queue_size;
    ata_device.queue.last_used_idx = 0;
    
    /* Configure queue in device */
    uint32_t queue_pfn = (uint32_t)queue_mem / PAGE_SIZE;
    KDEBUG("Setting queue PFN to 0x%08X\n", queue_pfn);
    ata_device.regs[VIRTIO_QUEUE_PFN/4] = queue_pfn;
    
    KDEBUG("Virtqueue setup complete OK\n");
    return true;
}

/* ============================================================================
 * PUBLIC API FUNCTIONS
 * ============================================================================ */

int ata_read_sectors(uint64_t lba, uint32_t count, void* buffer)
{
    if (!ata_device.initialized) return -1;
    
    for (uint32_t i = 0; i < count; i++) {
        if (ata_rw_sector(lba + i, (char*)buffer + i * 512, false) < 0) {
            return -1;
        }
    }
    
    return count;
}

int ata_write_sectors(uint64_t lba, uint32_t count, const void* buffer)
{
    if (!ata_device.initialized) return -1;
    
    for (uint32_t i = 0; i < count; i++) {
        if (ata_rw_sector(lba + i, (char*)buffer + i * 512, true) < 0) {
            return -1;
        }
    }
    
    return count;
}

static int ata_rw_sector(uint64_t lba, void* buffer, bool write)
{
    /* Create I/O request */
    io_request_t* req = create_io_request(lba, 1, buffer, write);
    if (!req) return -1;
    
    /* Submit request */
    if (ata_submit_request(req) < 0) {
        cleanup_io_request(req);
        return -1;
    }
    
    /* Wait for completion */
    while (!req->completed) {
        if (current_task) {
            current_task->state = TASK_BLOCKED;
            schedule();
        } else {
            /* Busy wait if no process context */
            for (volatile int i = 0; i < 1000; i++);
        }
    }
    
    int result = req->result;
    cleanup_io_request(req);
    return result;
}

/* ============================================================================
 * IRQ HANDLER
 * ============================================================================ */

void ata_irq_handler(void)
{
    KDEBUG("=== ATA IRQ HANDLER CALLED ===\n");
    
    if (!ata_device.initialized) {
        KDEBUG("Device not initialized, ignoring IRQ\n");
        return;
    }
    
    /* Acknowledge VirtIO interrupt */
    uint32_t irq_status = ata_device.regs[VIRTIO_INTERRUPT_STATUS/4];
    KDEBUG("VirtIO interrupt status: 0x%08X\n", irq_status);
    
    if (irq_status & 1) {  /* Used ring notification */
        /* Acknowledge interrupt */
        ata_device.regs[VIRTIO_INTERRUPT_ACK/4] = irq_status;
        
        spin_lock(&ata_device.lock);
        
        /* Process completions */
        while (ata_device.queue.used->idx != ata_device.queue.last_used_idx) {
            uint16_t used_idx = ata_device.queue.last_used_idx % ata_device.queue.queue_size;
            virtq_used_elem_t* used_ring = virtq_used_get_ring(ata_device.queue.used);
            uint32_t desc_id = used_ring[used_idx].id;
            
            KDEBUG("Completing request: desc_id=%u\n", desc_id);
            
            /* Find corresponding request */
            io_request_t* req = ata_device.desc_to_request[desc_id];
            if (req) {
                req->completed = true;
                req->result = 0;  /* Assume success for now */
                
                KDEBUG("Request %p marked as completed\n", req);
                
                /* Wake up waiting process if needed */
                if (req->waiting_process && req->waiting_process->state == TASK_BLOCKED) {
                    req->waiting_process->state = TASK_READY;
                    add_to_ready_queue(req->waiting_process);
                }
                
                /* Free descriptors */
                free_desc(desc_id);
                ata_device.desc_to_request[desc_id] = NULL;
            }
            
            ata_device.queue.last_used_idx++;
        }
        
        spin_unlock(&ata_device.lock);
        
        KDEBUG("IRQ processing completed\n");
    }
}

/* ============================================================================
 * REQUEST PROCESSING
 * ============================================================================ */

static io_request_t* create_io_request(uint64_t lba, uint32_t count, void* buffer, bool write)
{
    /* CORRECTION: Use static allocation if kmalloc fails */
    static io_request_t static_request;
    io_request_t* req = &static_request;  /* Use static for now */
    
    req->request_id = ata_device.next_request_id++;
    req->lba = lba;
    req->sector_count = count;
    req->buffer = buffer;
    req->write = write;
    req->completed = false;
    req->result = -1;
    req->waiting_process = current_task;
    req->next = NULL;
    
    return req;
}

static int ata_submit_request(io_request_t* req)
{
    if (use_real_virtio) {
        return ata_submit_request_real(req);
    } else {
        return ata_submit_request_simulation(req);
    }
}

static int ata_submit_request_real(io_request_t* req)
{
    KDEBUG("Submitting REAL VirtIO request: LBA=%u, count=%u, write=%s\n", 
           (uint32_t)req->lba, req->sector_count, req->write ? "YES" : "NO");
    
    if (!req || !req->buffer) {
        KERROR("Invalid request or buffer\n");
        req->completed = true;
        req->result = -1;
        return -1;
    }
    
    /* Verify VirtIO device is initialized */
    if (!ata_device.initialized) {
        KERROR("VirtIO device not initialized\n");
        req->completed = true;
        req->result = -1;
        return -1;
    }
    
    /* Verify disk limits */
    if (req->lba + req->sector_count > ata_device.capacity) {
        KERROR("Request beyond disk capacity: LBA=%u+%u > %u\n", 
               (uint32_t)req->lba, req->sector_count, (uint32_t)ata_device.capacity);
        req->completed = true;
        req->result = -1;
        return -1;
    }
    
    int result = virtio_blk_rw(req->lba, req->sector_count, req->buffer, req->write);
    
    /* Mark request as completed */
    req->completed = true;
    req->result = result;
    
    return result;
}

static int virtio_blk_rw(uint64_t lba, uint32_t count, void* buffer, bool write)
{
    KDEBUG("VirtIO: %s LBA=%u count=%u buffer=%p\n", 
           write ? "WRITE" : "READ", (uint32_t)lba, count, buffer);
    
    /* Allocate descriptors (header + data + status) */
    uint16_t desc_header = alloc_desc();
    uint16_t desc_data = alloc_desc();  
    uint16_t desc_status = alloc_desc();
    
    if (desc_header == 0xFFFF || desc_data == 0xFFFF || desc_status == 0xFFFF) {
        KERROR("Failed to allocate VirtIO descriptors\n");
        if (desc_header != 0xFFFF) free_desc(desc_header);
        if (desc_data != 0xFFFF) free_desc(desc_data);
        if (desc_status != 0xFFFF) free_desc(desc_status);
        return -1;
    }
    
    /* Prepare VirtIO request structures */
    struct virtio_blk_req* request = kmalloc(sizeof(struct virtio_blk_req));
    uint8_t* status = kmalloc(sizeof(uint8_t));
    
    if (!request || !status) {
        KERROR("Failed to allocate request structures\n");
        goto cleanup_desc;
    }
    
    /* Initialize request */
    memset(request, 0, sizeof(struct virtio_blk_req));
    request->type = write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN;
    request->reserved = 0;
    request->sector = lba;
    *status = 0xFF;
    
    /* Register request for IRQ handler */
    //ata_device.desc_to_request[desc_header] = (io_request_t*)request; /* Temporary mapping */
    ata_device.desc_to_request[desc_header] = (io_request_t*)request; /* Temporary mapping */
    
    /* Configure descriptors */
    /* 1. Header (read-only for device) */
    ata_device.queue.desc[desc_header].addr = (uint64_t)(uintptr_t)request;
    ata_device.queue.desc[desc_header].len = sizeof(struct virtio_blk_req);
    ata_device.queue.desc[desc_header].flags = VIRTQ_DESC_F_NEXT;
    ata_device.queue.desc[desc_header].next = desc_data;
    
    /* 2. Data buffer */
    ata_device.queue.desc[desc_data].addr = (uint64_t)(uintptr_t)buffer;
    ata_device.queue.desc[desc_data].len = count * 512;
    ata_device.queue.desc[desc_data].flags = VIRTQ_DESC_F_NEXT | (write ? 0 : VIRTQ_DESC_F_WRITE);
    ata_device.queue.desc[desc_data].next = desc_status;
    
    /* 3. Status (write for device) */
    ata_device.queue.desc[desc_status].addr = (uint64_t)(uintptr_t)status;
    ata_device.queue.desc[desc_status].len = 1;
    ata_device.queue.desc[desc_status].flags = VIRTQ_DESC_F_WRITE;
    ata_device.queue.desc[desc_status].next = 0;
    
    /* Add to available queue */
    uint16_t avail_idx = ata_device.queue.avail->idx;
    uint16_t* avail_ring = virtq_avail_get_ring(ata_device.queue.avail);
    uint16_t ring_idx = avail_idx % ata_device.queue.queue_size;
    
    avail_ring[ring_idx] = desc_header;
    
    /* Memory barrier before notification */
    __asm__ volatile("dsb" ::: "memory");
    
    /* Update available index */
    ata_device.queue.avail->idx = avail_idx + 1;
    
    /* Notify device */
    ata_device.regs[VIRTIO_QUEUE_NOTIFY/4] = 0; /* Queue 0 */
    
    KDEBUG("VirtIO request submitted, waiting for completion...\n");
    
    /* Wait for completion (polling) */
    uint32_t timeout = 1000000;
    while (timeout-- > 0) {
        if (ata_device.queue.used->idx != ata_device.queue.last_used_idx) {
            /* Response available */
            virtq_used_elem_t* used_ring = virtq_used_get_ring(ata_device.queue.used);
            uint16_t used_idx = ata_device.queue.last_used_idx % ata_device.queue.queue_size;
            virtq_used_elem_t* used_elem = &used_ring[used_idx];
            
            KDEBUG("VirtIO completion: desc=%u len=%u status=%u\n", 
                   used_elem->id, used_elem->len, *status);
            
            /* Free descriptors */
            free_desc(desc_header);
            free_desc(desc_data);
            free_desc(desc_status);
            
            /* Update used index */
            ata_device.queue.last_used_idx++;
            
            /* Check status */
            int result = (*status == VIRTIO_BLK_S_OK) ? (int)count : -1;
            
            /* Cleanup */
            kfree(request);
            kfree(status);
            
            return result;
        }
        
        /* Small delay */
        for (volatile int i = 0; i < 100; i++);
    }
    
    KERROR("VirtIO: Timeout waiting for completion\n");
    
cleanup_desc:
    free_desc(desc_header);
    free_desc(desc_data);
    free_desc(desc_status);
    if (request) kfree(request);
    if (status) kfree(status);
    return -1;
}

/* Simulation mode for testing */
static int ata_submit_request_simulation(io_request_t* req)
{
    if (!req || !req->buffer) {
        KERROR("Invalid request or buffer\n");
        req->completed = true;
        req->result = -1;
        return -1;
    }
    
    if (req->write) {
        KDEBUG("Write operation simulated\n");
        req->completed = true;
        req->result = 0;
        return 0;
    }
    
    /* Generate fake boot sector for LBA 0 */
    uint8_t* buffer = (uint8_t*)req->buffer;
    memset(buffer, 0, 512 * req->sector_count);
    
    if (req->lba == 0) {
        /* Create a simple boot sector */
        buffer[0] = 0xEB; buffer[1] = 0x58; buffer[2] = 0x90;
        memcpy(buffer + 3, "mkfs.fat", 8);
        buffer[510] = 0x55; buffer[511] = 0xAA;
        KDEBUG("Generated simulated boot sector\n");
    }
    
    req->completed = true;
    req->result = 0;
    return 0;
}

static void cleanup_io_request(io_request_t* req)
{
    /* CORRECTION: Don't free static request */
    (void)req;  /* Suppress unused warning */
    /* Static request, no cleanup needed */
}

/* ============================================================================
 * DESCRIPTOR MANAGEMENT
 * ============================================================================ */

static uint16_t alloc_desc(void)
{
    if (ata_device.queue.num_free == 0) return 0xFFFF;
    
    uint16_t head = ata_device.queue.free_head;
    ata_device.queue.free_head = ata_device.queue.desc[head].next;
    ata_device.queue.num_free--;
    
    return head;
}

static void free_desc(uint16_t desc)
{
    ata_device.queue.desc[desc].next = ata_device.queue.free_head;
    ata_device.queue.free_head = desc;
    ata_device.queue.num_free++;
}

/* ============================================================================
 * MODE CONTROL AND TESTING
 * ============================================================================ */

void ata_set_real_mode(bool enable_real)
{
    use_real_virtio = enable_real;
    KINFO("ATA: Switched to %s mode\n", enable_real ? "REAL VirtIO" : "SIMULATION");
}

void ata_simple_test(void)
{
    KINFO("=== SIMPLE ATA/VIRTIO TEST ===\n");
    
    if (!ata_is_initialized()) {
        KERROR("ATA device not initialized\n");
        return;
    }
    
    /* DIAGNOSTIC: Check heap state */
    KINFO("=== HEAP DIAGNOSTIC ===\n");
    KINFO("Attempting small allocation (64 bytes)...\n");
    void* test_small = kmalloc(64);
    if (test_small) {
        KINFO("OK Small allocation successful at %p\n", test_small);
        kfree(test_small);
    } else {
        KERROR("KO Small allocation failed\n");
    }
    
    KINFO("Attempting 512 byte allocation...\n");
    uint8_t* buffer = kmalloc(512);
    
    /* Use static buffer as fallback */
    static uint8_t static_buffer[512] __attribute__((aligned(4)));
    
    if (!buffer) {
        KERROR("KO 512-byte allocation failed - using static buffer\n");
        buffer = static_buffer;
        KINFO("Using static buffer at %p\n", buffer);
    } else {
        KINFO("OK 512-byte allocation successful at %p\n", buffer);
    }
    
    /* Test both modes to see what works */
    KINFO("Testing REAL VirtIO mode...\n");
    ata_set_real_mode(true);
    
    memset(buffer, 0, 512);
    int result_real = ata_read_sectors(0, 1, buffer);
    
    /* Test simulation mode */
    KINFO("Testing SIMULATION mode...\n");
    ata_set_real_mode(false);
    
    memset(buffer, 0, 512);
    int result_sim = ata_read_sectors(0, 1, buffer);
    
    /* Analyze results */
    KINFO("=== RESULTS ===\n");
    KINFO("Real VirtIO result: %d\n", result_real);
    KINFO("Simulation result:  %d\n", result_sim);
    
    if (result_real > 0) {
        KINFO("OK REAL VirtIO is working! Using real mode.\n");
        ata_set_real_mode(true);
        
        /* Show data from real disk */
        KINFO("Real disk data (first 16 bytes):\n");
        KINFO("  ");
        for (int i = 0; i < 16; i++) {
            kprintf("%02X ", buffer[i]);
        }
        kprintf("\n");
        
        /* Check boot signature */
        if (buffer[510] == 0x55 && buffer[511] == 0xAA) {
            KINFO("OK Valid boot sector signature found!\n");
        } else {
            KINFO("- Boot signature: %02X %02X\n", buffer[510], buffer[511]);
        }
        
    } else if (result_sim > 0) {
        KINFO("WARNING Only simulation mode works. Using simulation.\n");
        ata_set_real_mode(false);
        
        /* Show simulated data */
        KINFO("Simulated data (first 16 bytes):\n");
        KINFO("  ");
        for (int i = 0; i < 16; i++) {
            kprintf("%02X ", buffer[i]);
        }
        kprintf("\n");
        
        if (buffer[510] == 0x55 && buffer[511] == 0xAA) {
            KINFO("OK Simulated boot sector signature found!\n");
        }
        
    } else {
        KERROR("KO Both modes failed!\n");
    }
    
    /* Clean up only if we used kmalloc */
    if (buffer != static_buffer) {  /* Only free if it's not our static buffer */
        kfree(buffer);
    }
    
    KINFO("=== END TEST ===\n");
}

/* ============================================================================
 * DEVICE INFO FUNCTIONS
 * ============================================================================ */

bool ata_is_initialized(void)
{
    return ata_device.initialized;
}

uint64_t ata_get_capacity_sectors(void)
{
    return ata_device.capacity;
}

uint32_t ata_get_sector_size(void)
{
    return ata_device.sector_size;
}

bool ata_is_ready(void)
{
    return ata_device.initialized && ata_device.capacity > 0;
}

/* ============================================================================
 * DIAGNOSTIC FUNCTIONS
 * ============================================================================ */

void virtio_diagnose_device_state(void)
{
    KINFO("=== VIRTIO DEVICE DIAGNOSIS ===\n");
    
    if (!ata_device.initialized || !ata_device.regs) {
        KERROR("Device not initialized\n");
        return;
    }
    
    KINFO("VirtIO Registers:\n");
    KINFO("  MAGIC:           0x%08X (expect: 0x74726976)\n", ata_device.regs[VIRTIO_MAGIC/4]);
    KINFO("  VERSION:         0x%08X\n", ata_device.regs[VIRTIO_VERSION/4]);
    KINFO("  DEVICE_ID:       0x%08X (expect: 0x2)\n", ata_device.regs[VIRTIO_DEVICE_ID/4]);
    KINFO("  VENDOR_ID:       0x%08X\n", ata_device.regs[VIRTIO_VENDOR_ID/4]);
    KINFO("  DEVICE_FEATURES: 0x%08X\n", ata_device.regs[VIRTIO_DEVICE_FEATURES/4]);
    KINFO("  STATUS:          0x%08X\n", ata_device.regs[VIRTIO_STATUS/4]);
    
    uint32_t status = ata_device.regs[VIRTIO_STATUS/4];
    KINFO("  Status breakdown:\n");
    KINFO("    ACKNOWLEDGE: %s\n", (status & VIRTIO_STATUS_ACK) ? "OK" : "KO");
    KINFO("    DRIVER:      %s\n", (status & VIRTIO_STATUS_DRIVER) ? "OK" : "KO");
    KINFO("    FEATURES_OK: %s\n", (status & VIRTIO_STATUS_FEATURES_OK) ? "OK" : "KO");
    KINFO("    DRIVER_OK:   %s\n", (status & VIRTIO_STATUS_DRIVER_OK) ? "OK" : "KO");
    
    KINFO("Device capacity: %u sectors (%u MB)\n", 
          (uint32_t)ata_device.capacity, 
          (uint32_t)(ata_device.capacity * 512 / (1024*1024)));
}

void virtio_comprehensive_test(void)
{
    KINFO("=== COMPREHENSIVE VIRTIO TEST ===\n");
    
    virtio_diagnose_device_state();
    
    if (ata_device.initialized) {
        ata_simple_test();
    }
    
    KINFO("=== END COMPREHENSIVE TEST ===\n");
}