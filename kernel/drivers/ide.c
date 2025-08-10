#include <kernel/types.h>
#include <kernel/ide.h>
#include <kernel/kprintf.h>
#include <kernel/interrupt.h>

/* Variables globales */
static volatile uint16_t* ide_base = (volatile uint16_t*)IDE_PRIMARY_BASE;
static volatile uint16_t* ide_ctrl = (volatile uint16_t*)IDE_PRIMARY_CTRL;
static volatile uint32_t ide_irq_count = 0;

/* FONCTION 1: Lecture registre IDE */
static uint8_t ide_read_reg(uint8_t reg)
{
    if (reg == IDE_REG_CTRL || reg == IDE_REG_ALTSTATUS) {
        return (uint8_t)ide_ctrl[reg];
    } else {
        return (uint8_t)ide_base[reg];
    }
}

/* FONCTION 2: ecriture registre IDE */
static void ide_write_reg(uint8_t reg, uint8_t value)
{
    if (reg == IDE_REG_CTRL) {
        ide_ctrl[reg] = value;
    } else {
        ide_base[reg] = value;
    }
    
    /* Barriere memoire */
    __asm__ volatile("dsb sy" : : : "memory");
}

/* FONCTION 3: Attendre que le drive soit pret */
static bool ide_wait_ready(uint32_t timeout_ms)
{
    for (uint32_t i = 0; i < timeout_ms * 1000; i++) {
        uint8_t status = ide_read_reg(IDE_REG_STATUS);
        
        /* Attendre que BSY soit a 0 et DRDY a 1 */
        if (!(status & IDE_STATUS_BSY) && (status & IDE_STATUS_DRDY)) {
            return true;
        }
        
        /* Petit delai */
        for (volatile int j = 0; j < 100; j++);
    }
    
    return false;
}

/* FONCTION 4: Attendre DRQ (Data Request) */
static bool ide_wait_drq(uint32_t timeout_ms)
{
    for (uint32_t i = 0; i < timeout_ms * 1000; i++) {
        uint8_t status = ide_read_reg(IDE_REG_STATUS);
        
        /* Verifier erreur */
        if (status & IDE_STATUS_ERR) {
            return false;
        }
        
        /* Attendre DRQ */
        if (status & IDE_STATUS_DRQ) {
            return true;
        }
        
        /* Petit delai */
        for (volatile int j = 0; j < 100; j++);
    }
    
    return false;
}

/* FONCTION 5: Handler IRQ IDE */
void ide_irq_handler(void)
{
    ide_irq_count++;
    
    /* Lire status pour acquitter l'IRQ */
    uint8_t status = ide_read_reg(IDE_REG_STATUS);
    
    kprintf("[IDE] IRQ received! Status: 0x%02X (count: %u)\n", 
            status, ide_irq_count);
}

/* FONCTION 6: Initialisation IDE */
bool init_ide(void)
{
    kprintf("[IDE] === IDE CONTROLLER INITIALIZATION ===\n");
    
    /* Verifier l'adresse de base */
    kprintf("[IDE] IDE Primary base: 0x%08X\n", IDE_PRIMARY_BASE);
    kprintf("[IDE] IDE Primary ctrl: 0x%08X\n", IDE_PRIMARY_CTRL);
    
    /* Activer IRQ IDE */
    enable_irq(IDE_PRIMARY_IRQ);
    kprintf("[IDE] IRQ %d enabled\n", IDE_PRIMARY_IRQ);
    
    /* Reset du controleur */
    ide_write_reg(IDE_REG_CTRL, 0x04);  /* Software reset */
    
    /* Attendre reset */
    for (volatile int i = 0; i < 100000; i++);
    
    /* Desactiver reset */
    ide_write_reg(IDE_REG_CTRL, 0x00);
    
    /* Attendre que le drive soit pret */
    kprintf("[IDE] Waiting for drive ready...\n");
    
    if (!ide_wait_ready(5000)) {  /* 5 secondes */
        kprintf("[IDE] KO Drive not ready after reset\n");
        return false;
    }
    
    kprintf("[IDE] OK Drive ready!\n");
    
    /* Selectionner le master drive */
    ide_write_reg(IDE_REG_DRIVE, IDE_DRIVE_MASTER | IDE_DRIVE_LBA);
    
    if (!ide_wait_ready(1000)) {
        kprintf("[IDE] KO Drive not ready after selection\n");
        return false;
    }
    
    /* Lire le status final */
    uint8_t status = ide_read_reg(IDE_REG_STATUS);
    kprintf("[IDE] Final status: 0x%02X\n", status);
    
    if (status & IDE_STATUS_ERR) {
        uint8_t error = ide_read_reg(IDE_REG_ERROR);
        kprintf("[IDE] KO Error detected: 0x%02X\n", error);
        return false;
    }
    
    kprintf("[IDE] OK IDE controller initialized successfully!\n");
    return true;
}

/* FONCTION 7: Identification du disque */
bool ide_identify(void)
{
    kprintf("[IDE] === DISK IDENTIFICATION ===\n");
    
    /* Selectionner master drive */
    ide_write_reg(IDE_REG_DRIVE, IDE_DRIVE_MASTER);
    
    if (!ide_wait_ready(1000)) {
        kprintf("[IDE] KO Drive not ready for identify\n");
        return false;
    }
    
    /* Envoyer commande IDENTIFY */
    ide_write_reg(IDE_REG_COMMAND, IDE_CMD_IDENTIFY);
    
    /* Attendre DRQ */
    if (!ide_wait_drq(1000)) {
        kprintf("[IDE] KO No DRQ for identify command\n");
        return false;
    }
    
    /* Lire les donnees d'identification (256 mots de 16 bits) */
    uint16_t identify_data[256];
    
    for (int i = 0; i < 256; i++) {
        identify_data[i] = ide_base[IDE_REG_DATA];
    }
    
    /* Extraire les informations importantes */
    uint32_t sectors = ((uint32_t)identify_data[61] << 16) | identify_data[60];
    uint32_t size_mb = (sectors * 512) / (1024 * 1024);
    
    kprintf("[IDE] Disk information:\n");
    kprintf("[IDE]   Sectors: %u\n", sectors);
    kprintf("[IDE]   Size: %u MB\n", size_mb);
    
    /* Afficher le modele (mots 27-46) */
    kprintf("[IDE]   Model: ");
    for (int i = 27; i < 47; i++) {
        uint16_t word = identify_data[i];
        char c1 = (word >> 8) & 0xFF;
        char c2 = word & 0xFF;
        if (c1 >= 32 && c1 <= 126) kprintf("%c", c1);
        if (c2 >= 32 && c2 <= 126) kprintf("%c", c2);
    }
    kprintf("\n");
    
    return true;
}

/* FONCTION 8: Lecture secteur */
bool ide_read_sector(uint32_t lba, uint8_t* buffer)
{
    kprintf("[IDE] Reading sector %u...\n", lba);
    
    /* Selectionner master drive avec LBA */
    ide_write_reg(IDE_REG_DRIVE, IDE_DRIVE_MASTER | IDE_DRIVE_LBA | 
                  ((lba >> 24) & 0x0F));
    
    if (!ide_wait_ready(1000)) {
        kprintf("[IDE] KO Drive not ready for read\n");
        return false;
    }
    
    /* Configurer LBA et nombre de secteurs */
    ide_write_reg(IDE_REG_SECCOUNT, 1);            /* 1 secteur */
    ide_write_reg(IDE_REG_LBA_LOW, lba & 0xFF);
    ide_write_reg(IDE_REG_LBA_MID, (lba >> 8) & 0xFF);
    ide_write_reg(IDE_REG_LBA_HIGH, (lba >> 16) & 0xFF);
    
    uint32_t irq_before = ide_irq_count;
    
    /* Envoyer commande READ SECTORS */
    ide_write_reg(IDE_REG_COMMAND, IDE_CMD_READ_SECTORS);
    
    /* Attendre DRQ ou IRQ */
    bool drq_ready = false;
    
    for (int timeout = 0; timeout < 10000000; timeout++) {
        /* Check IRQ */
        if (ide_irq_count > irq_before) {
            kprintf("[IDE] DONE IRQ received during read!\n");
        }
        
        /* Check DRQ */
        uint8_t status = ide_read_reg(IDE_REG_STATUS);
        if (status & IDE_STATUS_DRQ) {
            drq_ready = true;
            break;
        }
        
        if (status & IDE_STATUS_ERR) {
            uint8_t error = ide_read_reg(IDE_REG_ERROR);
            kprintf("[IDE] KO Read error: 0x%02X\n", error);
            return false;
        }
        
        /* Status periodique */
        if (timeout % 2000000 == 0) {
            kprintf("[IDE] Read timeout %d: status=0x%02X, IRQ=%u\n",
                    timeout, status, ide_irq_count);
        }
    }
    
    if (!drq_ready) {
        kprintf("[IDE] KO DRQ timeout during read\n");
        return false;
    }
    
    /* Lire les donnees (256 mots de 16 bits = 512 bytes) */
    uint16_t* buf16 = (uint16_t*)buffer;
    
    for (int i = 0; i < 256; i++) {
        buf16[i] = ide_base[IDE_REG_DATA];
    }
    
    kprintf("[IDE] OK Sector %u read successfully\n", lba);
    kprintf("[IDE] IRQ count: %u -> %u\n", irq_before, ide_irq_count);
    
    return true;
}

/* FONCTION 9: Test complet IDE */
void ide_comprehensive_test(void)
{
    kprintf("\n- === COMPREHENSIVE IDE TEST ===\n");
    
    /* 1. Initialisation */
    if (!init_ide()) {
        kprintf("[IDE] KO Initialization failed\n");
        return;
    }
    
    /* 2. Identification */
    if (!ide_identify()) {
        kprintf("[IDE] WARNING Identification failed, continuing anyway\n");
    }
    
    /* 3. Test de lecture */
    uint8_t sector_buffer[512];
    
    if (ide_read_sector(0, sector_buffer)) {
        kprintf("[IDE] OK Read test successful!\n");
        
        /* Afficher les premiers bytes */
        kprintf("[IDE] First 16 bytes of sector 0:\n");
        kprintf("[IDE]   ");
        for (int i = 0; i < 16; i++) {
            kprintf("%02X ", sector_buffer[i]);
        }
        kprintf("\n");
        
        /* Verifier signature MBR */
        if (sector_buffer[510] == 0x55 && sector_buffer[511] == 0xAA) {
            kprintf("[IDE] OK Valid MBR signature found!\n");
        } else {
            kprintf("[IDE] - No MBR signature (raw disk)\n");
        }
    } else {
        kprintf("[IDE] KO Read test failed\n");
    }
    
    /* 4. Statistiques finales */
    kprintf("[IDE] Final statistics:\n");
    kprintf("[IDE]   Total IRQs received: %u\n", ide_irq_count);
    kprintf("[IDE]   Final status: 0x%02X\n", ide_read_reg(IDE_REG_STATUS));
    
    if (ide_irq_count > 0) {
        kprintf("[IDE] DONE IDE interrupts are working!\n");
    } else {
        kprintf("[IDE] WARNING No IDE interrupts received (polling mode)\n");
    }
}

/* FONCTION 10: Test simple pour demarrage rapide */
void ide_quick_test(void)
{
    kprintf("\n- === QUICK IDE TEST ===\n");
    
    /* Test rapide sans identification complete */
    enable_irq(IDE_PRIMARY_IRQ);
    
    /* Reset simple */
    ide_write_reg(IDE_REG_CTRL, 0x04);
    for (volatile int i = 0; i < 50000; i++);
    ide_write_reg(IDE_REG_CTRL, 0x00);
    
    /* Test status */
    uint8_t status = ide_read_reg(IDE_REG_STATUS);
    kprintf("[IDE] Status: 0x%02X\n", status);
    
    if (status != 0xFF && status != 0x00) {
        kprintf("[IDE] OK IDE controller detected!\n");
        ide_comprehensive_test();
    } else {
        kprintf("[IDE] KO No IDE controller found\n");
    }
}