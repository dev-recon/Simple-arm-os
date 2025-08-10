/* userfs_loader.c - Load userfs from memory loaded by QEMU */
#include <kernel/userfs_loader.h>
#include <kernel/ramfs.h>
#include <kernel/kprintf.h>
#include <kernel/string.h>

#if(0)
bool load_userfs_from_memory2(void)
{
    KINFO("=== LOADING USERFS FROM MEMORY ===\n");
    
    /* Check if data exists at the expected address */
    volatile userfs_header_t* header = (volatile userfs_header_t*)USERFS_LOAD_ADDR;
    
    KINFO("Checking userfs at address %p...\n", USERFS_LOAD_ADDR);
    
    /* Verify magic signature */
    uint64_t magic = header->magic;
    
    /* Afficher en deux parties 32 bits */
    uint32_t magic_high = (uint32_t)(magic >> 32);
    uint32_t magic_low = (uint32_t)(magic & 0xFFFFFFFF);
    
    KINFO("Magic signature: 0x%08X%08X\n", magic_high, magic_low);
    
    /* Meme chose pour la constante attendue */
    uint32_t expected_high = (uint32_t)(USERFS_MAGIC >> 32);
    uint32_t expected_low = (uint32_t)(USERFS_MAGIC & 0xFFFFFFFF);
    
    KINFO("Expected magic:  0x%08X%08X\n", expected_high, expected_low);
    
    if (magic != USERFS_MAGIC) {
        KWARN("No userfs found at memory address (wrong magic)\n");
        
        /* Debug: afficher les premiers octets */
        uint8_t* addr = (uint8_t*)USERFS_LOAD_ADDR;
        KINFO("First 16 bytes at address:\n");
        for (int i = 0; i < 16; i++) {
            KINFO("  [%02d] = 0x%02X", i, addr[i]);
            if (addr[i] >= 32 && addr[i] <= 126) {
                KINFO(" ('%c')\n", addr[i]);
            } else {
                KINFO(" (.)\n");
            }
        }
        
        return false;
    }
    
    uint32_t size = header->size;
    KINFO("OK UserFS found in memory!\n");
    KINFO("  Size: %u bytes (%u KB)\n", size, size / 1024);
    
    /* Extract TAR data to RAMFS */
    KINFO("Extracting TAR data to RAMFS...\n");
    extract_userfs_to_ramfs(header->data, size);
    
    return true;
}

void extract_userfs_to_ramfs(const uint8_t* tar_data, uint32_t size)
{
    KINFO("=== TAR EXTRACTION ===\n");
    KINFO("TAR data at: %p\n", tar_data);
    KINFO("TAR size: %u bytes\n", size);
    
    /* Simple TAR parser for basic files */
    const uint8_t* current = tar_data;
    const uint8_t* end = tar_data + size;
    
    while (current < end - 512) {
        /* TAR header is 512 bytes */
        const char* filename = (const char*)current;
        
        /* Skip empty entries */
        if (filename[0] == 0) {
            current += 512;
            continue;
        }
        
        /* Get file size from TAR header (octal at offset 124) */
        char size_str[12] = {0};
        memcpy(size_str, current + 124, 11);
        
        uint32_t file_size = 0;
        /* Simple octal to int conversion */
        for (int i = 0; i < 11 && size_str[i]; i++) {
            if (size_str[i] >= '0' && size_str[i] <= '7') {
                file_size = file_size * 8 + (size_str[i] - '0');
            }
        }
        
        KINFO("Found file: %s (size: %u)\n", filename, file_size);
        
        /* Skip header */
        current += 512;
        
        /* TODO: Write file to RAMFS using ramfs_write_sectors */
        /* For now, just skip the file data */
        uint32_t padded_size = (file_size + 511) & ~511;
        current += padded_size;
        
        if (current >= end) break;
    }
    
    KINFO("OK TAR extraction complete\n");
}
    #endif