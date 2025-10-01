/* kernel/process/exec.c */
#include <kernel/process.h>
#include <kernel/syscalls.h>
#include <kernel/memory.h>
#include <kernel/vfs.h>
#include <kernel/kernel.h>
#include <kernel/elf32.h>
#include <kernel/kprintf.h>
#include <kernel/file.h>


/* Forward declarations de toutes les fonctions statiques */
int read_elf_header(inode_t* inode, elf32_ehdr_t* header);
bool validate_elf_header(elf32_ehdr_t* header);
int load_elf_segments(inode_t* inode, elf32_ehdr_t* elf_header, vm_space_t* vm);
int load_segment(inode_t* inode, elf32_phdr_t* phdr, vm_space_t* vm);



int read_elf_header(inode_t* inode, elf32_ehdr_t* header)
{
    /* Create temporary file for reading */
    file_t temp_file;
    ssize_t bytes_read;
    
    temp_file.inode = inode;
    temp_file.offset = 0;
    temp_file.flags = O_RDONLY;
    temp_file.f_op = inode->f_op;
    
    bytes_read = temp_file.f_op->read(&temp_file, header, sizeof(elf32_ehdr_t));
    if (bytes_read != (ssize_t)sizeof(elf32_ehdr_t)) {
        return -EINVAL;
    }
    
    if(!validate_elf_header(header)){
        return -EINVAL;
    }

    return 0;
}

bool validate_elf_header(elf32_ehdr_t* header)
{
    /* Check ELF magic */
    if (header->e_ident[0] != 0x7F || 
        header->e_ident[1] != 'E' ||
        header->e_ident[2] != 'L' ||
        header->e_ident[3] != 'F') {
        return false;
    }

    //KDEBUG("ELF MAGIC OK\n");

    /* Check 32-bit little-endian */
    if (header->e_ident[4] != 1 ||  /* ELFCLASS32 */
        header->e_ident[5] != 1) {  /* ELFDATA2LSB */
        return false;
    }
    
    //KDEBUG("Check 32-bit little-endian OK\n");

    /* Check executable ARM */
    if (header->e_type != 2 ||      /* ET_EXEC */
        header->e_machine != 40) {  /* EM_ARM */
        return false;
    }

    //KDEBUG("Check executable ARM Type %d - Machine %d OK\n", header->e_type, header->e_machine );
    //KDEBUG("Executable entry point %p \n", header->e_entry );

    // TO MODIFY!!!
    /* Check entry point */
    //if (!IS_USER_ADDR(header->e_entry)) {
    //    return false;
    //}
    
    return true;
}

int load_elf_segments(inode_t* inode, elf32_ehdr_t* elf_header, vm_space_t* vm)
{
    /* Read program headers */
    elf32_phdr_t* phdrs = kmalloc(elf_header->e_phnum * sizeof(elf32_phdr_t));
    file_t temp_file;
    size_t phdrs_size;
    ssize_t bytes_read;
    int i;
    
    if (!phdrs) return -1;
    
    temp_file.inode = inode;
    temp_file.offset = elf_header->e_phoff;
    temp_file.flags = O_RDONLY;
    temp_file.f_op = inode->f_op;
    
    //KDEBUG("Load ELF Segemnts : Start reading segments\n");

    phdrs_size = elf_header->e_phnum * sizeof(elf32_phdr_t);
    bytes_read = temp_file.f_op->read(&temp_file, phdrs, phdrs_size);
    if (bytes_read != (ssize_t)phdrs_size) {
        kfree(phdrs);
        return -1;
    }

    //KDEBUG("Load ELF Segemnts : bytes_read = %u, elf_header->e_phnum %u\n", bytes_read, elf_header->e_phnum);
    
    /* Load each LOAD segment */
    for (i = 0; i < elf_header->e_phnum; i++) {
        elf32_phdr_t* phdr = &phdrs[i];
        
        if (phdr->p_type != PT_LOAD) continue;
        
        if (load_segment(inode, phdr, vm) < 0) {
            kfree(phdrs);
            return -1;
        }
    }
    
    kfree(phdrs);
    return 0;
}

static inline void flush_instructions(void){
    asm volatile("dsb ish");          // données visibles
    asm volatile("mcr p15,0,%0,c7,c5,0"::"r"(0)); // IC IALLU (ou IVAU par ligne)
    asm volatile("dsb ish; isb");
}

int load_segment(inode_t* inode, elf32_phdr_t* phdr, vm_space_t* vm)
{
    uint32_t vaddr_start = phdr->p_vaddr & ~(PAGE_SIZE - 1);  // Début aligné
    uint32_t vaddr_end = (phdr->p_vaddr + phdr->p_memsz + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    uint32_t vma_flags = 0;
    vma_t* vma = NULL;
    file_t temp_file;
    //uint32_t phys_addr = 0;

    extern void check_address_content(uint32_t phys_addr, const char* step);
    
    //KDEBUG("Loading segment: vaddr=0x%08X-0x%08X (aligned: 0x%08X-0x%08X)\n",
    //       phdr->p_vaddr, phdr->p_vaddr + phdr->p_memsz, vaddr_start, vaddr_end);
    //KDEBUG("File data: offset=0x%08X, size=%u\n", phdr->p_offset, phdr->p_filesz);
    
    /* Convert ELF flags to VMA flags */
    if (phdr->p_flags & PF_R) vma_flags |= VMA_READ;
    if (phdr->p_flags & PF_W) vma_flags |= VMA_WRITE;
    if (phdr->p_flags & PF_X) vma_flags |= VMA_EXEC;
 
    /* Create VMA for this segment */
    vma = create_vma(vm, vaddr_start, vaddr_end - vaddr_start, vma_flags);
    if (!vma) {
        KERROR("Failed to create VMA\n");
        return -1;
    }
  
    /* Setup file for reading */
    temp_file.inode = inode;
    temp_file.flags = O_RDONLY;
    temp_file.f_op = inode->f_op;
    
    /* Load page by page - BOUCLE CORRIGÉE */
    for (uint32_t page_vaddr = vaddr_start; page_vaddr < vaddr_end; page_vaddr += PAGE_SIZE) {
        /* Allocate physical page */
        void* phys_page = allocate_page();
        if (!phys_page) {
            KERROR("Failed to allocate physical page for 0x%08X\n", page_vaddr);
            return -1;
        }
                
        /* Map temporarily in kernel space for loading */
        //uint32_t temp_vaddr = map_temp_page((uint32_t)phys_page);
        uint32_t temp_vaddr = (uint32_t)phys_page;
        if (temp_vaddr == 0) {
            KERROR("Failed to map temp page\n");
            free_page(phys_page);
            return -1;
        } 
        
        /* Clear the entire page first */
        //memset((void*)temp_vaddr, 0, PAGE_SIZE);   //// FIX IT
        
        /* Calculate file data range for this page */
        uint32_t file_start_in_page = 0;
        uint32_t file_end_in_page = 0;
        uint32_t file_offset_to_read = 0;
        
        /* Does this page contain file data? */
        if (page_vaddr < phdr->p_vaddr + phdr->p_filesz && 
            page_vaddr + PAGE_SIZE > phdr->p_vaddr) {
            
            /* Calculate overlapping region */
            uint32_t data_start = MAX(page_vaddr, phdr->p_vaddr);
            uint32_t data_end = MIN(page_vaddr + PAGE_SIZE, phdr->p_vaddr + phdr->p_filesz);
            
            file_start_in_page = data_start - page_vaddr;
            file_end_in_page = data_end - page_vaddr;
            file_offset_to_read = phdr->p_offset + (data_start - phdr->p_vaddr);
            
            //KDEBUG("Reading %u bytes from file offset 0x%08X to page offset %u\n",
            //       file_end_in_page - file_start_in_page, file_offset_to_read, file_start_in_page);
            
            /* Set file position and read */
            temp_file.offset = file_offset_to_read;
            ssize_t bytes_read = temp_file.f_op->read(&temp_file, 
                                                     (void*)(temp_vaddr + file_start_in_page),
                                                     file_end_in_page - file_start_in_page);
            
            if (bytes_read != (ssize_t)(file_end_in_page - file_start_in_page)) {
                KERROR("Read failed: expected %u bytes, got %d\n",
                       file_end_in_page - file_start_in_page, bytes_read);
                //unmap_temp_page((void*)temp_vaddr);
                free_page(phys_page);
                return -1;
            }
            
            //KDEBUG("Successfully read %u bytes\n", bytes_read);

            // juste après le read() réussi dans temp_vaddr
            uintptr_t start = (temp_vaddr) & ~63u;
            uintptr_t end   = (temp_vaddr + PAGE_SIZE + 63u) & ~63u;
            for (uintptr_t p = start; p < end; p += 64) {
                //asm volatile("mcr p15,0,%0,c7,c10,1" :: "r"(p) : "memory"); // DCCMVAC
                asm volatile("mcr p15,0,%0,c7,c6,1" :: "r"(p) : "memory"); // DCIMVAC
            }
            asm volatile("dsb ish" ::: "memory");

            dcache_clean_by_va((void*)temp_vaddr, PAGE_SIZE);

            if (vma_flags & VMA_EXEC) {
                sync_icache_for_exec();
            }

            clean_dcache_by_mva((void *)temp_vaddr, PAGE_SIZE); 

        /* Après la lecture réussie */

            /* TEST IMMÉDIAT : vérifier les premiers bytes lus */
            //uint8_t* byte_ptr = (uint8_t*)(temp_vaddr + file_start_in_page);
            //KDEBUG("Raw bytes read: %02X %02X %02X %02X %02X %02X %02X %02X\n",
            //    byte_ptr[0], byte_ptr[1], byte_ptr[2], byte_ptr[3],
            //    byte_ptr[4], byte_ptr[5], byte_ptr[6], byte_ptr[7]);

            /* Vérifier si c'est un problème d'endianness */
            //uint32_t* word_ptr = (uint32_t*)(temp_vaddr + file_start_in_page);
            //KDEBUG("As 32-bit words: 0x%08X 0x%08X 0x%08X 0x%08X\n",
            //    word_ptr[0], word_ptr[1], word_ptr[2], word_ptr[3]);

            /* Pour la page 0x8000, vérifier spécifiquement */
/*             if (page_vaddr == 0x8000) {
                uint32_t expected = 0xeb000006;
                uint32_t actual = word_ptr[0];
                KDEBUG("Entry point check: expected=0x%08X, actual=0x%08X\n", expected, actual);
                
                if (actual == 0) {
                    KERROR("First instruction is zero - file read failed!\n");
                    
                    // Test : écrire une valeur de test 
                    word_ptr[0] = 0xDEADBEEF;
                    KDEBUG("Test write: wrote 0xDEADBEEF, readback=0x%08X\n", word_ptr[0]);
                    
                    // Si le test write/read fonctionne, c'est la lecture de fichier qui échoue 
                }
            } */
        } else {
            KERROR("Page contains no file data (BSS or padding)\n");
        }
        
        /* Debug: show first few bytes of the page */
        //uint32_t* debug_ptr = (uint32_t*)temp_vaddr;
        //KDEBUG("Page 0x%08X content: 0x%08X 0x%08X 0x%08X 0x%08X\n", temp_vaddr,
        //       debug_ptr[0], debug_ptr[1], debug_ptr[2], debug_ptr[3]);
        
        /* Unmap temporary mapping */
        //unmap_temp_page((void*)temp_vaddr);



        //phys_addr = get_physical_address(vm->pgdir, 0x00008000);
        //KDEBUG("load_segment : Physical address returned = 0x%08X\n", phys_addr);
        //if(phys_addr != 0)
        //    check_address_content( phys_addr, "**************** INSIDE LOAD SEGEMNTS .....................................");
    


        //uint8_t* check = (uint8_t*)map_temp_page((uint32_t)phys_page);
        //KDEBUG("Check page before map_user_page: %02X %02X %02X %02X\n", check[0], check[1], check[2], check[3]);
        //hexdump(check,8);
        //unmap_temp_page(check);
        
        /* Map page in user space with correct permissions */
        //KDEBUG("Mapping user page 0x%08X -> %p\n", page_vaddr, phys_page);
        if (map_user_page(vm->pgdir, page_vaddr, (uint32_t)phys_page, vma_flags, vm->asid) < 0) {
            KERROR("Failed to map user page 0x%08X\n", page_vaddr);
            free_page(phys_page);
            return -1;
        }

        //read_l2_entry(vm->pgdir, page_vaddr);
        //uint32_t temp = get_physical_address(vm->pgdir, page_vaddr);
        //hexdump((void*)temp, (size_t)0x800);

        flush_instructions();

        invalidate_dcache_by_mva((void *)page_vaddr, PAGE_SIZE); // DCIMVAC + DSB

        if (vma_flags & VMA_EXEC) {
            asm volatile("mcr p15,0,%0,c7,c5,0"::"r"(0)); // ICIALLU
            asm volatile("dsb ish; isb");
        }

        //uint8_t* check2 = (uint8_t*)map_temp_page((uint32_t)phys_page);
        //KDEBUG("Check N2 page after map_user_page: %02X %02X %02X %02X\n", check2[0], check2[1], check2[2], check2[3]);
        //unmap_temp_page(check);


        //uint32_t phys = get_physical_address(vm->pgdir, 0x00008000);
        //uint8_t *data = (uint8_t *)map_temp_page((uint32_t)phys);
        //KDEBUG("Post-mapping PA 0x%08X @ 0x00008000: %02X %02X %02X %02X\n", phys, data[0], data[1], data[2], data[3]);
        //unmap_temp_page(data);

        //hexdump((void *)vm->pgdir,32);
        //hexdump((void *)0x7F001000, 32);
        
        //KINFO("Successfully mapped page 0x%08X to phys 0x%08X in pgdir 0x%08X\n", page_vaddr, phys_page, vm->pgdir);
    }
    
    //KINFO("Segment loaded successfully\n");
    return 0;
}


