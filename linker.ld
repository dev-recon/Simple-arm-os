ENTRY(_start)

MEMORY
{
    RAM (rwx) : ORIGIN = 0x40010000, LENGTH = 2000M
}

SECTIONS
{
    . = 0x40010000;

    /* Vecteurs d'interruptions ARM (alignes 32 bytes) */
    .vectors ALIGN(32) : {
        KEEP(*(.vectors))
    } > RAM
    
    /* Symboles de debut */
    __start = .;
    __kernel_start = .;
    
    /* Code */
    .text.boot : {
        *(.text.boot)
    } > RAM
    
    .text : {
        __text_start = .;
        *(.text)
        *(.text.*)
        __text_end = .;
    } > RAM
    
    /* Donnees en lecture seule */
    .rodata : {
        __rodata_start = .;
        *(.rodata)
        *(.rodata.*)
        __rodata_end = .;
    } > RAM
    
    /* Donnees initialisees */
    .data : {
        __data_start = .;
        *(.data)
        *(.data.*)
        __data_end = .;
    } > RAM
    
    /* Donnees non initialisees */
    .bss : {
        __bss_start = .;
        *(.bss)
        *(.bss.*)
        *(COMMON)
        . = ALIGN(4096);  /* Aligner sur page */
        __bss_end = .;
    } > RAM
    
    /* Pile du kernel */
    .stack : {
        . = ALIGN(4096);
        __stack_bottom = .;
        . += 32768;  /* 16KB de pile */
        __stack_top = .;
    } > RAM

    /* Pile pour le mode ABT (Abort) */
    .abtpile : {
        . = ALIGN(8);
        __abt_stack_bottom = .;
        . += 1024;            /* 1KB */
        __abt_stack_top = .;
    } > RAM

    /* Pile pour le mode IRQ */
    .irqpile : {
        . = ALIGN(8);
        __irq_stack_bottom = .;
        . += 2048;            /* 2KB - augmente pour Cortex-A15 */
        __irq_stack_top = .;
    } > RAM

    /* Pile pour le mode SVC */
    .svcpile : {
        . = ALIGN(8);
        __svc_stack_bottom = .;
        . += 4096;            /* 4KB pour SVC - mode principal du kernel */
        __svc_stack_top = .;
    } > RAM
    
    /* === HEAP AUTOMATIQUE === */
    . = ALIGN(4096);
    __end = .;
    __kernel_end = .;
    
    /* Heap commence apres le kernel */
    __heap_start = .;
    
    /* Reserver de l'espace pour le heap */
    .heap : {
        . = ALIGN(4096);
        __heap_start = .;
        . += 8M;  /* 8MB de heap (augmente pour virt) */
        __heap_end = .;
    } > RAM
    
    /* Zone libre apres le heap */
    __free_memory_start = .;
    
    /* Calculer les tailles */
    __kernel_size = __kernel_end - __kernel_start;
    __heap_size = __heap_end - __heap_start;
    
    /* Limite de la RAM pour machine virt */
    __ram_start = 0x40000000;
    __ram_end = 0x140000000;  /* 4GB pour virt */
    __ram_size = __ram_end - __ram_start;
    
    /* Sections de debug */
    .debug_info 0 : { *(.debug_info) }
    .debug_abbrev 0 : { *(.debug_abbrev) }
    .debug_line 0 : { *(.debug_line) }
    .debug_str 0 : { *(.debug_str) }
    
    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.ARM.exidx*)
        *(.ARM.extab*)
    }
}
