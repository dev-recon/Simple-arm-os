/*
 * vexpress.ld - Script de liaison pour VExpress-A9
 * Memoire: 1GB RAM a 0x60000000 (layout VExpress-A9)
 */

ENTRY(_start)

MEMORY
{
    /* Utiliser toute la RAM disponible de QEMU */
    RAM (rwx) : ORIGIN = 0x60010000, LENGTH = 1000M
}

SECTIONS
{
    . = 0x60010000;
    
    /* Symbole de debut du kernel */
    __start = .;
    __kernel_start = .;
    
    /* Section de boot - doit etre en premier */
    .text.boot : {
        *(.text.boot)
    } > RAM
    
    /* Code principal */
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
        . = ALIGN(4);
        __bss_end = .;
    } > RAM
    
    /* Section pour la pile */
    .stack : {
        . = ALIGN(8);
        __stack_bottom = .;
        stack_bottom = .;
        . += 16384;  /* 16KB de pile */
        __stack_top = .;
        stack_top = .;
    } > RAM
    
    /* Marquer la fin du kernel - IMPORTANT ! */
    . = ALIGN(4096);  /* Aligner sur page */
    __end = .;
    __kernel_end = .;
    
    /* Calculer la taille du kernel */
    __kernel_size = __end - __start;
    
    /* Informations pour l'allocateur memoire */
    __heap_start = ALIGN(4096);  /* Debut du heap apres le kernel */
    
    /* Informations de debug (non chargees) */
    .debug_info 0 : { *(.debug_info) }
    .debug_abbrev 0 : { *(.debug_abbrev) }
    .debug_line 0 : { *(.debug_line) }
    .debug_str 0 : { *(.debug_str) }
    
    /* Rejeter les sections inutiles */
    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.ARM.exidx*)
        *(.ARM.extab*)
    }
}