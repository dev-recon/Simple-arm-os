ENTRY(_start)

KERNEL_LINK_ADDR = DEFINED(KERNEL_LINK_ADDR) ? KERNEL_LINK_ADDR : 0x40080000;
RAM_BASE_ADDR = DEFINED(RAM_BASE_ADDR) ? RAM_BASE_ADDR : 0x40000000;
RAM_END_ADDR = DEFINED(RAM_END_ADDR) ? RAM_END_ADDR : 0x80000000;

MEMORY
{
    RAM (rwx) : ORIGIN = KERNEL_LINK_ADDR, LENGTH = RAM_END_ADDR - KERNEL_LINK_ADDR
}

PHDRS
{
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = KERNEL_LINK_ADDR;
    __start = .;
    __kernel_start = .;
    __kernel_phys_start = .;
    __text_start = .;

    .text.boot : ALIGN(16) {
        KEEP(*(.text.boot))
    } > RAM :text

    .vectors : ALIGN(2048) {
        KEEP(*(.vectors))
    } > RAM :text

    .text : ALIGN(16) {
        *(.text)
        *(.text.*)
        . = ALIGN(4096);
        __text_end = .;
    } > RAM :text

    .rodata : ALIGN(4096) {
        __rodata_start = .;
        *(.rodata)
        *(.rodata.*)
        . = ALIGN(4096);
        __rodata_end = .;
    } > RAM :text

    .data : ALIGN(4096) {
        __data_start = .;
        *(.data)
        *(.data.*)
        __data_end = .;
    } > RAM :data

    .bss (NOLOAD) : ALIGN(16) {
        __bss_start = .;
        *(.bss)
        *(.bss.*)
        *(COMMON)
        __bss_end = .;
    } > RAM :data

    .stack (NOLOAD) : ALIGN(4096) {
        __stack_bottom = .;
        . += 64K;
        __stack_top = .;
        __stack_svc_top = .;
    } > RAM :data

    .smpstacks (NOLOAD) : ALIGN(4096) {
        __smp_stack_bottom = .;
        . += 16K * 4;
        __smp_stack_top = .;
    } > RAM :data

    . = ALIGN(4096);
    __end = .;
    __kernel_end = .;
    __kernel_phys_end = .;

    .heap (NOLOAD) : ALIGN(4096) {
        __heap_start = .;
        . += 8M;
        __heap_end = .;
    } > RAM :data

    __free_memory_start = .;
    __kernel_size = __kernel_end - __kernel_start;
    __heap_size = __heap_end - __heap_start;
    __ram_start = RAM_BASE_ADDR;
    __ram_end = RAM_END_ADDR;
    __ram_size = __ram_end - __ram_start;

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
