ENTRY(_start)

KERNEL_LINK_ADDR = 0x40080000;
RAM_END_ADDR = 0x80000000;

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
    __kernel_start = .;
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
    } > RAM :data

    __kernel_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
