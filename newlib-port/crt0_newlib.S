/* crt0_newlib.S - userspace entry point for programs linked with newlib */

.section .text
.align 4
.global _start
.type _start, %function

_start:
    /*
     * Stack layout prepared by the kernel:
     *   sp[0]        = argc
     *   sp[1..]      = argv pointers, NULL terminated
     *   after argv   = envp pointers, NULL terminated
     */
    ldr r0, [sp]              /* argc */
    add r1, sp, #4            /* argv */
    add r2, r1, r0, lsl #2
    add r2, r2, #4            /* envp = argv + argc + NULL */
    bic sp, sp, #7            /* AAPCS 8-byte stack alignment */

    ldr r3, =environ
    str r2, [r3]

    bl main
    bl exit

1:
    b 1b

