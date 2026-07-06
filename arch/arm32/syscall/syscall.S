/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: arch/arm32/syscall/syscall.S
 * Layer: Kernel / syscall entry assembly
 *
 * Responsibilities:
 * - Capture user register state at SVC entry.
 * - Return safely from privileged mode to user mode.
 *
 * Notes:
 * - Must stay consistent with task_context_t offsets.
 */

.section .text
.align 2

.global swi_handler
.global current_task
.global current_tasks
.global save_user_bank
.global signal_return_trampoline
.equ __NR_rt_sigreturn, 173
.equ MAX_SYSCALLS,     512     /* Keep in sync with include/kernel/syscalls.h */

/*
 * Generated from arch/arm32/asm-offsets.c. The syscall path is extremely sensitive
 * to task_context_t layout, so no field offset is hardcoded here.
 */
.include "asm-offsets.h"

.macro load_current_task_local reg tmp
    /*
     * TPIDRPRW is a privileged per-CPU register.  It is the authoritative fast
     * path for the current task on SMP; current_tasks[] remains a diagnostic
     * mirror and a fallback for very early bring-up code.
     */
    mrc     p15, 0, \reg, c13, c0, 4
    cmp     \reg, #0
    bne     1f
    mrc     p15, 0, \tmp, c0, c0, 5
    and     \tmp, \tmp, #3
    ldr     \reg, =current_tasks
    ldr     \reg, [\reg, \tmp, lsl #2]
1:
.endm

    /* General-purpose registers r0-r12. */
    // r0.         0,
    // r1          4,
    // r2          8,
    // r3          12
    // r4          16
    // r5          20
    // r6          24
    // r7          28
    // r8          32
    // r9          36
    // r10         40
    // r11         44
    // r12         48
    
    /* Special registers. */
    // sp          52       // Stack Pointer 
    // lr          56       // Link Register 
    // pc;         60       // Program Counter 
    // cpsr;       64       // Current Program Status Register 
    
    // is_first_run; 68      // first-run flag
    // ttbr0;      72
    // asid;       76

    // spsr;       80        // SPSR_svc 
    // returns_to_user;  84  // has to return to user mode 

    // usr_r[0];     88      // user r0..r12 captured on SVC entry
    // usr_r[1];     92
    // usr_r[2];     96
    // usr_r[3];     100
    // usr_r[4];     104
    // usr_r[5];     108
    // usr_r[6];     112
    // usr_r[7];     116
    // usr_r[8];     120
    // usr_r[9];     124
    // usr_r[10];    128
    // usr_r[11];    132
    // usr_r[12];    136
    // usr_sp;       140
    // usr_lr;       144
    // usr_pc;       148        // user resume PC
    // usr_cpsr;     152        // usually 0x10
    // svc_sp_top;   156        // allocated kernel-stack top for this task
    // svc_sp;       160        // current SVC stack pointer
    // svc_lr_saved; 164

/*
 * ARM32 SVC entry.
 *
 * The handler has two jobs:
 *   1. Build a canonical user context in current_task->context before C code
 *      can clobber scratch registers.
 *   2. Preserve the active SVC frame so a syscall may yield/sleep/wait and
 *      later resume inside the kernel instead of being forced to user mode.
 *
 * Keep this file in lock-step with task_context_t offsets and task_switch.S.
 */
swi_handler:

    stmfd sp!, {r4-r12, lr}     /* save callee-preserved registers + LR_svc */
    mrs r12, spsr
    stmfd sp!, {r12}            /* save user CPSR/SPSR_svc */
    
    /* Syscall exit debug hook. */
    //push {r0-r3, lr}
    //bl debug_print_sp3
    //pop {r0-r3, lr}

    /* Validate syscall number. */
    cmp r7, #MAX_SYSCALLS
    movhs r0, #-38              /* invalid syscall: -ENOSYS */
    subhs sp, sp, #12           /* build the same small frame as the normal path */
    bhs syscall_return
    
    /* Arguments for syscall_handler. */
    /* Prototype: syscall_handler(syscall_num, arg1, arg2, arg3, arg4, arg5) */

    /*
     * 1) Freeze the user registers immediately.
     * After this point the C calling convention and helper calls may clobber
     * r0-r3, so ctx->usr_r[] becomes the canonical user register image.
     */
    stmfd   sp!, {r0-r3}
    load_current_task_local r12, r0  /* r12 = current task for this CPU */
    ldmfd   sp!, {r0-r3}
    cmp     r12, #0
    beq     syscall_no_current_task
    add     r12, r12, #TASK_CONTEXT_OFF   /* r12 = &current->context */

    /* Copy user-visible registers into ctx->usr_r[]. */
    str     r0,  [r12, #CTX_USR_R0]
    str     r1,  [r12, #CTX_USR_R1]
    str     r2,  [r12, #CTX_USR_R2]
    str     r3,  [r12, #CTX_USR_R3]
    str     r4,  [r12, #CTX_USR_R4]   /* user r4/r5 carry extra syscall args here */
    str     r5,  [r12, #CTX_USR_R5]
    str     r6,  [r12, #CTX_USR_R6]
    str     r7,  [r12, #CTX_USR_R7]
    str     r8,  [r12, #CTX_USR_R8]
    str     r9,  [r12, #CTX_USR_R9]
    str     r10, [r12, #CTX_USR_R10]
    str     r11, [r12, #CTX_USR_R11]

    /* Save syscall arguments before reusing scratch registers. */
    mov     r8, r0
    mov     r9, r1
    mov     r10, r2
    mov     r6, r3

    ldr     r0, [sp, #36]
    str     r0, [r12, #CTX_USR_R12]

    /*
     * 2) Capture banked state without calling out.
     * User SP/LR live in the USR/SYS bank, not in SVC. We briefly switch to
     * SYS mode to read them, then return to SVC before touching kernel state.
     */
    mrs     r0, spsr
    str     r0,  [r12, #CTX_USR_CPSR]  /* user CPSR */
    mov     r0,  lr
    str     r0,  [r12, #CTX_USR_PC]    /* user resume PC = LR_svc */

    cps     #0x1F                            /* switch to SYS mode to read user SP */
    mov     r0,  sp
    mov     r1,  lr
    cps     #0x13                            /* revenir en SVC */
    str     r0,  [r12, #CTX_USR_SP]
    str     r1,  [r12, #CTX_USR_LR]

    mov     r0,  #1
    str     r0,  [r12, #CTX_RET_TO_USER]   /* this SVC normally returns to user */

    mov   r0, sp
    str   r0, [r12, #CTX_SVC_SP]  /* SVC SP before the handler-local arg frame */
    str   r0, [r12, #CTX_SP]      /* initial kernel resume SP snapshot */

    /* Prepare the stack-passed arguments for syscall_handler. */
    sub   sp, sp, #12          /* 2 args + AAPCS alignment padding */
    str   r6, [sp, #0]         /* C arg4 = user r3 */
    str   r4, [sp, #4]         /* C arg5 = user r4 */

    mov     r0,  sp
    str     r0,  [r12, #CTX_SP]      /* authoritative SVC SP while in syscall */
    str     r0,  [r12, #CTX_SVC_SP]

    //push {r0-r3, lr}
    //mov r0, r12
    //bl debug_print_sp
    //pop {r0-r3, lr}


    /* First four C arguments in registers. */
    mov   r0, r7               /* syscall number */
    mov   r1, r8               /* arg1 */
    mov   r2, r9               /* arg2 */
    mov   r3, r10              /* arg3 */


    /* Enter the C syscall dispatcher. It may sleep, wait, or schedule away. */
    bl syscall_handler

    /* Signal delivery may replace the normal user-return path. */
    str r0, [sp, #8]
    bl signal_consume_user_return_override
    cmp r0, #0
    bne signal_user_return
    ldr r0, [sp, #8]
    
syscall_return:
    /*
     * r0 contains the syscall return value. Keep it aside while restoring the
     * saved SVC frame, then put it back in r0 just before exception return.
     */
    mov   r3, r0
    /* Drop the small syscall_handler argument frame. */
    add sp, sp, #12

    /* Restore the SPSR saved just above the callee-preserved register frame. */
    ldr     r12, [sp], #4       /* r12 = saved SPSR; sp advances by one word */
    msr     spsr_cxsf, r12

    /* Restore the SVC caller frame, including the old scratch registers. */
    ldmfd  sp!, {r4-r12, lr}

    //push {r0-r3, lr}
    //bl debug_print_sp3
    //pop {r0-r3, lr}

    /* Publish the syscall return value to user r0. */
    mov     r0, r3

    /* Syscall exit debug hook. */
    //push {r0-r3, lr}
    //bl debug_print_sp3
    //pop {r0-r3, lr}

    /* Exception-return to user mode. */
    movs pc, lr

signal_user_return:
    load_current_task_local r12, r2
    add     r12, r12, #TASK_CONTEXT_OFF

    /* Abandon the current SVC frame; ctx->usr_* now describes the return. */
    ldr     sp, [r12, #CTX_SVC_SP_TOP]
    ldr     r2, [r12, #CTX_USR_CPSR]
    msr     spsr_cxsf, r2

    cps     #0x1F
    ldr     sp, [r12, #CTX_USR_SP]
    ldr     lr, [r12, #CTX_USR_LR]
    cps     #0x13

    add     r10, r12, #CTX_USR_R0
    ldmia   r10, {r0-r9}
    ldr     r10, [r12, #CTX_USR_R10]
    ldr     lr, [r12, #CTX_USR_PC]
    ldr     r11, [r12, #CTX_USR_R11]
    ldr     r12, [r12, #CTX_USR_R12]
    movs    pc, lr

stack_panic:
    /* Basic stack-overflow fallback. */
    mov r0, #-12                /* -ENOMEM */
    b syscall_return

syscall_no_current_task:
    /*
     * Without a current task we cannot safely build ctx->usr_r[].  Return an
     * error instead of writing through NULL or a corrupted per-CPU slot.
     */
    mov r0, #-14                /* -EFAULT */
    sub sp, sp, #12
    b syscall_return

/* Signal trampoline: user signal return enters the dedicated syscall. */
signal_return_trampoline:
    mov r7, #__NR_rt_sigreturn  /* __NR_rt_sigreturn */
    swi #0
    
    /* If sigreturn fails, terminate the process. */
    mov r7, #1                  /* sys_exit */
    mov r0, #-1
    swi #0

/* Legacy/simple context-switch helper kept for diagnostics. */
.global context_switch_virt
context_switch_virt:
    /* Arguments: r0 = current_task, r1 = next_task */
    
    /* Basic pointer validation. */
    cmp r0, #0
    cmpne r1, #0
    bxeq lr                     /* Retour si pointeurs NULL */
    
    /* Save current user context. */
    stmia r0, {r0-r14}^
    mrs r2, spsr
    str r2, [r0, #60]
    
    /* Restore next user context. */
    ldr r2, [r1, #60]
    msr spsr_cxsf, r2
    ldmia r1, {r0-r14}^
    
    /* Change address space if needed. */
    ldr r2, [r1, #64]
    mrc p15, 0, r3, c2, c0, 0
    cmp r2, r3
    beq skip_ttbr_update
    
    mcr p15, 0, r2, c2, c0, 0
    
    /* Invalidate TLB only after a TTBR change. */
    mov r2, #0
    mcr p15, 0, r2, c8, c7, 0
    
skip_ttbr_update:
    /* Ordering barriers. */
    dsb
    isb
    
    /* Return into the new task. */
    movs pc, lr

/* User-context helper functions. */
.global save_user_context
save_user_context:
    /* Validate pointer. */
    cmp r0, #0
    bxeq lr
    
    /* Save user context. */
    stmia r0, {r0-r15}^
    mrs r1, spsr
    str r1, [r0, #64]
    
    bx lr

.global restore_user_context  
restore_user_context:
    /* Validate pointer. */
    cmp r0, #0
    bxeq lr
    
    /* Restore user context. */
    ldr r1, [r0, #64]
    msr spsr_cxsf, r1
    ldmia r0, {r0-r15}^
    bx lr

/* Minimal signal-frame setup helper. */
.global setup_signal_frame
setup_signal_frame:
    /* r0 = user_stack, r1 = signal_handler, r2 = signal_number */
    
    /* Build the signal frame on the user stack. */
    sub r0, r0, #256
    
    /* Save current user context into the frame. */
    stmia r0, {r0-r14}^
    mrs r3, spsr
    str r3, [r0, #60]
    
    /* Configure signal return. */
    ldr r3, =signal_return_trampoline
    str r3, [r0, #56]           /* LR = trampoline */
    
    /* Configure signal-handler arguments. */
    mov r3, r2                  /* r3 = signal_number */
    mov r2, #0                  /* siginfo = NULL for now */
    mov r1, #0                  /* ucontext = NULL for now */
    mov r0, r3                  /* r0 = signal_number */
    
    bx lr

/* Cache-management helper. */
.global flush_syscall_cache
flush_syscall_cache:
    /* Keep the usual order: data cache, barrier, instruction cache, TLB. */
    
    /* Data cache first. */
    mov r0, #0
    mcr p15, 0, r0, c7, c14, 0  /* Clean & Invalidate D-cache */
    
    /* Barrier before instruction-cache invalidation. */
    dsb sy
    
    /* Instruction cache. */
    mcr p15, 0, r0, c7, c5, 0   /* Invalidate I-cache */
    
    /* TLB last. */
    mcr p15, 0, r0, c8, c7, 0   /* Invalidate TLB */
    
    /* Endal barriers. */
    dsb sy
    isb
    
    bx lr

/* Optional performance counters. */
.global enable_performance_counters
enable_performance_counters:
    /* Check availability. */
    mrc p15, 0, r1, c0, c1, 2
    ands r1, r1, #0x7000000     /* Check cache levels */
    bxeq lr
    
    /* Enable counters. */
    mrc p15, 0, r0, c9, c12, 0
    orr r0, r0, #7              /* Enable + Reset cycles + Reset events */
    mcr p15, 0, r0, c9, c12, 0
    
    /* Enable the cycle counter. */
    mov r0, #0x80000000
    mcr p15, 0, r0, c9, c12, 1  /* PMCNTENSET */
    
    bx lr

.global read_cycle_counter
read_cycle_counter:
    mrc p15, 0, r0, c9, c13, 0  /* PMCCNTR */
    bx lr

.end
