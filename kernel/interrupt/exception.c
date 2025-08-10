#include <kernel/kernel.h>
#include <kernel/types.h>
#include <kernel/kprintf.h>
#include <kernel/debug_print.h>

// Implémentez ces handlers
void undefined_instruction_handler(void) {
    kprintf("=== UNDEFINED INSTRUCTION ===\n");
    uint32_t lr, spsr;
    asm volatile("mov %0, lr" : "=r"(lr));
    asm volatile("mrs %0, spsr" : "=r"(spsr));
    kprintf("UND LR: 0x%08X, SPSR: 0x%08X\n", lr, spsr);
    while(1);
}

void prefetch_abort_handler(void) {
    kprintf("=== PREFETCH ABORT ===\n");
    uint32_t lr, spsr, ifar;
    asm volatile("mov %0, lr" : "=r"(lr));
    asm volatile("mrs %0, spsr" : "=r"(spsr));
    asm volatile("mrc p15, 0, %0, c6, c0, 2" : "=r"(ifar)); // IFAR
    kprintf("PABT LR: 0x%08X, SPSR: 0x%08X, IFAR: 0x%08X\n", lr, spsr, ifar);
    while(1);
}

void data_abort_handler(void)
{
    kprintf("[ERROR] === REGISTER DUMP ===\n");
    
    uint32_t r0, r1, r2, r3, r4;
    __asm__ volatile(
        "str r0, %0\n"
        "str r1, %1\n" 
        "str r2, %2\n"
        "str r3, %3\n"
        "str r4, %4\n"
        : "=m"(r0), "=m"(r1), "=m"(r2), "=m"(r3), "=m"(r4)
    );
    
    kprintf("[ERROR] R0=0x%08X\n", r0);
    kprintf("[ERROR] R1=0x%08X\n", r1);
    kprintf("[ERROR] R2=0x%08X\n", r2);
    kprintf("[ERROR] R3=0x%08X\n", r3);
    kprintf("[ERROR] R4=0x%08X\n", r4);


    kprintf("[ERROR] === INSTRUCTION ANALYSIS ===\n");
    
    uint32_t lr;
    __asm__ volatile("mov %0, lr" : "=r"(lr));
    
    // Pour data abort, l'instruction fautive est à LR-8
    uint32_t fault_pc = lr - 8;
    kprintf("[ERROR] Fault PC (LR-8): 0x%08X\n", fault_pc);
    
    // Lire l'instruction fautive
    if (fault_pc >= 0x40010000 && fault_pc < 0x40050000) {
        uint32_t instruction = *(volatile uint32_t *)fault_pc;
        kprintf("[ERROR] Fault instruction: 0x%08X\n", instruction);
        
        // Décoder le type d'instruction ARM
        if ((instruction & 0x0C000000) == 0x04000000) {
            // LDR/STR instruction
            kprintf("[ERROR] -> LDR/STR instruction\n");
            
            uint32_t rn = (instruction >> 16) & 0xF;  // Base register
            uint32_t rd = (instruction >> 12) & 0xF;  // Destination register
            bool is_load = (instruction & 0x00100000) != 0;
            
            kprintf("[ERROR] -> %s R%d, [R%d + offset]\n", 
                    is_load ? "LDR" : "STR", rd, rn);
        }
    }


    kprintf("[ERROR] === MEMORY LAYOUT ANALYSIS ===\n");
    
    extern uint32_t __start, __end;
    extern uint32_t __bss_start, __bss_end;
    
    uint32_t kernel_start = (uint32_t)&__start;
    uint32_t kernel_end = (uint32_t)&__end;
    uint32_t bss_start = (uint32_t)&__bss_start;
    uint32_t bss_end = (uint32_t)&__bss_end;
    uint32_t lr_register = 0;

    __asm__ volatile("mov %0, lr" : "=r"(lr_register));
    
    kprintf("[ERROR] Kernel:    0x%08X - 0x%08X\n", kernel_start, kernel_end);
    kprintf("[ERROR] BSS:       0x%08X - 0x%08X\n", bss_start, bss_end);
    kprintf("[ERROR] Corrupt LR: 0x%08X\n", lr_register);
    
    // Vérifier si LR est dans une zone connue
    if (lr_register >= kernel_start && lr_register < kernel_end) {
        kprintf("[ERROR] LR in kernel range\n");
    } else if (lr_register >= bss_start && lr_register < bss_end) {
        kprintf("[ERROR] LR in BSS range\n");
    } else {
        kprintf("[ERROR] LR COMPLETELY OUTSIDE VALID MEMORY!\n");
    }

    uint32_t current_sp;
    __asm__ volatile("mov %0, sp" : "=r"(current_sp));
    
    uint32_t cpsr;
    __asm__ volatile("mrs %0, cpsr" : "=r"(cpsr));
    
    kprintf("DATA ABORT - Mode: 0x%02X, SP: 0x%08X\n", 
            cpsr & 0x1F, current_sp);
    
    // Vérifier si SP est dans une zone valide
    extern uint32_t __stack_bottom, __stack_top;
    extern uint32_t __abt_stack_bottom, __abt_stack_top;
    
    bool sp_valid = false;
    if (current_sp >= (uint32_t)&__stack_bottom && 
        current_sp <= (uint32_t)&__stack_top) {
        kprintf("SP in main kernel stack\n");
        sp_valid = true;
    }
    
    if (current_sp >= (uint32_t)&__abt_stack_bottom && 
        current_sp <= (uint32_t)&__abt_stack_top) {
        kprintf("SP in ABT stack\n");  
        sp_valid = true;
    }
    
    if (!sp_valid) {
        kprintf("ERROR: SP not in any valid stack!\n");
    }


    uint32_t dfar, dfsr, sp;
    
    /* Lire les registres de faute */
    __asm__ volatile("mrc p15, 0, %0, c6, c0, 0" : "=r"(dfar));  /* DFAR */
    __asm__ volatile("mrc p15, 0, %0, c5, c0, 0" : "=r"(dfsr));  /* DFSR */
    __asm__ volatile("mov %0, lr" : "=r"(lr));
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    
    KERROR("=== DATA ABORT ANALYSIS ===\n");
    KERROR("DFAR (fault addr): 0x%08X\n", dfar);
    KERROR("DFSR (fault stat): 0x%08X\n", dfsr);
    KERROR("LR (return addr):  0x%08X\n", lr);
    KERROR("SP (stack ptr):    0x%08X\n", sp);
    
    /* Analyser le type de faute */
    uint32_t fault_type = dfsr & 0xF;
    KERROR("Fault type: ");
    switch (fault_type) {
        case 0x5: KERROR("Translation fault (section)\n"); break;
        case 0x7: KERROR("Translation fault (page)\n"); break;
        case 0x3: KERROR("Access flag fault (section)\n"); break;
        case 0x6: KERROR("Access flag fault (page)\n"); break;
        case 0x9: KERROR("Domain fault (section)\n"); break;
        case 0xB: KERROR("Domain fault (page)\n"); break;
        case 0xD: KERROR("Permission fault (section)\n"); break;
        case 0xF: KERROR("Permission fault (page)\n"); break;
        default: KERROR("Unknown fault type 0x%X\n", fault_type); break;
    }
    
    /* Vérifier si l'adresse est dans une plage connue */
    if (dfar >= 0x40000000 /*&& dfar < 0x140000000*/) {
        KERROR("Fault in valid RAM range\n");
    } else if (dfar >= 0x08000000 && dfar < 0x40000000) {
        KERROR("Fault in device/peripheral range\n");
    } else {
        KERROR("Fault in INVALID memory range!\n");
    }
    
    panic("Unhandled Data Abort");
}