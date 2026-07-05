/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/interrupt/exception.c
 * Layer: Kernel / interrupts and exceptions
 *
 * Responsibilities:
 * - Handle IRQs, timer ticks, aborts, and crash diagnostics.
 * - Keep exception reports actionable during early kernel debugging.
 *
 * Notes:
 * - Handlers run in privileged exception modes with banked registers.
 */

#include <kernel/kernel.h>
#include <kernel/types.h>
#include <kernel/kprintf.h>
#include <kernel/debug_print.h>
#include <asm/arm.h>
#include <kernel/uart.h>
#include <kernel/process.h>
#include <kernel/task.h>
#include <kernel/memory.h>
#include <kernel/signal.h>
#include <kernel/syscalls.h>
#include <kernel/file.h>
#include <kernel/string.h>

static DEFINE_SPINLOCK(exception_log_lock);

// Implémentez ces handlers
void undefined_instruction_handler(void) {
    /* Capturer AVANT tout appel : bl ecrase lr.
     * lr_und = adresse instruction fautive + 4.
     * lr_svc/sp_svc (banques, virt ext A15) = etat SVC au moment du saut. */
    uint32_t lr, spsr, lr_svc, sp_svc;
    asm volatile("mov %0, lr" : "=r"(lr));
    asm volatile("mrs %0, spsr" : "=r"(spsr));
    asm volatile("mrs %0, lr_svc" : "=r"(lr_svc));
    asm volatile("mrs %0, sp_svc" : "=r"(sp_svc));

    kprintf("=== UNDEFINED INSTRUCTION ===\n");
    kprintf("UND LR: 0x%08X (PC fautif=0x%08X), SPSR: 0x%08X\n", lr, lr - 4, spsr);
    task_t* task = task_current_local();
    kprintf("LR_svc: 0x%08X SP_svc: 0x%08X current_task=%p (%s)\n",
            lr_svc, sp_svc, (void*)task,
            task ? task->name : "?");
    while(1);
}

/* void prefetch_abort_handler(void) {
    kprintf("=== PREFETCH ABORT ===\n");
    uint32_t lr, spsr, ifar;
    asm volatile("mov %0, lr" : "=r"(lr));
    asm volatile("mrs %0, spsr" : "=r"(spsr));
    asm volatile("mrc p15, 0, %0, c6, c0, 2" : "=r"(ifar)); // IFAR
    kprintf("PABT LR: 0x%08X, SPSR: 0x%08X, IFAR: 0x%08X\n", lr, spsr, ifar);
    while(1);
} */

static inline uint32_t ifsr_status5(uint32_t ifsr) {
    return (ifsr & 0xF) | ((ifsr >> 6) & 0x10); // [3:0] + bit10→bit4
}

static const char* ifsr_str(uint32_t s) {
    switch (s) {
        case 0x05: return "Translation fault, L1";
        case 0x07: return "Translation fault, L2";
        case 0x03: return "Access flag fault, L1";
        case 0x06: return "Access flag fault, L2";
        case 0x04: return "Domain fault, L1";
        case 0x09: return "Domain fault, L2";
        case 0x0D: return "Permission fault, L1";
        case 0x0F: return "Permission fault, L2"; // (inclut XN pour PABT)
        case 0x08: return "Sync ext abort on TT walk";
        case 0x0C: return "Sync external abort";
        default:   return "Unknown/implementation-defined";
    }
}

typedef struct {
    uint32_t l1_desc;
    uint32_t l2_desc;
    int has_l2;
    uint32_t l1_index, l2_index;
    paddr_t l1_base, l2_base;
} pte_probe_t;

typedef struct {
    uint32_t magic;     // 0xDEADBEEF si rempli
    uint32_t ctx_ptr;   // &context (tel qu’on le pense)
    uint32_t spsr_set;  // valeur SPSR écrite (après msr)
    uint32_t spsr_now;  // mrs spsr juste avant le saut
    uint32_t lr_svc;    // LR_svc juste avant MOVS
    uint32_t lr_usr;    // valeur réelle de LR banké user
    uint32_t sp_usr;    // (optionnel) SP banké user
} rtusr_snap_t;

volatile rtusr_snap_t g_rtusr_snap;

void dump_rtusr_snapshot(void) {
    uart_puts("\n-- RTUSR SNAP --\n");
    uart_puts("magic=");    uart_put_hex(g_rtusr_snap.magic);
    uart_puts(" ctx=");     uart_put_hex(g_rtusr_snap.ctx_ptr);
    uart_puts(" spsr_set=");uart_put_hex(g_rtusr_snap.spsr_set);
    uart_puts(" spsr_now=");uart_put_hex(g_rtusr_snap.spsr_now);
    uart_puts(" lr_svc=");  uart_put_hex(g_rtusr_snap.lr_svc);
    uart_puts(" lr_usr=");  uart_put_hex(g_rtusr_snap.lr_usr);
    uart_puts(" sp_usr=");  uart_put_hex(g_rtusr_snap.sp_usr);
    uart_puts("\n");
}

static pte_probe_t probe_pte(paddr_t ttbr0, vaddr_t va) {
    pte_probe_t p = {0};
    paddr_t l1_base = ttbr0 & ~0x3FFFu;       // TTBR0 short-desc: 16KB align
    uint32_t l1_index = (va >> 20) & 0xFFF;   // 4KB entries, 1MB per entry
    uint32_t *l1 = (uint32_t*)phys_to_virt(l1_base);
    uint32_t l1d = l1[l1_index];

    p.l1_base = l1_base;
    p.l1_index = l1_index;
    p.l1_desc = l1d;

    uint32_t l1_type = l1d & 0x3;
    if (l1_type == 0x2) {
        // Section/Supersection: pas de L2
        p.has_l2 = 0;
    } else if (l1_type == 0x1) {
        // Coarse page table -> L2
        paddr_t l2_base = l1d & ~0x3FFu;      // bits [31:10]
        uint32_t l2_index = (va >> 12) & 0xFF;
        uint32_t *l2 = (uint32_t*)phys_to_virt(l2_base);
        uint32_t l2d = l2[l2_index];
        p.has_l2 = 1;
        p.l2_base = l2_base;
        p.l2_index = l2_index;
        p.l2_desc = l2d;
    } else {
        // Fault or reserved
        p.has_l2 = 0;
    }
    return p;
}

static const char* l1_type_str(uint32_t d) {
    switch (d & 0x3) {
        case 0x0: return "L1: Fault";
        case 0x1: return "L1: Page Table (coarse)";
        case 0x2: return "L1: Section/Supersection";
        case 0x3: return "L1: Reserved";
    }
    return "?";
}
static const char* l2_type_str(uint32_t d) {
    switch (d & 0x3) {
        case 0x0: return "L2: Fault";
        case 0x1: return "L2: Large page (64KB)";
        case 0x2: return "L2: Small page (XN-free format)";
        case 0x3: return "L2: Small page (XN in bit0)";
    }
    return "?";
}

// Helpers (best-effort) pour XN/AP (short descriptor)
// Section: XN = bit4 ; AP[2] = bit15 ; AP[1:0] = bits[11:10]
// Small page (desc==0b11) : XN = bit0 ; AP[2]=bit9 ; AP[1:0]=bits[5:4]
static int section_xn(uint32_t l1d) { return (l1d >> 4) & 1; }
static int smallpage_xn(uint32_t l2d) { 
    if ((l2d & 3) == 3) return l2d & 1; // format avec XN
    return 0; // format sans XN
}


__attribute__((noinline))
void prefetch_abort_handler(void) {
    /* Capturer les registres banqués AVANT tout appel (bl écrase lr).
     * MRS banked (lr_svc/sp_svc) dispo sur Cortex-A15 (virt extensions). */
    uint32_t lr_svc, sp_svc, spsr_svc;
    unsigned long log_flags;

    __asm__ volatile("mrs %0, lr_svc" : "=r"(lr_svc));
    __asm__ volatile("mrs %0, sp_svc" : "=r"(sp_svc));
    __asm__ volatile("mrs %0, spsr" : "=r"(spsr_svc));

    spin_lock_irqsave(&exception_log_lock, &log_flags);

    uart_puts("=== PREFETCH ABORT ===\n");
    uart_puts("SP_svc="); uart_put_hex(sp_svc);
    uart_puts(" current_task="); uart_put_hex((uint32_t)task_current_local());
    uart_puts("\n");

    uint32_t ifsr = get_ifsr();
    uint32_t ifar = get_ifar();
    uint32_t sctlr = get_sctlr();
    uint32_t ttbcr = get_ttbcr();
    uint32_t ttbr0 = get_ttbr0();
    uint32_t ttbr1 = get_ttbr1();
    uint32_t dacr  = get_dacr();

    uint32_t status = ifsr_status5(ifsr);

    //dump_rtusr_snapshot();

    uart_puts("LR_svc="); uart_put_hex(lr_svc);
    uart_puts(" SPSR_svc="); uart_put_hex(spsr_svc);
    uart_puts(" (mode="); uart_put_hex(spsr_svc & 0x1F);
    uart_puts(" T="); uart_put_dec((spsr_svc>>5)&1); uart_puts(")\n");

    uart_puts("IFSR="); uart_put_hex(ifsr);
    uart_puts(" status="); uart_put_hex(status);
    uart_puts(" ("); uart_puts(ifsr_str(status)); uart_puts(")\n");
    uart_puts("IFAR="); uart_put_hex(ifar); uart_puts("\n");

    uart_puts("SCTLR="); uart_put_hex(sctlr);
    uart_puts(" TTBCR="); uart_put_hex(ttbcr);
    uart_puts(" TTBR0="); uart_put_hex(ttbr0);
    uart_puts(" TTBR1="); uart_put_hex(ttbr1);
    uart_puts(" DACR="); uart_put_hex(dacr); uart_puts("\n");

    // Probe des PTE (dans l’espace courant -> TTBR0)
    uint32_t tt_sel = ifar >> (32 - 2);      // N = 2
    uint32_t ttbr = (tt_sel == 0) ? ttbr0 : ttbr1;
    pte_probe_t p = probe_pte(ttbr, ifar);

    uart_puts("L1["); uart_put_dec(p.l1_index); uart_puts("] @");
    uart_put_hex(p.l1_base); uart_puts(": ");
    uart_put_hex(p.l1_desc); uart_puts(" (");
    uart_puts(l1_type_str(p.l1_desc)); uart_puts(")\n");

    if ((p.l1_desc & 3) == 2) {
        // Section: check XN
        uart_puts("  Section XN="); uart_put_dec(section_xn(p.l1_desc)); uart_puts("\n");
    } else if ((p.l1_desc & 3) == 1) {
        uart_puts("  L2 base="); uart_put_hex(p.l2_base);
        uart_puts(" idx="); uart_put_dec(p.l2_index); uart_puts("\n");
        uart_puts("  L2 desc="); uart_put_hex(p.l2_desc); uart_puts(" (");
        uart_puts(l2_type_str(p.l2_desc)); uart_puts(")\n");
        if ((p.l2_desc & 3) == 3 || (p.l2_desc & 3) == 2) {
            uart_puts("  SmallPage XN="); uart_put_dec(smallpage_xn(p.l2_desc)); uart_puts("\n");
        }
    }

    while (1) { /* stop with the diagnostic log lock held */ }
}


/* ATS1CPR: translate VA as privileged read; PAR returns PA or fault status */
static inline uint32_t ats1cpr(uint32_t va){
    uint32_t par;
    asm volatile(
        "mcr p15,0,%1,c7,c8,0\n"   /* ATS1CPR */
        "isb\n"
        "mrc p15,0,%0,c7,c4,0\n"   /* PAR */
        : "=r"(par) : "r"(va) : "memory");
    return par;
}

static const char* dfsr_string(uint32_t dfsr) {
    uint32_t fs = ((dfsr >> 10) & 1) << 4 | (dfsr & 0xF);
    switch (fs) {
        case 0x01: return "Alignment fault";
        case 0x05: return "Translation fault (Section)";
        case 0x07: return "Translation fault (Page)";
        case 0x09: return "Domain fault (Section)";
        case 0x0B: return "Domain fault (Page)";
        case 0x0D: return "Permission fault (Section)";
        case 0x0F: return "Permission fault (Page)";
        case 0x08: return "Precise external abort";
        default:   return "Other/impl.-def.";
    }
}

static inline bool spsr_thumb(uint32_t spsr){ return (spsr & (1u<<5)) != 0; }

static inline bool exception_from_user(uint32_t spsr)
{
    return (spsr & ARM_CPSR_MODE) == ARM_MODE_USR;
}

static inline paddr_t pick_ttbr(vaddr_t va, uint32_t ttbcr);

typedef struct {
    uint32_t spsr_abt;
    uint32_t dfar;
    uint32_t dfsr;
    uint32_t fault_pc;
    uint32_t lr_abt;
    uint32_t saved[6];
    bool coredump_queued;
    char dump_path[32];
} user_fault_snapshot_t;

#define COREDUMP_QUEUE_SIZE 8
#define COREDUMP_WORD_COUNT 8

typedef struct {
    vaddr_t va;
    paddr_t phys;
    uint32_t value;
    bool mapped;
} coredump_word_t;

typedef struct {
    vaddr_t va;
    uint32_t ttbr;
    uint32_t ttbcr;
    paddr_t l1_addr;
    uint32_t l1_desc;
    paddr_t l2_base;
    paddr_t l2_addr;
    uint32_t l2_desc;
    paddr_t section_pa;
    uint32_t domain;
    paddr_t l2_pa;
    uint32_t ap2;
    uint32_t ap;
    uint32_t xn;
    uint32_t texcb;
    uint32_t kind;
} coredump_walk_t;

typedef struct {
    bool valid;
    uint32_t seq;
    int pid;
    char task_name[TASK_NAME_MAX];
    uint32_t spsr_abt;
    uint32_t dfar;
    uint32_t dfsr;
    uint32_t fault_pc;
    uint32_t lr_abt;
    uint32_t saved[6];
    uint32_t ttbr0;
    uint32_t asid;
    uint32_t brk;
    uint32_t sctlr;
    uint32_t dacr;
    uint32_t pc_par;
    uint32_t dfar_par;
    coredump_walk_t dfar_walk;
    coredump_walk_t pc_walk;
    coredump_word_t text_words[COREDUMP_WORD_COUNT];
    coredump_word_t fault_words[COREDUMP_WORD_COUNT];
    char path[32];
} coredump_event_t;

static DEFINE_SPINLOCK(coredump_lock);
static coredump_event_t coredump_queue[COREDUMP_QUEUE_SIZE];
static uint32_t coredump_head;
static uint32_t coredump_tail;
static uint32_t coredump_count;
static uint32_t coredump_seq;
static task_t* coredumpd_task;

static bool user_va_to_phys(task_t* task, vaddr_t va, paddr_t* phys_out)
{
    paddr_t phys;

    if (!task || task->type != TASK_TYPE_PROCESS || !task->process ||
        !task->process->vm || !task->process->vm->pgdir) {
        return false;
    }

    if (va >= USER_SPACE_END) {
        return false;
    }

    phys = get_phys_addr_from_pgdir(task->process->vm->pgdir, va);
    if (!phys) {
        return false;
    }

    *phys_out = phys;
    return true;
}

static void coredump_capture_words(coredump_word_t* words, task_t* task, vaddr_t center)
{
    vaddr_t start = center >= 16 ? (center - 16) & ~3u : 0;

    for (uint32_t i = 0; i < COREDUMP_WORD_COUNT; i++) {
        vaddr_t va = start + i * 4;
        paddr_t phys = 0;

        words[i].va = va;
        words[i].phys = 0;
        words[i].value = 0;
        words[i].mapped = false;

        if (user_va_to_phys(task, va, &phys)) {
            words[i].phys = phys;
            words[i].value = *(volatile uint32_t*)phys_to_virt(phys);
            words[i].mapped = true;
        }
    }
}

static void coredump_capture_walk(coredump_walk_t* walk, vaddr_t va)
{
    uint32_t ttbcr = get_ttbcr();
    paddr_t ttbr  = pick_ttbr(va, ttbcr);
    paddr_t l1_base = ttbr & ~0x3FFFu;
    uint32_t l1_idx  = (va >> 20) & 0xFFF;
    paddr_t l1_addr = l1_base + 4 * l1_idx;
    uint32_t *l1_ptr = (uint32_t*)phys_to_virt(l1_addr);
    uint32_t l1 = *l1_ptr;

    memset(walk, 0, sizeof(*walk));
    walk->va = va;
    walk->ttbr = ttbr;
    walk->ttbcr = ttbcr;
    walk->l1_addr = l1_addr;
    walk->l1_desc = l1;

    if ((l1 & 3) == 2) {
        walk->kind = 2;
        walk->section_pa = l1 & 0xFFF00000;
        walk->domain = (l1 >> 5) & 0xF;
        return;
    }

    if ((l1 & 3) == 1) {
        paddr_t l2_base = l1 & ~0x3FFu;
        uint32_t l2_idx  = (va >> 12) & 0xFF;
        paddr_t l2_addr = l2_base + 4 * l2_idx;
        uint32_t *l2_ptr = (uint32_t*)phys_to_virt(l2_addr);
        uint32_t l2 = *l2_ptr;
        uint32_t l2_type = l2 & 3;

        walk->kind = 1;
        walk->l2_base = l2_base;
        walk->l2_addr = l2_addr;
        walk->l2_desc = l2;

        if ((l2_type & 2) == 0) {
            walk->kind = 3;
            return;
        }

        walk->kind = 4;
        walk->l2_pa = l2 & 0xFFFFF000;
        walk->ap2 = (l2 >> 9) & 1;
        walk->ap = (l2 >> 4) & 3;
        walk->xn = l2 & 1;
        walk->texcb = (((l2 >> 6) & 7) << 2) |
                      (((l2 >> 3) & 1) << 1) |
                      ((l2 >> 2) & 1);
        return;
    }

    walk->kind = 0;
}

static void coredump_capture_event(coredump_event_t* event,
                                   uint32_t spsr_abt,
                                   uint32_t dfar,
                                   uint32_t dfsr,
                                   uint32_t fault_pc,
                                   uint32_t lr_abt,
                                   uint32_t* saved)
{
    task_t* task = task_current_local();
    process_t* proc = (task && task->type == TASK_TYPE_PROCESS) ? task->process : NULL;

    memset(event, 0, sizeof(*event));
    event->pid = proc ? proc->pid : -1;
    snprintf(event->path, sizeof(event->path), "/tmp/%d.dump", event->pid);
    strncpy(event->task_name, task ? task->name : "?", sizeof(event->task_name) - 1);
    event->task_name[sizeof(event->task_name) - 1] = '\0';
    event->spsr_abt = spsr_abt;
    event->dfar = dfar;
    event->dfsr = dfsr;
    event->fault_pc = fault_pc;
    event->lr_abt = lr_abt;
    memcpy(event->saved, saved, sizeof(event->saved));
    event->sctlr = get_sctlr();
    event->dacr = get_dacr();
    event->pc_par = ats1cpr(fault_pc);
    event->dfar_par = ats1cpr(dfar);

    if (proc && proc->vm) {
        event->ttbr0 = (uint32_t)proc->vm->pgdir;
        event->asid = proc->vm->asid;
        event->brk = proc->vm->brk;
    }

    coredump_capture_walk(&event->dfar_walk, dfar);
    coredump_capture_walk(&event->pc_walk, fault_pc);
    coredump_capture_words(event->text_words, task, fault_pc);
    coredump_capture_words(event->fault_words, task, dfar);
}

static bool coredump_enqueue(uint32_t spsr_abt,
                             uint32_t dfar,
                             uint32_t dfsr,
                             uint32_t fault_pc,
                             uint32_t lr_abt,
                             uint32_t* saved,
                             char* out_path,
                             size_t out_path_size)
{
    coredump_event_t event;
    unsigned long flags;

    coredump_capture_event(&event, spsr_abt, dfar, dfsr, fault_pc, lr_abt, saved);

    spin_lock_irqsave(&coredump_lock, &flags);
    if (coredump_count >= COREDUMP_QUEUE_SIZE) {
        spin_unlock_irqrestore(&coredump_lock, flags);
        if (out_path && out_path_size)
            out_path[0] = '\0';
        return false;
    }

    event.valid = true;
    event.seq = ++coredump_seq;
    coredump_queue[coredump_tail] = event;
    coredump_tail = (coredump_tail + 1) % COREDUMP_QUEUE_SIZE;
    coredump_count++;
    spin_unlock_irqrestore(&coredump_lock, flags);

    if (out_path && out_path_size) {
        strncpy(out_path, event.path, out_path_size - 1);
        out_path[out_path_size - 1] = '\0';
    }

    if (coredumpd_task)
        task_wake(coredumpd_task);
    return true;
}

static bool coredump_dequeue(coredump_event_t* event)
{
    unsigned long flags;

    spin_lock_irqsave(&coredump_lock, &flags);
    if (coredump_count == 0) {
        spin_unlock_irqrestore(&coredump_lock, flags);
        return false;
    }

    *event = coredump_queue[coredump_head];
    coredump_queue[coredump_head].valid = false;
    coredump_head = (coredump_head + 1) % COREDUMP_QUEUE_SIZE;
    coredump_count--;
    spin_unlock_irqrestore(&coredump_lock, flags);
    return true;
}

static bool coredump_path_is_tmp_file(const char* path)
{
    const char* name;

    if (!path || strncmp(path, "/tmp/", 5) != 0) {
        return false;
    }

    name = path + 5;
    if (*name == '\0') {
        return false;
    }

    while (*name) {
        if (*name == '/') {
            return false;
        }
        name++;
    }

    return true;
}

static void core_write(int fd, const char* text)
{
    if (fd >= 0 && text) {
        sys_write(fd, text, strlen(text));
    }
}

static void core_printf(int fd, const char* fmt, ...)
{
    char line[256];
    va_list args;
    int len;

    if (fd < 0) {
        return;
    }

    va_start(args, fmt);
    len = vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);

    if (len < 0) {
        return;
    }
    if ((size_t)len >= sizeof(line)) {
        len = sizeof(line) - 1;
    }

    sys_write(fd, line, (size_t)len);
}

static void coredump_write_words_to_file(int fd, const char* label,
                                         uint32_t center,
                                         const coredump_word_t* words)
{
    core_printf(fd, "%s around 0x%08X\n", label, center);

    for (uint32_t i = 0; i < COREDUMP_WORD_COUNT; i++) {
        if (words[i].mapped) {
            core_printf(fd, "  0x%08X: 0x%08X  phys=0x%08X\n",
                        words[i].va, words[i].value, words[i].phys);
        } else {
            core_printf(fd, "  0x%08X: <unmapped>\n", words[i].va);
        }
    }
}

static void coredump_write_walk_to_file(int fd, const coredump_walk_t* walk)
{
    core_printf(fd, "TTBR=0x%08X TTBCR=0x%08X L1@0x%08X = 0x%08X\n",
                walk->ttbr, walk->ttbcr, walk->l1_addr, walk->l1_desc);

    if (walk->kind == 2) {
        core_printf(fd, "  L1: SECTION PA=0x%08X domain=0x%08X AP/TEX/C/B decoded in section bits\n",
                    walk->section_pa, walk->domain);
        return;
    }

    if (walk->kind == 1 || walk->kind == 3 || walk->kind == 4) {
        core_printf(fd, "  L1: COARSE L2 @0x%08X  L2@0x%08X = 0x%08X\n",
                    walk->l2_base, walk->l2_addr, walk->l2_desc);

        if (walk->kind == 3) {
            core_write(fd, "  L2: Fault/invalid\n");
            return;
        }

        if (walk->kind == 4) {
            core_printf(fd, "  L2: SMALL PA=0x%08X AP2=0x%08X AP=0x%08X XN=0x%08X TEX/C/B=0x%08X\n",
                        walk->l2_pa, walk->ap2, walk->ap, walk->xn, walk->texcb);
        }
        return;
    }

    core_write(fd, "  L1: Fault/Reserved type\n");
}

static void coredump_write_event_to_file(const coredump_event_t* event)
{
    char* open_path;
    int fd;
    task_t* task = task_current_local();
    process_t* proc = task ? task->process : NULL;
    mode_t old_umask = proc ? proc->umask : 0;

    if (!coredump_path_is_tmp_file(event->path)) {
        return;
    }

    open_path = strdup(event->path);
    if (!open_path) {
        return;
    }

    /*
     * Coredumps are diagnostic artifacts. Create them world-readable/writable
     * without poking filesystem internals after creation; let kernel_open()
     * apply the normal umask path with a temporary zero umask.
     */
    if (proc) {
        proc->umask = 0;
    }
    fd = kernel_open(open_path, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (proc) {
        proc->umask = old_umask;
    }
    if (fd < 0) {
        return;
    }

    core_write(fd, "=== USER SEGFAULT ===\n");
    core_printf(fd, "signal=SIGSEGV pid=%d task=%s\n", event->pid, event->task_name);
    core_printf(fd, "PC=0x%08X DFAR=0x%08X DFSR=0x%08X (%s) SPSR=0x%08X\n",
                event->fault_pc, event->dfar, event->dfsr,
                dfsr_string(event->dfsr), event->spsr_abt);
    core_printf(fd, "LR_abt=0x%08X mode=0x%08X thumb=%u\n",
                event->lr_abt, event->spsr_abt & 0x1F,
                spsr_thumb(event->spsr_abt) ? 1 : 0);
    core_printf(fd, "saved r0=0x%08X r1=0x%08X r2=0x%08X r3=0x%08X r12=0x%08X lr_abt=0x%08X\n",
                event->saved[0], event->saved[1], event->saved[2],
                event->saved[3], event->saved[4], event->saved[5]);

    core_printf(fd, "TTBR0=0x%08X ASID=0x%08X BRK=0x%08X\n",
                event->ttbr0, event->asid, event->brk);

    if ((event->pc_par & 1) == 0) {
        core_printf(fd, "PC->PAR OK, phys=0x%08X\n",
                    (event->pc_par & 0xFFFFF000) | (event->fault_pc & 0xFFF));
    } else {
        core_printf(fd, "PC->PAR FAULT fs=0x%08X\n", (event->pc_par >> 1) & 0x3F);
    }

    if ((event->dfar_par & 1) == 0) {
        core_printf(fd, "DFAR->PAR OK, phys=0x%08X\n",
                    (event->dfar_par & 0xFFFFF000) | (event->dfar & 0xFFF));
    } else {
        core_printf(fd, "DFAR->PAR FAULT fs=0x%08X\n", (event->dfar_par >> 1) & 0x3F);
    }

    core_printf(fd, "SCTLR=0x%08X DACR=0x%08X\n", event->sctlr, event->dacr);

    core_printf(fd, "Walk for DFAR=0x%08X\n", event->dfar);
    coredump_write_walk_to_file(fd, &event->dfar_walk);
    core_printf(fd, "Walk for PC=0x%08X\n", event->fault_pc);
    coredump_write_walk_to_file(fd, &event->pc_walk);

    coredump_write_words_to_file(fd, "User text", event->fault_pc, event->text_words);
    coredump_write_words_to_file(fd, "Fault address", event->dfar, event->fault_words);

    sys_close(fd);
}

static void coredumpd_main(void* arg)
{
    coredump_event_t event;

    (void)arg;

    while (1) {
        while (coredump_dequeue(&event)) {
            if (event.valid) {
                coredump_write_event_to_file(&event);
            }
        }

        task_sleep_ms(100);
    }
}

int coredumpd_start(void)
{
    process_t* vfs_context;

    if (coredumpd_task) {
        return 0;
    }

    coredumpd_task = task_create_process("coredumpd", coredumpd_main, NULL,
                                         20, TASK_TYPE_KERNEL);
    if (!coredumpd_task) {
        return -ENOMEM;
    }

    /*
     * coredumpd is a kernel thread, but the current VFS helpers use
     * current_task->process for FD tables, permissions and umask. Give the
     * worker a tiny daemon-owned VFS context scoped by code to /tmp dumps
     * instead of making it a privileged user process.
     */
    vfs_context = (process_t*)kmalloc(sizeof(process_t));
    if (!vfs_context) {
        task_destroy(coredumpd_task);
        coredumpd_task = NULL;
        return -ENOMEM;
    }
    memset(vfs_context, 0, sizeof(*vfs_context));
    vfs_context->uid = 2; /* daemon */
    vfs_context->gid = 2; /* daemon */
    vfs_context->umask = 0;
    vfs_context->state = (proc_state_t)PROC_READY;
    strcpy(vfs_context->cwd, "/tmp");

    coredumpd_task->process = vfs_context;
    coredumpd_task->context.is_first_run = 1;
    coredumpd_task->context.ttbr0 = (uint32_t)ttbr0_pgdir;
    coredumpd_task->context.asid = ASID_KERNEL;
    coredumpd_task->context.returns_to_user = 0;
    add_to_ready_queue(coredumpd_task);
    return 0;
}

static user_fault_snapshot_t* user_fault_build_snapshot_on_svc_stack(task_t* task,
                                                                     uint32_t spsr_abt,
                                                                     uint32_t dfar,
                                                                     uint32_t dfsr,
                                                                     uint32_t fault_pc,
                                                                     uint32_t lr_abt,
                                                                     uint32_t* saved,
                                                                     bool coredump_queued,
                                                                     const char* dump_path,
                                                                     uint32_t* svc_sp_out)
{
    vaddr_t top;
    vaddr_t sp;
    user_fault_snapshot_t* snap;

    if (!task || !task->stack_base || !task->stack_top) {
        return NULL;
    }

    top = task->context.svc_sp_top ? (vaddr_t)task->context.svc_sp_top : (vaddr_t)(uintptr_t)task->stack_top;
    sp = (top - 512 - sizeof(user_fault_snapshot_t)) & ~7u;

    if (sp <= (vaddr_t)(uintptr_t)task->stack_base || sp >= (vaddr_t)(uintptr_t)task->stack_top) {
        return NULL;
    }

    snap = (user_fault_snapshot_t*)(uintptr_t)sp;
    snap->spsr_abt = spsr_abt;
    snap->dfar = dfar;
    snap->dfsr = dfsr;
    snap->fault_pc = fault_pc;
    snap->lr_abt = lr_abt;
    memcpy(snap->saved, saved, sizeof(snap->saved));
    snap->coredump_queued = coredump_queued;
    if (dump_path) {
        strncpy(snap->dump_path, dump_path, sizeof(snap->dump_path) - 1);
        snap->dump_path[sizeof(snap->dump_path) - 1] = '\0';
    } else {
        snap->dump_path[0] = '\0';
    }

    task->context.sp = sp;
    task->context.svc_sp = sp;
    task->context.returns_to_user = 0;
    *svc_sp_out = sp;
    return snap;
}

__attribute__((noreturn))
static void handle_user_fault_on_svc_stack(user_fault_snapshot_t* snap)
{
    task_t* task = task_current_local();

    uart_puts("Segmentation Fault (");
    uart_put_hex(snap->dfar);
    if (snap->coredump_queued && snap->dump_path[0]) {
        uart_puts(") -> core dump queued ");
        uart_puts(snap->dump_path);
    } else {
        uart_puts(") -> core dump dropped");
    }
    uart_puts("\n");

    if (task && task->type == TASK_TYPE_PROCESS && task->process) {
        task->process->term_signal = SIGSEGV;
        sys_exit(SIGSEGV);
    }

    while (1) {
        wait_for_interrupt();
    }
}

/*
 * DATA ABORT enters in ABT mode on the ABT stack. The dump path opens and
 * writes files, so it may sleep behind VirtIO/ext2. Before doing that, move to
 * the faulting task's SVC stack so any scheduler entry still sees a valid
 * kernel stack for current_task.
 */
__attribute__((noreturn, naked))
static void user_fault_enter_svc_stack(user_fault_snapshot_t* snap, vaddr_t svc_sp)
{
    (void)snap;
    (void)svc_sp;
    __asm__ volatile(
        "cpsid   i\n"
        "cps     #0x13\n"
        "mov     sp, r1\n"
        "cpsie   i\n"
        "bl      handle_user_fault_on_svc_stack\n"
        "1:      wfi\n"
        "b       1b\n"
    );
}

static inline paddr_t pick_ttbr(vaddr_t va, uint32_t ttbcr) {
    uint32_t N = ttbcr & 7;               /* split */
    if (N == 0) return get_ttbr0();
    uint32_t top = va >> (32-N);
    return top ? get_ttbr1() : get_ttbr0();
}

static void dump_l1_l2(vaddr_t va) {
    uint32_t ttbcr = get_ttbcr();
    paddr_t ttbr  = pick_ttbr(va, ttbcr);
    paddr_t l1_base = ttbr & ~0x3FFFu;   /* 16KB aligned */
    uint32_t l1_idx  = (va >> 20) & 0xFFF;
    paddr_t l1_addr = l1_base + 4 * l1_idx;
    uint32_t *l1_ptr = (uint32_t*)phys_to_virt(l1_addr);
    uint32_t l1 = *l1_ptr;

    uart_puts("TTBR="); uart_put_hex(ttbr);
    uart_puts(" TTBCR="); uart_put_hex(ttbcr);
    uart_puts(" L1@"); uart_put_hex(l1_addr);
    uart_puts(" = "); uart_put_hex(l1); uart_puts("\n");

    uint32_t l1_type = l1 & 3;
    if (l1_type == 2 /*section*/) {
        uint32_t domain = (l1 >> 5) & 0xF;
        uart_puts("  L1: SECTION PA=");
        uart_put_hex(l1 & 0xFFF00000); uart_puts(" domain=");
        uart_put_hex(domain);
        uart_puts(" AP/TEX/C/B decoded in section bits\n");
        return;
    }
    if (l1_type == 1 /*coarse L2 table*/) {
        paddr_t l2_base = l1 & ~0x3FFu;        /* 1KB aligned */
        uint32_t l2_idx  = (va >> 12) & 0xFF;
        paddr_t l2_addr = l2_base + 4 * l2_idx;
        uint32_t *l2_ptr = (uint32_t*)phys_to_virt(l2_addr);
        uint32_t l2 = *l2_ptr;

        uart_puts("  L1: COARSE L2 @"); uart_put_hex(l2_base);
        uart_puts("  L2@"); uart_put_hex(l2_addr);
        uart_puts(" = "); uart_put_hex(l2); uart_puts("\n");

        uint32_t l2_type = l2 & 3;
        if ((l2_type & 2) == 0) { uart_puts("  L2: Fault/invalid\n"); return; }

        /* Small page (0b10 or 0b11 with XN in bit0) */
        uint32_t pa  = l2 & 0xFFFFF000;
        uint32_t ap2 = (l2 >> 9) & 1;
        uint32_t ap  = (l2 >> 4) & 3;  /* AP[1:0] */
        uint32_t xn  = l2 & 1;
        uint32_t tex = (l2 >> 6) & 7;
        uint32_t c   = (l2 >> 3) & 1;
        uint32_t b   = (l2 >> 2) & 1;

        uart_puts("  L2: SMALL PA="); uart_put_hex(pa);
        uart_puts(" AP2="); uart_put_hex(ap2);
        uart_puts(" AP="); uart_put_hex(ap);
        uart_puts(" XN="); uart_put_hex(xn);
        uart_puts(" TEX/C/B="); uart_put_hex(tex<<2 | c<<1 | b);
        uart_puts("\n");
        return;
    }

    uart_puts("  L1: Fault/Reserved type\n");
}

void dump_task_context(task_t *t) {
    uint8_t *p = (uint8_t*)&t->context;
    kprintf("DUMP context for task %s @ %p\n", t->name, t);
    for (int i = 0; i < 168; i += 16) {
        kprintf("%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
               p[i+0], p[i+1], p[i+2], p[i+3], p[i+4], p[i+5], p[i+6], p[i+7],
               p[i+8], p[i+9], p[i+10], p[i+11], p[i+12], p[i+13], p[i+14], p[i+15]);
    }
}

int data_abort_handler(uint32_t spsr_abt, uint32_t dfar, uint32_t dfsr, uint32_t *saved)
{
    /* saved = {r0,r1,r2,r3,r12,lr_abt} empilés par le vecteur */
    uint32_t lr_abt = saved[5];
    uint32_t status = ((dfsr >> 10) & 1) << 4 | (dfsr & 0xF);
    uint32_t mode = spsr_abt & 0x1F;
    bool is_write = (dfsr & (1u << 11)) != 0;
    uint32_t fault_pc;
    task_t* task = task_current_local();
    unsigned long log_flags;

    if ((status == 0x05 || status == 0x07) && mode == 0x10) {
        if (handle_user_stack_fault(dfar) == 0) {
            if (task) {
                task->page_faults++;
                task->stack_faults++;
            }
            return 0;
        }
        if (handle_lazy_anon_fault(dfar, is_write) == 0) {
            if (task) {
                task->page_faults++;
                task->lazy_faults++;
            }
            return 0;
        }
    }

    if (status == 0x0F && is_write && mode == 0x10) {
        if (handle_cow_fault(dfar) == 0) {
            if (task) {
                task->page_faults++;
                task->cow_faults++;
            }
            return 0;
        }
    }

    /* User-mode faults that are not handled above become SIGSEGV. Keep the
     * console readable and put the detailed crash context into /tmp/<pid>.dump.
     */
    fault_pc = lr_abt - (spsr_thumb(spsr_abt) ? 4u : 8u);
    if (exception_from_user(spsr_abt)) {
        vaddr_t svc_sp = 0;
        char dump_path[32];
        bool coredump_queued;
        user_fault_snapshot_t* snap;

        coredump_queued = coredump_enqueue(spsr_abt, dfar, dfsr, fault_pc,
                                           lr_abt, saved, dump_path,
                                           sizeof(dump_path));
        snap = user_fault_build_snapshot_on_svc_stack(task, spsr_abt,
                                                      dfar, dfsr, fault_pc,
                                                      lr_abt, saved,
                                                      coredump_queued,
                                                      coredump_queued ? dump_path : NULL,
                                                      &svc_sp);
        if (snap) {
            user_fault_enter_svc_stack(snap, svc_sp);
        }

        uart_puts("Segmentation Fault (");
        uart_put_hex(dfar);
        uart_puts(") -> no valid SVC stack\n");
        return -1;
    }

    spin_lock_irqsave(&exception_log_lock, &log_flags);

    uart_puts("\n=== DATA ABORT ===\n");
    uart_puts("DFAR="); uart_put_hex(dfar);
    uart_puts(" DFSR="); uart_put_hex(dfsr);
    uart_puts(" ("); uart_puts(dfsr_string(dfsr)); uart_puts(")\n");

    uart_puts("SPSR_abt="); uart_put_hex(spsr_abt);
    uart_puts(" LR_abt="); uart_put_hex(lr_abt); uart_puts("\n");

    /* PC fautif selon ARM/Thumb dans SPSR_abt[T] */
    uart_puts("Faulting PC="); uart_put_hex(fault_pc); uart_puts(spsr_thumb(spsr_abt) ? " (Thumb)\n" : " (ARM)\n");

    /* Un petit dump de l’instruction fautive si mappée */
    uint32_t par = ats1cpr(fault_pc);
    if ((par & 1) == 0) {
        paddr_t phys = (par & 0xFFFFF000) | (fault_pc & 0xFFF);
        uart_puts("PC->PAR OK, phys="); uart_put_hex(phys); uart_puts("\n");
    } else {
        uart_puts("PC->PAR FAULT fs="); uart_put_hex((par >> 1) & 0x3F); uart_puts("\n");
    }

    /* Traduction de DFAR via PAR: confirme la cause réelle */
    par = ats1cpr(dfar);
    if ((par & 1) == 0) {
        paddr_t phys = (par & 0xFFFFF000) | (dfar & 0xFFF);
        uart_puts("DFAR->PAR OK, phys="); uart_put_hex(phys); uart_puts("\n");
    } else {
        uart_puts("DFAR->PAR FAULT fs="); uart_put_hex((par >> 1) & 0x3F); uart_puts("\n");
    }

    /* MMU state utile pour expliquer domain/permission */
    uart_puts("SCTLR="); uart_put_hex(get_sctlr());
    uart_puts(" DACR="); uart_put_hex(get_dacr()); uart_puts("\n");

    /* Marche des tables sur la VA fautive */
    uart_puts("Walk for DFAR="); uart_put_hex(dfar); uart_puts("\n");
    dump_l1_l2(dfar);

    /* Optionnel: marche aussi pour PC (utile sur prefetch aborts croisés) */
    uart_puts("Walk for PC="); uart_put_hex(fault_pc); uart_puts("\n");
    dump_l1_l2(fault_pc);

    /* Ici: tu peux aussi dumper TTBR0/1, CONTEXTIDR/ASID, current->pgdir, etc. */

    uart_puts("TACHE COURANTE = ");
    uart_puts(task ? task->name : "?");
    uart_puts("\n");

    spin_unlock_irqrestore(&exception_log_lock, log_flags);
    return -1;
}

/* ATS1CPR: translate VA as privileged read; PAR returns PA or fault status */
static inline uint32_t ats1cpr2(uint32_t va){
    uint32_t par;
    asm volatile(
        "mcr p15,0,%1,c7,c8,0\n"   /* ATS1CPR */
        "isb\n"
        "mrc p15,0,%0,c7,c4,0\n"   /* PAR */
        : "=r"(par) : "r"(va) : "memory");
    return par;
}

static inline bool spsr_thumb2(uint32_t spsr){ return (spsr & (1u<<5)) != 0; }

static inline uint32_t pick_ttbr2(uint32_t va, uint32_t ttbcr) {
    uint32_t N = ttbcr & 7;               /* split */
    if (N == 0) return get_ttbr0();
    uint32_t top = va >> (32-N);
    return top ? get_ttbr1() : get_ttbr0();
}

void data_abort_c_handler(uint32_t spsr_abt, uint32_t dfar, uint32_t dfsr, uint32_t *saved)
{
    /* saved = {r0,r1,r2,r3,r12,lr_abt} empilés par le vecteur */
    uint32_t lr_abt = saved[5];

    uart_puts("\n=== DATA ABORT ===\n");
    uart_puts("DFAR="); uart_put_hex(dfar);
    uart_puts(" DFSR="); uart_put_hex(dfsr);
    uart_puts(" ("); uart_puts(dfsr_string(dfsr)); uart_puts(")\n");

    uart_puts("SPSR_abt="); uart_put_hex(spsr_abt);
    uart_puts(" LR_abt="); uart_put_hex(lr_abt); uart_puts("\n");

    /* PC fautif selon ARM/Thumb dans SPSR_abt[T] */
    uint32_t fault_pc = lr_abt - (spsr_thumb(spsr_abt) ? 4u : 8u);
    uart_puts("Faulting PC="); uart_put_hex(fault_pc); uart_puts(spsr_thumb(spsr_abt) ? " (Thumb)\n" : " (ARM)\n");

    /* Un petit dump de l’instruction fautive si mappée */
    uint32_t par = ats1cpr(fault_pc);
    if ((par & 1) == 0) {
        paddr_t phys = (par & 0xFFFFF000) | (fault_pc & 0xFFF);
        uart_puts("PC->PAR OK, phys="); uart_put_hex(phys); uart_puts("\n");
    } else {
        uart_puts("PC->PAR FAULT fs="); uart_put_hex((par >> 1) & 0x3F); uart_puts("\n");
    }

    /* Traduction de DFAR via PAR: confirme la cause réelle */
    par = ats1cpr(dfar);
    if ((par & 1) == 0) {
        paddr_t phys = (par & 0xFFFFF000) | (dfar & 0xFFF);
        uart_puts("DFAR->PAR OK, phys="); uart_put_hex(phys); uart_puts("\n");
    } else {
        uart_puts("DFAR->PAR FAULT fs="); uart_put_hex((par >> 1) & 0x3F); uart_puts("\n");
    }

    /* MMU state utile pour expliquer domain/permission */
    uart_puts("SCTLR="); uart_put_hex(get_sctlr());
    uart_puts(" DACR="); uart_put_hex(get_dacr()); uart_puts("\n");

    /* Marche des tables sur la VA fautive */
    uart_puts("Walk for DFAR="); uart_put_hex(dfar); uart_puts("\n");
    dump_l1_l2(dfar);

    /* Optionnel: marche aussi pour PC (utile sur prefetch aborts croisés) */
    uart_puts("Walk for PC="); uart_put_hex(fault_pc); uart_puts("\n");
    dump_l1_l2(fault_pc);

    /* Ici: tu peux aussi dumper TTBR0/1, CONTEXTIDR/ASID, current->pgdir, etc. */

    /* Stop net (ou tente une recovery si tu peux) */
    panic("Data Abort");
}  
