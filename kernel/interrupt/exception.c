#include <kernel/kernel.h>
#include <kernel/types.h>
#include <kernel/kprintf.h>
#include <kernel/debug_print.h>
#include <asm/arm.h>
#include <kernel/uart.h>

// Implémentez ces handlers
void undefined_instruction_handler(void) {
    kprintf("=== UNDEFINED INSTRUCTION ===\n");
    uint32_t lr, spsr;
    asm volatile("mov %0, lr" : "=r"(lr));
    asm volatile("mrs %0, spsr" : "=r"(spsr));
    kprintf("UND LR: 0x%08X, SPSR: 0x%08X\n", lr, spsr);
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
    uint32_t l1_base, l2_base;
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

static pte_probe_t probe_pte(uint32_t ttbr0, uint32_t va) {
    pte_probe_t p = {0};
    uint32_t l1_base = ttbr0 & ~0x3FFFu;      // TTBR0 short-desc: 16KB align
    uint32_t l1_index = (va >> 20) & 0xFFF;   // 4KB entries, 1MB per entry
    uint32_t *l1 = (uint32_t*)l1_base;
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
        uint32_t l2_base = l1d & ~0x3FFu;     // bits [31:10]
        uint32_t l2_index = (va >> 12) & 0xFF;
        uint32_t *l2 = (uint32_t*)l2_base;
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
static int section_ap_user_ro_or_no(uint32_t l1d) {
    uint32_t ap2 = (l1d >> 15) & 1;
    uint32_t ap10 = (l1d >> 10) & 3;
    // AP decode (user perms): 0=no access, 1=RO, 2/3=RW (depends on ap2)
    // Ici on renvoie 1 si l'utilisateur n'a PAS exécution/accès écriture (indicatif)
    // C'est un "hint", pas une vérité absolue pour exec; XN reste la clé pour PABT.
    return (ap2==0 && ap10==0) || (ap2==0 && ap10==1);
}
static int smallpage_xn(uint32_t l2d) { 
    if ((l2d & 3) == 3) return l2d & 1; // format avec XN
    return 0; // format sans XN
}


__attribute__((noinline))
void prefetch_abort_handler(void) {
    uart_puts("=== PREFETCH ABORT ===\n");

    uint32_t lr_svc, spsr_svc;
    __asm__ volatile("mov %0, lr" : "=r"(lr_svc));
    __asm__ volatile("mrs %0, spsr" : "=r"(spsr_svc));

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

    while (1) { /* stop */ }
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

static inline uint32_t pick_ttbr(uint32_t va, uint32_t ttbcr) {
    uint32_t N = ttbcr & 7;               /* split */
    if (N == 0) return get_ttbr0();
    uint32_t top = va >> (32-N);
    return top ? get_ttbr1() : get_ttbr0();
}

static void dump_l1_l2(uint32_t va) {
    uint32_t ttbcr = get_ttbcr();
    uint32_t ttbr  = pick_ttbr(va, ttbcr);
    uint32_t l1_base = ttbr & ~0x3FFFu;   /* 16KB aligned */
    uint32_t l1_idx  = (va >> 20) & 0xFFF;
    uint32_t *l1_ptr = (uint32_t*)(l1_base + 4*l1_idx);
    uint32_t l1 = *l1_ptr;

    uart_puts("TTBR="); uart_put_hex(ttbr);
    uart_puts(" TTBCR="); uart_put_hex(ttbcr);
    uart_puts(" L1@"); uart_put_hex((uint32_t)l1_ptr);
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
        uint32_t l2_base = l1 & ~0x3FFu;        /* 1KB aligned */
        uint32_t l2_idx  = (va >> 12) & 0xFF;
        uint32_t *l2_ptr = (uint32_t*)(l2_base + 4*l2_idx);
        uint32_t l2 = *l2_ptr;

        uart_puts("  L1: COARSE L2 @"); uart_put_hex(l2_base);
        uart_puts("  L2@"); uart_put_hex((uint32_t)l2_ptr);
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

void data_abort_handler(uint32_t spsr_abt, uint32_t dfar, uint32_t dfsr, uint32_t *saved)
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
        uint32_t phys = (par & 0xFFFFF000) | (fault_pc & 0xFFF);
        uart_puts("PC->PAR OK, phys="); uart_put_hex(phys); uart_puts("\n");
    } else {
        uart_puts("PC->PAR FAULT fs="); uart_put_hex((par >> 1) & 0x3F); uart_puts("\n");
    }

    /* Traduction de DFAR via PAR: confirme la cause réelle */
    par = ats1cpr(dfar);
    if ((par & 1) == 0) {
        uint32_t phys = (par & 0xFFFFF000) | (dfar & 0xFFF);
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
    while (1) { /* halt */ }
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

static const char* dfsr_string2(uint32_t dfsr) {
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

static inline bool spsr_thumb2(uint32_t spsr){ return (spsr & (1u<<5)) != 0; }

static inline uint32_t pick_ttbr2(uint32_t va, uint32_t ttbcr) {
    uint32_t N = ttbcr & 7;               /* split */
    if (N == 0) return get_ttbr0();
    uint32_t top = va >> (32-N);
    return top ? get_ttbr1() : get_ttbr0();
}

static void dump_l1_l22(uint32_t va) {
    uint32_t ttbcr = get_ttbcr();
    uint32_t ttbr  = pick_ttbr(va, ttbcr);
    uint32_t l1_base = ttbr & ~0x3FFFu;   /* 16KB aligned */
    uint32_t l1_idx  = (va >> 20) & 0xFFF;
    uint32_t *l1_ptr = (uint32_t*)(l1_base + 4*l1_idx);
    uint32_t l1 = *l1_ptr;

    uart_puts("TTBR="); uart_put_hex(ttbr);
    uart_puts(" TTBCR="); uart_put_hex(ttbcr);
    uart_puts(" L1@"); uart_put_hex((uint32_t)l1_ptr);
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
        uint32_t l2_base = l1 & ~0x3FFu;        /* 1KB aligned */
        uint32_t l2_idx  = (va >> 12) & 0xFF;
        uint32_t *l2_ptr = (uint32_t*)(l2_base + 4*l2_idx);
        uint32_t l2 = *l2_ptr;

        uart_puts("  L1: COARSE L2 @"); uart_put_hex(l2_base);
        uart_puts("  L2@"); uart_put_hex((uint32_t)l2_ptr);
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
        uint32_t phys = (par & 0xFFFFF000) | (fault_pc & 0xFFF);
        uart_puts("PC->PAR OK, phys="); uart_put_hex(phys); uart_puts("\n");
    } else {
        uart_puts("PC->PAR FAULT fs="); uart_put_hex((par >> 1) & 0x3F); uart_puts("\n");
    }

    /* Traduction de DFAR via PAR: confirme la cause réelle */
    par = ats1cpr(dfar);
    if ((par & 1) == 0) {
        uint32_t phys = (par & 0xFFFFF000) | (dfar & 0xFFF);
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
