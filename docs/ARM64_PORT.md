# ARM64 Port

ArmOS now has an initial AArch64 target alongside the stable ARM32 kernel. The
first target is QEMU `virt`; Raspberry Pi 3 remains an AArch32 hardware target
until the generic ARM64 kernel contracts are ready.

## Completed Milestones

### Milestone 1: EL1 Serial Bootstrap

The current ARM64 target deliberately implements only the earliest boot path:

- AArch64 entry at `0x40080000`;
- boot CPU selection through `MPIDR_EL1`;
- EL2 to EL1h transition when required;
- 64 KiB boot stack and BSS initialization;
- PL011 output on QEMU `virt`;
- preservation and reporting of the QEMU DTB pointer.

It does not yet provide dynamic virtual memory, the full buddy allocator,
scheduler, filesystems, syscalls, SMP, or an ARM64 userland. Those remain on
the working ARM32 kernel while the 64-bit contracts are brought across
incrementally.

### Milestone 2: EL1 Exception Vectors

The bootstrap now installs a 2 KiB-aligned `VBAR_EL1` table with all 16 ARMv8-A
vector slots. Every entry builds a 288-byte architecture-local frame containing
`x0`-`x30`, `ELR_EL1`, `SPSR_EL1`, `ESR_EL1`, `FAR_EL1`, and the vector number.

Boot includes a recoverable `BRK #0x64` smoke test. The C dispatcher verifies
the current-EL/SPx synchronous vector and BRK exception class, advances
`ELR_EL1`, and returns through `ERET`. Unexpected exceptions print the same
register diagnostics and park the CPU.

### Milestone 3: EL1 Identity MMU

The bootstrap now enables ARMv8-A stage-1 translation with a 4 KiB granule and
a 39-bit TTBR0 address space. A 4 KiB L1 table installs two 1 GiB blocks:

- `0x00000000-0x3fffffff` as Device-nGnRE, outer-shareable and execute-never;
- `0x40000000-0x7fffffff` as normal WBWA, inner-shareable RAM.

`MAIR_EL1`, `TCR_EL1`, and `TTBR0_EL1` are installed before enabling the
`M`, `C`, and `I` bits in `SCTLR_EL1`. The bootstrap uses `AT S1E1R` and
`PAR_EL1` to verify that UART and kernel addresses translate while
`0x80000000` remains unmapped. A second BRK/ERET test runs after MMU activation
to prove that vectors, stack, code and MMIO remain coherent.

### Milestone 4: GICv2 And Generic Timer IRQ

The ARM64 QEMU profile explicitly selects `virt,gic-version=2`. The bootstrap
initializes the distributor and CPU interface at the standard QEMU addresses,
enables physical timer PPI 30, and programs `CNTP_TVAL_EL0` from
`CNTFRQ_EL0`. When boot entered through EL2, `CNTHCTL_EL2` grants EL1 physical
counter and timer access before `ERET`.

The smoke test unmasks IRQs, waits in `WFI`, handles three timer interrupts
through the current-EL/SPx IRQ vector, acknowledges each interrupt through
GICC IAR/EOIR, then masks and disables the timer. QEMU 10.0.2 reports a
62.5 MHz counter for the selected Cortex-A72 profile.

### Milestone 5: Shared Early Page Allocator

The first architecture-neutral kernel component now runs on ARM64. A small
bitmap allocator in `kernel/memory` manages 4 KiB physical pages before the
full memory manager, scheduler, and spinlocks exist. Its address and page types
come from the common kernel type contract, backed by ARM64 page and cache
geometry headers.

The QEMU bootstrap manages the page-aligned range after `__kernel_end`. Its
smoke test:

- reserves the first page and verifies that allocation skips it;
- allocates one page and a contiguous three-page extent;
- writes and reads patterns at both ends of the allocated memory;
- frees and reallocates a page to verify deterministic reuse;
- restores the initial free-page count after releasing temporary allocations.

This allocator is intentionally single-CPU and bounded. It is an early-boot
building block, not yet a replacement for the ARM32 buddy allocator.

### Milestone 6: FDT Memory Topology

A dependency-free reader in `kernel/lib/fdt_memory.c` now discovers physical
memory instead of relying on a platform constant. It validates all FDT block
offsets and lengths, supports one- and two-cell address/size tuples, and reads:

- every top-level `/memory` range;
- the FDT memory-reservation map;
- child `reg` ranges under `/reserved-memory`;
- the DTB's own address and exact `totalsize`.

With the QEMU 10.0.2 1 GiB profile, the bootstrap discovers RAM at
`0x40000000-0x7fffffff`, manages pages from the end of the kernel to
`0x80000000`, and reserves the 1 MiB DTB at `0x48000000`. The early bitmap is
explicitly sized for at most 1 GiB of RAM; larger profiles are rejected until
allocator metadata becomes dynamic.

### Milestone 7: Allocated L1/L2/L3 Tables

The static boot L1 table is now only the bridge used to enable translation.
After FDT discovery and early-page initialization, the bootstrap allocates
three contiguous 4 KiB pages for a new L1/L2/L3 hierarchy, cleans them to the
point of coherency, and switches `TTBR0_EL1` to the allocated L1.

The MMIO range remains a Device 1 GiB L1 block. The 1 GiB RAM range is split
into 2 MiB L2 blocks, while its first 2 MiB containing the kernel, stack, and
allocated tables is split again into 4 KiB L3 pages.

The replacement follows the required ordering around the TTBR write and a
local stage-1 TLB invalidation. Translation probes for PL011, kernel RAM, and
the unmapped `0x80000000` boundary are repeated after the switch. A dedicated
page is then removed from L3, checked as faulting through `AT S1E1R`, restored,
and checked for its original contents after a targeted `TLBI VAE1`. A BRK/ERET
round trip and a second three-interrupt timer test finally prove that vectors,
code, stack, MMIO, and IRQ delivery remain usable through the new hierarchy.

SMP-wide TLB invalidation is not enabled yet.

### Milestone 8: TTBR1 Kernel Alias And Permissions

The linker now aligns text, read-only data, and writable data on 4 KiB
boundaries and exports their exact ranges. Before switching to the allocated
tables, L3 descriptors enforce:

- kernel text: EL1 read/execute, read-only, inaccessible to EL0;
- kernel rodata: EL1 read-only and execute-never, inaccessible to EL0;
- kernel data, BSS, stacks, and allocator pages: EL1 read/write and
  execute-never, inaccessible to EL0.

A fourth allocated L1 is installed in `TTBR1_EL1`. It reuses the existing RAM
L2/L3 hierarchy and exposes the same physical pages at the canonical 39-bit
kernel offset `0xFFFFFF8000000000`; kernel text therefore appears at
`0xFFFFFF8040080000`. `TCR_EL1` now defines 4 KiB, inner-shareable WBWA walks
for both TTBR0 and TTBR1.

The smoke test compares data through low and high aliases, verifies their PAR
physical addresses, checks privileged read/write permissions, and confirms
that EL0 translation probes fail for text, rodata, and data.

### Milestone 9: High-Half Execution And Low Identity Retirement

An assembly trampoline now transfers the live PC, stack pointer, and
`VBAR_EL1` to their canonical TTBR1 aliases. Because kernel code is linked as
one position-preserving image, PC-relative calls and data references continue
to resolve within the same physical image after the offset is applied.

Once execution is demonstrably in `0xFFFFFF80...`, the high-half C entry clears
only TTBR0 L1 entry 1, which removes the `0x40000000-0x7fffffff` RAM identity
window. TTBR0 L1 entry 0 remains mapped as Device memory for the early PL011,
GICv2, and timer paths. TTBR1 retains the shared RAM L2/L3 hierarchy.

The post-transition smoke test verifies that the low kernel address faults,
the high text address still translates, and PL011 MMIO remains available. It
then takes and returns from a BRK through the high VBAR and receives three
physical timer interrupts with no low RAM alias present.

### Milestone 10: User-Only TTBR0 And ASIDs

The TTBR1 L1 now also maps the physical MMIO gigabyte as EL1-only Device
memory. Early UART and GIC accessors derive either the physical address or its
canonical kernel alias from the current PC, so the same drivers work on both
sides of the high-half trampoline. Once execution is high, both low L1 entries
are retired and no kernel RAM or MMIO mapping remains in TTBR0.

The bootstrap then exercises the first user-address-space contract. ASID 1
owns a private three-level TTBR0 with one RW/NX EL0 page at `0x00400000`;
ASID 2 owns an empty L1. Switching to ASID 2 makes the page fault, while
TTBR1 kernel text and MMIO remain translated. Switching back to ASID 1 restores
the page and its contents without changing TTBR1.

This is the page-table and context-switch primitive for future processes, not
yet integration with `task`, `vm_space`, the full allocator, or EL0 execution.

### Milestone 11: First EL0 Execution And SVC Return

The bootstrap now enters EL0t through an `ERET` trampoline with a private
three-page user layout: RX code at `0x00400000`, RW/NX data at `0x00401000`,
and an RW/NX stack at `0x00402000`. The code page is copied into place before
entry and receives the required data-cache clean and instruction-cache
invalidation. Mapping helpers reject writable executable user pages.

The copied payload uses its EL0 stack, invokes a private smoke-test SVC, resumes
in EL0 with the returned value, stores `0x1235` in its data page, and invokes a
second SVC to return to a registered EL1h continuation. The lower-EL AArch64
synchronous vector dispatches both calls and preserves the architectural SVC
return PC. A physical timer IRQ after the round trip confirms that exception
and interrupt state remains usable.

These two SVC numbers are bring-up probes only. They are not the public ArmOS
syscall ABI, and this payload is not yet owned by a scheduler task or
`vm_space`.

## Toolchain

On macOS, install the AArch64 bare-metal compiler and QEMU:

```sh
brew install aarch64-elf-gcc
./tools/build_qemu_10_0_2.sh
```

On Debian/Ubuntu, the distro cross compiler can build the freestanding
bootstrap. Select its prefix explicitly:

```sh
sudo apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
export ARCH=aarch64-linux-gnu-
```

The pinned QEMU build now produces both `qemu-system-arm` and
`qemu-system-aarch64`.

## Build And Boot

Build without launching QEMU:

```sh
TARGET_ARCH=arm64 TARGET_PLATFORM=qemu-virt ./build.sh
```

Build and boot with the exact emulator baseline:

```sh
QEMU_REQUIRED_VERSION=10.0.2 \
TARGET_ARCH=arm64 TARGET_PLATFORM=qemu-virt ./run.sh
```

The expected serial milestone is:

```text
ArmOS ARM64 bring-up
Architecture: AArch64
Current EL: EL1
DTB: 0x0000000048000000
ARM64_BOOT_OK
Testing EL1 synchronous vector with BRK #0x64
Exception vector: 0x0000000000000004
ESR_EL1: 0x00000000F2000064 EC: 0x000000000000003C
ARM64_VECTOR_OK
ARM64_EXCEPTION_RETURN_OK
Enabling ARMv8 4K identity MMU
ARM64_MMU_OK
Testing synchronous vector with MMU enabled
ARM64_VECTOR_OK
ARM64_MMU_EXCEPTION_OK
Testing GICv2 physical timer PPI 30
CNTFRQ_EL0: 0x0000000003B9ACA0 timer ticks: 0x0000000000000003
ARM64_TIMER_IRQ_OK
Early pages: base=0x000000004009F000 end=0x0000000080000000 ...
FDT RAM: base=0x0000000040000000 size=0x0000000040000000 ...
ARM64_FDT_MEMORY_OK
ARM64_PHYS_ALLOC_OK
TTBR0 allocated: old=... new=... L2=... L3=...
ARM64_L3_PAGE_TLBI_OK
TTBR1 kernel alias: table=... text=0xFFFFFF8040080000 TCR=...
ARM64_TTBR1_PERMISSIONS_OK
ARM64_DYNAMIC_PGTABLE_OK
High kernel: PC=0xFFFFFF80... SP=0xFFFFFF80... VBAR=0xFFFFFF80...
ARM64_TTBR1_EXECUTION_OK
ARM64_HIGH_MMIO_OK
ARM64_LOW_MAP_RETIRED_OK
User TTBR0: mapped=0x0001... empty=0x0002... VA=0x0000000000401000 PA=...
ARM64_USER_TTBR0_ASID_OK
Testing high VBAR synchronous vector
ARM64_VECTOR_OK
Entering EL0 at 0x0000000000400000 stack=0x0000000000403000
EL0 result: 0x0000000000001235 SVC count: 0x0000000000000002
ARM64_EL0_SVC_RETURN_OK
Testing timer IRQ after EL0 return
ARM64_TIMER_IRQ_OK
ARM64_HIGH_KERNEL_OK
```

Generated artifacts are isolated from ARM32 under:

```text
build/images/kernel-arm64-qemu-virt.bin
build/images/kernel-arm64-qemu-virt.elf
build/images/kernel-arm64-qemu-virt.map
build/images/kernel-arm64-qemu-virt.dis
```

## Next Milestones

1. Integrate TTBR0/ASID ownership with `task` and `vm_space`, and graduate the
   early allocator into the synchronized full physical-memory path.
2. Define the real syscall ABI, then add ELF64 loading, AArch64 context switch,
   signal frames, and the userland target.
