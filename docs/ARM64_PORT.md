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
```

Generated artifacts are isolated from ARM32 under:

```text
build/images/kernel-arm64-qemu-virt.bin
build/images/kernel-arm64-qemu-virt.elf
build/images/kernel-arm64-qemu-virt.map
build/images/kernel-arm64-qemu-virt.dis
```

## Next Milestones

1. Graduate the early page allocator into the synchronized full
   physical-memory path.
2. Replace bootstrap blocks with dynamically allocated page tables and a kernel/user virtual
   address contract.
3. Define AArch64 task context, syscall, signal, ELF64, and userland ABIs.
