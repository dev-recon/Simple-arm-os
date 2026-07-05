# ArmOS Multi-Arch Migration

This branch restarts the multi-arch work from the v0.6 baseline. The goal is
not to invent a generic HAL up front. The goal is to make ARM32 dependencies
visible, contained, and testable, then let the second concrete port define the
interfaces that are actually needed.

## Current Rule

Keep the working ARM32/QEMU `virt` kernel boring while reducing architecture
leaks in small commits.

Good migration steps:

- replace ambiguous address values with `paddr_t`, `vaddr_t`, and `pfn_t`;
- move direct CP15, barrier, cache, timer, and exception details behind
  architecture-local `<asm/...>` helpers;
- keep generated `asm-offsets` as the only source of truth for C/ASM structure
  offsets;
- keep FDT discovery centralized;
- preserve UART `tty0` as the recovery console.

Bad migration steps:

- create a speculative HAL without a second target;
- change syscall ABI conventions in the name of portability;
- hide ARM32 behavior behind vague names that lose ordering or cache semantics;
- move many files at once without a green ARM32 build.

## Phase A - Mechanical Cleanup

Status: mostly complete for direct inline-assembly cleanup.

Done in this branch:

- Added explicit ARM32 helpers for:
  - `cpu_relax()`;
  - inner-shareable data memory barrier;
  - inner-shareable data sync barrier;
  - inner-shareable write data sync barrier.
- Converted selected non-architecture code to use `<asm/arm.h>` instead of
  inline assembly:
  - VirtIO block;
  - VirtIO GPU;
  - VirtIO input;
  - ELF exec cache maintenance.
- Routed MMU, ASID, VBAR, PSCI/HVC, current-task register, IRQ diagnostic
  register, stack-register, and CPU wait operations through ARM helper APIs.
- Removed stale task-switch debug assembly hooks from generic task code.

Still to audit:

- expected architecture-local assembly only:
  - `arch/arm32/asm-offsets.c`, which emits generated C/ASM offsets;
  - the naked user-abort-to-SVC trampoline in the exception path;
- ARM-specific timer helpers in generic-looking headers;
- hardcoded ARM ELF checks before an AArch64 userland exists.

## Phase B - ARM32 Containment

Target shape:

```text
arch/arm32/
  boot/
  include/
  mmu/
  smp/
  syscall/
  task/
  timer/
```

This should be introduced gradually. A file moves only when its dependencies are
clear and the ARM32 build still compiles after the move.

Done so far:

- moved ARM32 boot assembly to `arch/arm32/boot/boot.S`;
- moved ARM32 IRQ entry assembly to `arch/arm32/interrupt/interrupt.S`;
- moved ARM32 syscall entry assembly to `arch/arm32/syscall/syscall.S`;
- moved ARM32 context-switch assembly to `arch/arm32/task/task_switch.S`;
- moved ARM32 PSCI/secondary CPU bring-up to `arch/arm32/smp/smp.c`;
- moved generated assembly-offset source to `arch/arm32/asm-offsets.c`;
- moved ARM32 architecture headers to `arch/arm32/include/asm`;
- taught the top-level `Makefile` to build these ARM32 architecture objects
  from `arch/arm32` and to search architecture headers first.

Kernel code that should remain architecture-neutral:

- scheduler policy;
- VFS and filesystems;
- procfs formatting;
- TTY core and line discipline;
- process lifecycle above register-frame details;
- signal policy above signal-frame layout;
- userland build and root filesystem layout.

## Phase C - Second ARM32 Platform

Before AArch64, use a second ARM32 machine to force real platform boundaries.
Candidates:

- QEMU `raspi2b`;
- real Raspberry Pi 2-class board;
- another ARMv7 board with FDT, GIC/timer equivalents, and a usable UART.

This phase validates platform interfaces without also changing pointer width,
exception level, or page-table format.

## Phase D - AArch64

AArch64 should start only after ARM32/QEMU `virt` and the second ARM32 target
share the same platform seams.

Expected new AArch64 pieces:

- EL1 boot path;
- AArch64 exception vectors;
- long-descriptor MMU;
- AArch64 syscall ABI;
- AArch64 context switch;
- AArch64 signal frame;
- AArch64 toolchain/userland target.

Expected reusable pieces:

- FDT parser;
- VirtIO MMIO drivers, after DMA/address cleanup;
- VFS;
- procfs;
- scheduler policy;
- TTY core;
- newlib-oriented userland organization.

## Validation Policy

For this branch, the minimum validation after each mechanical extraction is:

```text
make kernel.bin ARCH=arm-none-eabi- CROSS_COMPILE=arm-none-eabi-
```

Do not run QEMU automatically from this branch unless explicitly requested. The
interactive stress matrix remains user-driven while the code is being reshaped.
