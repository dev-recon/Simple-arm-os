# ArmOS

ArmOS is a small ARM Unix-like kernel for QEMU and Raspberry Pi experiments.
The complete v0.6 kernel and userland remain 32-bit, with QEMU `virt` /
Cortex-A15 as the feature-development reference and Raspberry Pi 3 as the
AArch32 hardware reference. An isolated AArch64/QEMU-virt EL1 serial bootstrap
now starts the ARM64 port.

It started as a learning experiment: can a Linux-like ARM kernel be built from
scratch, with modern tooling and AI-assisted development? It is now a usable
educational and research operating system with user processes, virtual memory,
filesystems, syscalls, signals, `/proc`, a shell, and a newlib-based userland
path.

ArmOS is not Linux, and it is not production-ready. The goal is to keep the
system small enough to understand while still implementing real operating
system mechanisms.

## ArmOS v0.6 Milestone

ArmOS v0.6 is the first release where ArmOS starts to feel like a small,
self-contained Unix lab rather than only a kernel bring-up project.

The development workflow for the operating system itself remains deliberately
conservative: kernel, filesystem, drivers, release images, and stabilization
work are still built from macOS or Linux with the host ARM cross toolchain
(`arm-none-eabi-gcc`, newlib, Makefiles, and the project scripts). This is the
supported path for contributors.

What changed since the early native-userland milestone is the amount of real
Unix surface available once ArmOS is already running. The generated root
filesystem now ships:

- a native TinyCC toolchain exposed through `/usr/bin/tcc`
- the TinyCC runtime bundle under `/opt/tcc`
- a source snapshot under `/usr/src/armos/userland`
- enough newlib syscall glue to compile and run small C user programs directly
  from inside `mash`
- optional static ncurses support with a custom `TERM=armos` terminfo entry
- optional GNU nano support, cross-built as a small static ArmOS user program
- optional BSD-style tool bundle with `bmake`, `sed`, `awk`, `install`,
  `mtree`, `xargs`, `diff`, `patch`, `pax`/`tar`, and `m4`
- a 512 MB ext2 root filesystem inside an MBR-partitioned `disk.img`
- a more disciplined kernel portability foundation: generated assembly offsets,
  `paddr_t` / `vaddr_t` address types, and a shared FDT parser
- active SMP hardening that is useful for development stress, while keeping the
  public runtime contract conservative

That means an ArmOS user can boot the system, edit C code with `kilo` or
`nano`, compile it with `tcc`, and run the resulting binary without returning
to the host machine. It is not yet a replacement for the project build system,
but it is now a credible end-user programming environment.

## Current Status

ArmOS currently provides:

- ARMv7-A kernel running on QEMU `virt` / Cortex-A15
- Raspberry Pi 3 AArch32 hardware target running on Cortex-A53
- initial AArch64 QEMU `virt` bootstrap reaching EL1 with PL011 diagnostics,
  a complete exception-vector table, a recoverable BRK/ERET smoke test, and a
  4 KiB long-descriptor identity MMU with Device/normal memory attributes,
  plus GICv2 physical-timer IRQ delivery through the EL1h vector and a shared
  early physical-page allocator driven by FDT RAM and reservation discovery;
  TTBR0 then migrates from the static boot table to allocated L1/L2/L3 tables
  with a tested 4 KiB unmap/remap path, while TTBR1 provides a canonical
  permission-checked kernel alias used by the live PC, stack, vectors, and
  MMIO; all low kernel mappings are then removed and isolated user-only TTBR0
  tables are exercised with distinct ASIDs; a copied EL0t payload now runs on
  separate RX code and RW/NX data/stack pages, returns through the lower-EL SVC
  vector, and leaves the physical timer operational; its TTBR0 tables, mapped
  pages, and ASID now have an explicit bootstrap user-VM owner with a balanced
  lifecycle test; `svc #0` now follows an AArch64 register ABI and validates
  successful `write`, `-EFAULT`, `-ENOSYS`, and `exit(42)` paths; EL0 entry
  and exception capture now share an explicit register context whose generated
  assembly offsets and nonvolatile-register preservation are checked at boot;
  a bootstrap task context now performs a validated two-stack cooperative
  switch while carrying the EL0 image and TTBR0/ASID identity; the switch
  boundary activates that identity and validates mapped/empty TTBR0 isolation;
  mapping generations now preserve resident single-CPU ASIDs without a TLBI
  on each context switch; user page tables now grow L2/L3 levels on demand
  across multiple virtual regions after low-map retirement, and page unmap
  performs targeted `(ASID, VA)` invalidation with exact physical-page and
  table-lifecycle accounting; eager anonymous ranges prevalidate overlap,
  roll back partial allocation, cross L3 boundaries, and reclaim empty L3/L2
  tables; a native-width generic syscall dispatcher, process-state model, and
  AArch64 ELF64 loader are now exercised at boot; lower-EL translation faults
  back lazy `brk` and private anonymous `mmap` reservations with zeroed pages,
  and the EL0 probe validates `munmap` and process exit through that path
- MMU enabled with split TTBR0/TTBR1 address spaces
- ASID support and ASID rollover handling
- typed physical/virtual address groundwork (`paddr_t`, `vaddr_t`, `pfn_t`)
- generated assembly offsets for fragile C/ASM context structures
- small in-kernel FDT parser used by platform/device discovery paths
- Kernel tasks and user processes
- Per-task kernel stacks
- Context switching across user and kernel execution paths
- Timer-driven scheduling
- experimental SMP bring-up with per-CPU state and diagnostics
- `fork`, `execve`, `waitpid`, `exit`
- Copy-on-write process memory
- anonymous `mmap` / `munmap` groundwork for user mappings
- Signals and basic job control
- Pipes, file descriptors, `dup`, `dup2`
- Ext2 root filesystem with read/write support
- MBR-partitioned disk image with a 512 MB ext2 root partition
- FAT32 compatibility mount
- VirtIO block device support
- VirtIO net diagnostic/echo bring-up
- `/proc` virtual filesystem
- UART-backed rescue console/TTY on `tty0`
- Optional VirtIO-GPU graphical console/TTY on `tty1`
- VirtIO input keyboard support for the graphical console
- Shell: `mash`
- Newlib-based userland
- Native TinyCC bring-up for end users: users can compile simple C programs
  directly inside ArmOS through the `/usr/bin/tcc` wrapper
- Userland source snapshot installed under `/usr/src/armos`, so ArmOS users can
  inspect, edit, and rebuild small programs from inside the running system
- Optional ncurses and nano bundles for terminal UI experiments
- Optional BSD-style tools for Makefile, text-processing, archive, patch, and
  macro-processing workflows
- Core utilities such as `cat`, `echo`, `pwd`, `ls`, `cp`, `mv`, `rm`,
  `mkdir`, `rmdir`, `touch`, `sleep`, `kill`, `ps`, `stat`, `head`,
  `grep`, `sed`, `sort`, `uniq`, `wc`, and `which`
- System tools such as `mount`, `umount`, `shutdown`, and `fsck-lite`
- Runtime smoke and stress tests through `systest`, `ttytest`, and `memstress`

## Platform

Reference platform:

- QEMU `virt`
- QEMU 10.0.2 is the supported v0.6 reference emulator
- QEMU 11.0.1 has been smoke-tested, but its macOS/Cocoa graphical window
  scaling differs from 10.0.2
- ARM Cortex-A15
- ARMv7-A, 32-bit
- GICv2
- ARM generic timer
- VirtIO block device
- UART console
- Optional VirtIO-GPU display and VirtIO input keyboard

Hardware reference platform:

- Raspberry Pi 3 Model B/B+ in AArch64 mode
  (`TARGET_ARCH=arm64 TARGET_PLATFORM=raspi3`)
- four Cortex-A53 CPUs participating in the scheduler
- PL011 UART rescue console on `tty0`
- SD/eMMC block device with a dedicated FAT32 firmware partition and ext2 root
- BCM2836 local interrupt controller and ARM generic timer

See [Raspberry Pi 3](docs/RASPBERRY_PI3.md) for the build, SD-card,
UART, validation, and current limitation contracts.

See [ARM64 Port](docs/ARM64_PORT.md) for the AArch64 bootstrap contract,
toolchain, validation marker, and staged migration plan.

### CPU Support Contract

The stable public runtime profile is currently **SMP=1**:

```sh
./boot.sh
```

or explicitly:

```sh
SMP_CPUS=1 ./boot.sh
```

The kernel contains active SMP bring-up work for multi-CPU QEMU runs, including
per-CPU scheduler state, TLB shootdown rendezvous, shutdown parking, and stress
diagnostics. `SMP_CPUS>1` is now useful and increasingly robust for developers,
but the public release contract remains `SMP_CPUS=1` until the full mixed stress
matrix is boring across repeated runs.

The v0.6 release contract remains QEMU `virt` with one CPU. Raspberry Pi 3 SMP
is a separately validated hardware-development profile, not yet a promise that
all QEMU multi-CPU or future Raspberry Pi variants are release-stable.

## Filesystems

ArmOS currently uses ext2 as its richer root filesystem.

Typical layout:

- `/` mounted as ext2
- `/mnt` used for FAT32 compatibility/testing
- `/proc` mounted as a virtual procfs
- `/dev` for device nodes
- `/home/user` as the default user home directory
- `/tmp` for temporary files
- `/usr/src/armos` for the shipped userland source snapshot used by native TCC
  experiments
- `/bin` for core utilities, `/sbin` for system programs, `/usr/bin` for
  ArmOS user programs, and `/opt/<program>/bin` for imported external tools
- `/opt/tcc`, `/opt/ncurses`, `/opt/nano`, and `/opt/bsd*` for optional
  generated/imported tool bundles when those build flags are enabled

Ext2 supports normal files, directories, links, permissions, and writable
operations used by the current userland. FAT32 remains useful as a compatibility
filesystem, but it is no longer expected to mirror the full root filesystem.

## Userland

Newlib is the supported userland C library.

The older in-tree libc and older programs are archived under
`userland/legacy/` for reference and bring-up archaeology, but new userland
work should use the newlib path.

The shell, `mash`, supports interactive commands, external programs, pipes,
redirections, background jobs, scripts, and basic job control.

ArmOS ships a userland source snapshot in the root filesystem:

```text
/usr/src/armos/userland
```

This is intentional, but it does not replace the project development toolchain.
Kernel work, stabilization, release builds, and normal contributor workflows
still use the host cross toolchain on macOS or Linux (`arm-none-eabi-gcc`,
newlib, Makefiles, and scripts). Native TinyCC is aimed at ArmOS users who want
to open a source file with `kilo`, compile a small program, and run it without
leaving ArmOS.

Example inside `mash`:

```sh
tcc /usr/src/armos/userland/coreutils/src/ls.c -o /tmp/ls-tcc
/tmp/ls-tcc /proc
```

Optional terminal UI packages can be staged during a build:

```sh
BUILD_NCURSES=1 BUILD_NANO=1 ./build.sh
```

This installs ncurses under `/opt/ncurses`, a small `cursestest` program under
`/usr/bin`, and nano under `/opt/nano/bin`. The generated bundles are build
artifacts and are not tracked in Git.

Optional BSD-style tools can be staged with:

```sh
BUILD_BSD=1 ./build.sh
```

This adds ports such as `bmake`, BSD `sed`/`awk`, `install`, `mtree`, `xargs`,
`diff`, `patch`, `pax`/`tar`, and `m4`. See
[`docs/BSD_USERLAND.md`](docs/BSD_USERLAND.md).

## Stability

ArmOS has passed repeated stress runs such as:

```sh
systest &; systest &; systest &; systest &; systest &
```

The stability notes track task lifetime, zombie cleanup, kernel stack page
balance, physical page allocation/free balance, ASID rollover, scheduler
refusals, TTY counters, and known long-idle issues.

See:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/GET_STARTED_KERNEL_DEV.md`](docs/GET_STARTED_KERNEL_DEV.md)
- [`docs/GET_STARTED_USERLAND_DEV.md`](docs/GET_STARTED_USERLAND_DEV.md)
- [`docs/BSD_USERLAND.md`](docs/BSD_USERLAND.md)
- [`STABILITY.md`](STABILITY.md)
- [`ROADMAP.md`](ROADMAP.md)

Known areas still under investigation include:

- graphical console polish such as resize, richer scrollback, and copy/paste
- procfs transient entries during fork/exit storms
- SMP promotion from developer mode to release-stable mode
- cleanup of old debug code and unused kernel paths

## Building And Running

Installation guides:

- macOS: [`INSTALLATION_macos.md`](INSTALLATION_macos.md)
- Linux: [`INSTALLATION_linux.md`](INSTALLATION_linux.md)

Common scripts:

```sh
./run.sh
```

On a fresh checkout, rebuilds and starts the stable reference target:

```text
arm32/qemu-virt
```

Other architecture/platform pairs are explicit opt-ins through the same
pipeline. For example:

```sh
TARGET_ARCH=arm64 TARGET_PLATFORM=qemu-virt ./run.sh
```

```sh
./boot.sh
```

Boots an existing `kernel.bin` and `disk.img` without rebuilding.

```sh
./boot-graphics.sh
```

Boots the same kernel and disk with VirtIO-GPU enabled. The UART terminal stays
available as `tty0`; the graphical QEMU window exposes `tty1`.

Exit QEMU with:

```text
Ctrl+A, then X
```

At the `mash$>` prompt, useful smoke tests are:

```sh
systest
ps
ls -la /
ls -la /proc
hello
```

## Development Notes

This is a learning-oriented kernel. Some code is still intentionally verbose or
instrumented because it helped bring up difficult subsystems such as MMU,
context switching, signals, filesystems, VirtIO, and process lifecycle code.

Planned cleanup work includes:

- removing dead code
- reducing old debug logs
- lowering warning noise
- shrinking kernel size
- isolating architecture-specific ARM32 code more cleanly
- advancing the ARM64 port from its EL1 serial bootstrap

## Roadmap

Near-term work:

- continue graphical console polish while preserving UART `tty0`
- improve shell/userland polish
- continue procfs cleanup
- reduce dead code and warnings
- stabilize the optional ncurses/nano path
- automate the mixed SMP stress matrix

Medium-term ideas:

- improve POSIX compatibility for larger userland packages
- extend the locally IRQ-safe ARM64 dispatcher with SMP runqueue locking and
  per-CPU ownership, replace the bounded generic ARM64 VMA/table inventories
  with dynamic range nodes, make ASID residency SMP-safe, move early allocation
  into the synchronized physical allocator, and connect VFS-backed ELF64
  `execve`, runnable fork children, file descriptors, pipes, and TTYs before
  building the AArch64 newlib userland

See [`ROADMAP.md`](ROADMAP.md) for more detail.

## Project Goals

ArmOS is intended to be:

- small enough to understand
- real enough to exercise serious kernel mechanisms
- useful for learning ARM bare-metal development
- useful for teaching operating system concepts
- a base for experiments around schedulers, virtual memory, filesystems,
  syscalls, userland, and hypervisor guests

It is not intended to replace Linux.

## Contributing

Contributions, experiments, bug reports, tests, and documentation improvements
are welcome.

Please read [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

ArmOS is licensed under the Apache License, Version 2.0.

See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
