# ArmOS

ArmOS is a small ARMv7-A Unix-like kernel for the QEMU `virt` machine,
currently targeting Cortex-A15.

It started as a learning experiment: can a Linux-like ARM kernel be built from
scratch, with modern tooling and AI-assisted development? It is now a usable
educational and research operating system with user processes, virtual memory,
filesystems, syscalls, signals, `/proc`, a shell, and a newlib-based userland
path.

ArmOS is not Linux, and it is not production-ready. The goal is to keep the
system small enough to understand while still implementing real operating
system mechanisms.

## ArmOS v0.3 Milestone

ArmOS v0.3 is a major userland autonomy milestone.

The development workflow for the operating system itself remains deliberately
conservative: kernel, filesystem, drivers, release images, and stabilization
work are still built from macOS or Linux with the host ARM cross toolchain
(`arm-none-eabi-gcc`, newlib, Makefiles, and the project scripts). This is the
supported path for contributors.

What changes in v0.3 is what ArmOS can do for its own users once it is already
running. The generated root filesystem now ships:

- a native TinyCC toolchain exposed through `/usr/bin/tcc`
- the TinyCC runtime bundle under `/opt/tcc`
- a source snapshot under `/usr/src/armos/userland`
- enough newlib syscall glue to compile and run small C user programs directly
  from inside `mash`

That means an ArmOS user can boot the system, open a source file with `kilo`,
compile it with `tcc`, and run the resulting binary without returning to the
host machine. It is not yet a replacement for the project build system, but it
is the first step toward a self-hosted-feeling Unix environment.

## Current Status

ArmOS currently provides:

- ARMv7-A kernel running on QEMU `virt` / Cortex-A15
- MMU enabled with split TTBR0/TTBR1 address spaces
- ASID support and ASID rollover handling
- Kernel tasks and user processes
- Per-task kernel stacks
- Context switching across user and kernel execution paths
- Timer-driven scheduling
- `fork`, `execve`, `waitpid`, `exit`
- Copy-on-write process memory
- Signals and basic job control
- Pipes, file descriptors, `dup`, `dup2`
- Ext2 root filesystem with read/write support
- FAT32 compatibility mount
- VirtIO block device support
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
- Core utilities such as `cat`, `echo`, `pwd`, `ls`, `cp`, `mv`, `rm`,
  `mkdir`, `rmdir`, `touch`, `sleep`, `kill`, `ps`, `stat`, `head`,
  `grep`, `sed`, `sort`, `uniq`, `wc`, and `which`
- System tools such as `mount`, `umount`, `shutdown`, and `fsck-lite`
- Runtime smoke and stress tests through `systest`, `ttytest`, and `memstress`

## Platform

Current supported platform:

- QEMU `virt`
- QEMU 10.0.2 is the supported v0.3 reference emulator
- QEMU 11.0.1 has been smoke-tested, but its macOS/Cocoa graphical window
  scaling differs from 10.0.2
- ARM Cortex-A15
- ARMv7-A, 32-bit
- GICv2
- ARM generic timer
- VirtIO block device
- UART console
- Optional VirtIO-GPU display and VirtIO input keyboard

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
per-CPU scheduler state, SMP diagnostics, and TLB shootdown experiments.
However, `SMP_CPUS>1` is still considered an experimental developer mode. It is
useful for finding races and validating future scheduler/MMU work, but it is
not the documented stable configuration for end users or public releases yet.

Future targets may include Raspberry Pi boards or an AArch64 port, but the
current development platform is QEMU `virt`.

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

ArmOS v0.3 also ships a userland source snapshot in the root filesystem:

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
- [`STABILITY.md`](STABILITY.md)
- [`ROADMAP.md`](ROADMAP.md)

Known areas still under investigation include:

- graphical console polish such as resize, richer scrollback, and copy/paste
- procfs transient entries during fork/exit storms
- cleanup of old debug code and unused kernel paths

## Building And Running

Installation guides:

- macOS: [`INSTALLATION_macos.md`](INSTALLATION_macos.md)
- Linux: [`INSTALLATION_linux.md`](INSTALLATION_linux.md)

Common scripts:

```sh
./run.sh
```

Rebuilds the project, recreates disk images, and starts QEMU.

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

## Roadmap

Near-term work:

- continue graphical console polish while preserving UART `tty0`
- improve shell/userland polish
- continue procfs cleanup
- reduce dead code and warnings

Medium-term ideas:

- port a small `kilo`-style terminal editor
- experiment with reduced ncurses
- eventually try `nano`
- improve POSIX compatibility for larger userland packages
- evaluate AArch64 and Raspberry Pi ports

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
