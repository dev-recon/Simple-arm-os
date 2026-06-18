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
- UART-backed console/TTY
- Shell: `mash`
- Homegrown libc compatibility path
- Newlib-based userland path
- Core utilities such as `cat`, `echo`, `pwd`, `ls`, `cp`, `mv`, `rm`,
  `mkdir`, `rmdir`, `touch`, `sleep`, `kill`, `ps`, `stat`, `head`,
  `shutdown`, and stress tools
- Runtime smoke and stress tests through `systest`

## Platform

Current supported platform:

- QEMU `virt`
- ARM Cortex-A15
- ARMv7-A, 32-bit
- GICv2
- ARM generic timer
- VirtIO block device
- UART console

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
- `/bin` for official userland commands, with prefixed `nl-*` copies kept in `/opt/newlib/bin`

Ext2 supports normal files, directories, links, permissions, and writable
operations used by the current userland. FAT32 remains useful as a compatibility
filesystem, but it is no longer expected to mirror the full root filesystem.

## Userland

The project is moving toward a newlib-based userland.

The older in-tree libc and older binaries remain useful as compatibility and
bring-up tools, but new userland work should prefer the newlib path.

The shell, `mash`, supports interactive commands, external programs, pipes,
redirections, background jobs, scripts, and basic job control.

## Stability

ArmOS has passed repeated stress runs such as:

```sh
systest &; systest &; systest &; systest &; systest &
```

The stability notes track task lifetime, zombie cleanup, kernel stack page
balance, physical page allocation/free balance, ASID rollover, scheduler
refusals, TTY counters, and known long-idle issues.

See:

- [`STABILITY.md`](STABILITY.md)
- [`ROADMAP.md`](ROADMAP.md)

Known areas still under investigation include:

- long-idle TTY/read wakeups
- terminal/raw mode support
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

- harden TTY and long-idle shell behavior
- add minimal termios/raw mode
- split the diagnostic `ps` into `lps` and provide a compact POSIX-like `ps`
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
