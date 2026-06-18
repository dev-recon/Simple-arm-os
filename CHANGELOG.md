# Changelog

## ArmOS v0.1 - 2026-06-18

Initial public release of ArmOS.

ArmOS v0.1 is a small ARMv7-A Unix-like kernel and userland for the QEMU `virt`
machine, targeting Cortex-A15. It is intended for learning, research, and
experimentation around real operating-system mechanisms while staying small
enough to understand.

### Highlights

- ARMv7-A kernel for QEMU `virt` / Cortex-A15
- MMU enabled with split TTBR0/TTBR1 address spaces
- ASID support with rollover handling
- Kernel tasks and user processes
- Timer-driven scheduling
- User/kernel context switching across blocking syscalls
- `fork`, `execve`, `waitpid`, `exit`
- Copy-on-write process memory
- Signals, process groups, and basic job control
- Pipes, file descriptors, `dup`, `dup2`, and file descriptor flags
- Ext2 root filesystem with read/write support
- FAT32 compatibility mount under `/mnt`
- VirtIO block device support
- `/proc` virtual filesystem
- UART-backed console/TTY
- `mash` shell with external commands, scripts, pipes, redirections, background
  jobs, history, and completion
- Newlib-based userland path alongside the older in-tree libc compatibility path
- Core utilities including `cat`, `echo`, `pwd`, `ls`, `cp`, `mv`, `rm`,
  `mkdir`, `rmdir`, `touch`, `sleep`, `kill`, `ps`, `lps`, `stat`, `head`,
  `shutdown`, and stress tools
- Runtime smoke and stress coverage through `systest`

### Stability Baseline

The release has passed repeated parallel `systest` stress runs, including
fork/exec/wait, signals, process groups, pipes, filesystem operations, malloc
stress, ASID rollover, and procfs traversal.

Known areas still under active development:

- long-idle TTY/read wakeup hardening
- terminal/raw mode support
- procfs transient entry presentation under fork/exit storms
- cleanup of old debug code and unused kernel paths
- broader POSIX/newlib compatibility for larger userland ports

### Platform

Supported release target:

- QEMU `virt`
- ARM Cortex-A15
- ARMv7-A, 32-bit
- GICv2
- ARM generic timer
- VirtIO block device
- UART console

### Build And Run

See:

- `README.md`
- `INSTALLATION_macos.md`
- `INSTALLATION_linux.md`

Common commands:

```sh
./run.sh
./boot.sh
```

Exit QEMU with `Ctrl+A`, then `X`.
