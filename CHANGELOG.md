# Changelog

## ArmOS v0.2 - 2026-06-22

ArmOS v0.2 focuses on making the system feel like a small interactive Unix-like
environment rather than only a serial-console kernel lab.

### Highlights

- Userland `init` under `/sbin/init`, with process reaping delegated to
  userland policy.
- Newlib is now the reference userland C library; the older in-tree libc and
  early programs are archived under `userland/legacy/`.
- Root and user sessions, `su`, `/root`, and more Unix-like ownership display.
- Improved `mash` shell behavior, job control, `$?`, `wait`, `fg`, `bg`, and
  POSIX-style `jobs` output.
- Compact POSIX-like `ps`, with the detailed ArmOS diagnostic view moved to
  `lps`.
- More userland utilities, including `top`, `kload`, `ttyinfo`, `keytest`,
  `grep`, `sed`, `sort`, `uniq`, `wc`, `which`, `who`, `whoami`, `uname`,
  `date`, `uptime`, `free`, `df`, `mount`, and `umount`.
- `/dev/null`, `/dev/tty`, `/dev/tty0`, `/dev/tty1`, and `/dev/console`
  support.
- Better `termios` coverage, raw/non-canonical mode, terminal-generated
  signals, foreground process groups, and background TTY read behavior.
- Optional VirtIO-GPU graphical console on `tty1`.
- VirtIO input keyboard support for `tty1`, including a Mac French development
  layout fallback.
- Graphical console bitmap font rendering, ANSI colors, cursor blinking through
  a dedicated `displayd` kernel task, and simple scrollback.
- `kilo` editor usable on both UART and graphical console paths.
- QEMU scripts support selecting an alternate QEMU binary through `QEMU=...`
  while defaulting to the system/Homebrew QEMU.

### Supported Emulator

ArmOS v0.2 is validated against QEMU 10.0.2 on macOS as the reference
emulator. QEMU 11.0.1 has been smoke-tested, including the graphical boot path,
but its macOS/Cocoa window scaling differs from 10.0.2 and should be treated as
compatible-but-not-reference for this release.

### Stability Baseline

The UART console remains the required rescue path. `boot.sh` should stay usable
even if the graphical console regresses. The graphical boot path is additive:

```sh
./boot-graphics.sh
```

Useful validation commands:

```sh
systest
ttytest
ttytest --interactive-canon
ttytest --interactive-raw
keytest
kilo /home/user/hello.c
top
lps
```

Known areas still under active development:

- graphical-console resize and richer scrollback;
- host-style mouse selection/copy-paste in the graphical window;
- full UTF-8/accent rendering;
- more complete login/getty model for multiple consoles;
- broader POSIX/newlib compatibility for larger ports.

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
