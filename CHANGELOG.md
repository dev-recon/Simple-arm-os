# Changelog

## Unreleased

### SMP Bring-Up

- Added active SMP hardening work around task ownership, scheduler state,
  TLB shootdown diagnostics, procfs snapshots, and multi-CPU stress tooling.
- Documented the current support contract: the stable public runtime profile is
  still `SMP_CPUS=1`.
- `SMP_CPUS>1` is available as an experimental developer mode for race hunting
  and scheduler/MMU validation, but it is not yet the release-stable
  configuration.

## ArmOS v0.3 - 2026-06-29

ArmOS v0.3 is the first public release that gives ArmOS end users a small
native C programming environment, while keeping the project development and
stabilization workflow on the existing macOS/Linux cross toolchain.

### Highlights

- Native TinyCC bring-up inside ArmOS through `/usr/bin/tcc`, intended for
  end-user experiments and small programs.
- TinyCC runtime bundle staged under `/opt/tcc`, rebuilt by the standard build
  scripts when `BUILD_TCC=1`.
- Expanded TCC/newlib syscall glue for native userland builds.
- `/usr/src/armos` source tree installed directly in the root filesystem.
  ArmOS users can inspect, edit, compile, and run small userland programs from
  inside ArmOS itself.
- Userland source snapshot includes public headers, coreutils, programs,
  `mash`, init, and system tools.
- `mash` now resolves explicit relative command paths such as `./hello` and
  `../tool` before `execve`, matching normal shell expectations.
- Native TCC validation includes:
  - `hello.c` compile/link/run inside ArmOS;
  - argument passing through `argv`;
  - simple newlib `malloc`, `string`, and `stat` paths;
  - direct execution of locally compiled programs with `./program`;
  - non-trivial compile/link of the ArmOS `kilo` source.
- Boot and `uname` version strings updated to `ArmOS 0.3 armv7l`.

### Source-In-Userfs Model

The release intentionally ships userland sources in:

```text
/usr/src/armos/userland
```

This is not just documentation. It is part of the product direction: ArmOS users
should be able to edit code with `kilo`, compile it with native TinyCC, and run
the result directly in ArmOS.

This does not change the main engineering workflow. Kernel development,
stabilization, release builds, and contributor work remain host cross-compiled
from macOS or Linux with `arm-none-eabi-gcc` and the existing build scripts.
The current native scope is small userland programs, not kernel self-hosting.

Example:

```sh
tcc /usr/src/armos/userland/coreutils/src/ls.c -o /tmp/ls-tcc
/tmp/ls-tcc /proc
```

### Supported Emulator

ArmOS v0.3 keeps QEMU 10.0.2 as the reference emulator. QEMU 11.0.1 has been
smoke-tested, but its macOS/Cocoa graphical window scaling differs from 10.0.2
and remains compatible-but-not-reference.

### Known Limitations

- Native TCC support targets small end-user programs first.
- The kernel still builds with `arm-none-eabi-gcc`; TinyCC is not a kernel
  compiler target.
- `/opt/tcc` is generated/staged by the build scripts and remains ignored by
  Git.
- Larger ports may still expose missing POSIX/newlib behavior.

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
