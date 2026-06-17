# ArmOS Roadmap

This file tracks medium-term project direction. `STABILITY.md` keeps runtime
baselines and bug notes; this roadmap keeps feature sequencing and design
decisions.

## Near-Term Stability

- Investigate the long-idle shell hang:
  - after roughly one hour idle, typing a command and pressing serial Enter
    (`\r`) moves to the next line but the command does not run;
  - echo/output stops after that point;
  - `Ctrl+C` does not recover;
  - QEMU must be exited with `Ctrl+A`, then `x`.
- Confirm whether the blocked path is TTY `read`, shell job-control,
  foreground process group state, UART input delivery, or timer/sleep wakeup.
- Keep tracking scheduler counters after stress:
  - live tasks/zombies;
  - kernel stack page balance;
  - physical page allocation/free balance;
  - ASID rollover;
  - `sched-refuse`, `ready-refuse`, `tty-stale`, `unintr-timeout`.

## Code Cleanup And Size Reduction

Goal: reduce kernel size, improve readability, and lower compile-time warning
noise without changing behavior.

Approach:

1. Inventory unused/dead code first.
   - Static functions not referenced.
   - Old debug helpers.
   - Obsolete scheduler/syscall experiments.
   - Disabled assembly paths.
   - Duplicate helpers superseded by newer implementations.

2. Remove in small commits.
   - One subsystem per commit when possible.
   - Keep behavior-preserving cleanups separate from functional fixes.
   - Avoid mixing warning cleanup with architecture changes.

3. Track binary impact.
   - Compare `kernel.bin`, `kernel.elf`, and map file sizes before/after.
   - Watch `.text`, `.data`, `.bss`, and debug/log string footprint.

4. Reduce warnings.
   - Fix real type/sign/format warnings.
   - Prefer deleting unused variables/functions over silencing warnings.
   - Add casts only when the ownership/type boundary is intentional.

5. Keep diagnostics that still pay rent.
   - Preserve crash dumps, scheduler sanity checks, memory counters, and
     stability counters.
   - Remove stale bring-up logs and duplicated debug print paths.

6. Validate after each cleanup batch.
   - Full rebuild from clean tree.
   - Boot.
   - `systest`.
   - Basic shell/filesystem/procfs smoke tests.
   - At least one background job stress run for scheduler-sensitive changes.

## TTY And Terminal

Goal: keep UART/QEMU as the practical transport for now, but expose a cleaner
Unix-like TTY model to userland.

Priority order:

1. Fix long-idle TTY/read wakeups.
2. Add minimal termios support:
   - `tcgetattr`;
   - `tcsetattr`;
   - `ICANON`;
   - `ECHO`;
   - `ISIG`;
   - `OPOST`;
   - `ONLCR`.
3. Complete terminal-generated signals:
   - `Ctrl+C` -> `SIGINT`;
   - `Ctrl+\` -> `SIGQUIT`;
   - `Ctrl+Z` -> `SIGTSTP`;
   - `SIGCONT` resumes stopped jobs cleanly.
4. Strengthen foreground process group handling:
   - `tcgetpgrp`;
   - `tcsetpgrp`;
   - stale foreground group detection;
   - background TTY read/write policy.
5. Clean up device nodes:
   - `/dev/tty`;
   - `/dev/tty0`;
   - `/dev/console`;
   - `isatty()`;
   - `ttyname()`.
6. Improve interactive line editing in `mash`:
   - robust redraw;
   - history navigation;
   - faster tab completion;
   - mid-line editing;
   - prompt redraw when background jobs finish.
7. Add raw/non-canonical mode for full-screen tools.

## Userland Commands

### `ps` split

- Rename the current detailed ArmOS diagnostic `ps` to `lps`.
- Add a compact POSIX-like `ps` default format:

```text
  PID TTY           TIME CMD
 2152 ttys000    0:01.22 -zsh
 2171 ttys000    0:00.01 -zsh
```

Rationale:

- The current `ps` is useful for kernel debugging but too verbose for the
  expected Unix default.
- `lps` keeps the ArmOS-specific diagnostic view available.
- `lps` does not appear to conflict with a common POSIX command name.

## Editor Path

Long-term ambition: run a real terminal editor in ArmOS.

Recommended sequence:

1. Implement termios/raw mode well enough for direct terminal control.
2. Port or write a small `kilo`-style editor:
   - no ncurses dependency;
   - direct `read()` / `write()`;
   - ANSI/VT100 escape sequences;
   - open/save files;
   - cursor movement;
   - insert/delete;
   - simple search later.
3. Use the small editor to harden:
   - raw mode;
   - terminal redraw;
   - file writes/truncation;
   - malloc/realloc under interactive workloads.
4. Attempt a reduced `ncurses` port:
   - one terminal type first (`ansi`, `vt100`, or `xterm`);
   - minimal terminfo/termcap support;
   - no locale/NLS at first.
5. Port `nano` after the TTY and curses layers are stable.

Notes:

- `kilo` is a tiny C editor by Salvatore Sanfilippo. It is a better first
  target than `nano` because it does not require ncurses.
- `nano + ncurses` is a good medium-term maturity test, not a small first step.
- A tiny in-tree editor is acceptable as an intermediate tool even if the
  eventual goal is to run standard packages.

## Newlib Direction

- New userland work should prefer the newlib-based toolchain path.
- Keep the old libc and old binaries available as a compatibility fallback for
  now, but avoid double-maintaining commands that are actively modified.
- Keep newlib binaries isolated enough that failures can be compared against
  older binaries during bring-up.

## Filesystems

- Continue using ext2 as the richer root filesystem.
- Keep FAT32 mounted for compatibility/testing, but it no longer needs to mirror
  the full userfs feature set.
- Preserve Linux-like behavior for links, permissions, directory traversal,
  and visible `.` / `..` entries where appropriate.

## Longer-Term Packages

Potential future package targets after TTY/raw mode and newlib mature:

- `kilo`-style editor or in-tree small editor.
- Reduced `ncurses`.
- `nano`.
- `tcc` for native compilation experiments.
- Later, larger POSIX tools once syscall and libc gaps are clearer.
