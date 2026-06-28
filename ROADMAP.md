# ArmOS Roadmap

This file tracks medium-term project direction. `STABILITY.md` keeps runtime
baselines and bug notes; this roadmap keeps feature sequencing and design
decisions.

## Near-Term Stability

- Keep validating the long-idle TTY/read wakeup fix with longer soak tests.
  The previous hang after idle input has been addressed in the TTY/job-control
  path and validated in short idle runs, but one-hour-plus runs should remain
  part of the stability checklist.
- Keep tracking scheduler counters after stress:
  - live tasks/zombies;
  - kernel stack page balance;
  - physical page allocation/free balance;
  - ASID rollover;
  - `sched-refuse`, `ready-refuse`, `tty-stale`, `unintr-timeout`;
  - `/proc/sched` `aging_selections` and `debt_selections`.
- Keep validating `priority-rr-debt` with mixed workloads. The current policy
  provides starvation resistance and basic CPU debt fairness; the next step is
  better instrumentation and workload-specific tuning, not a full CFS rewrite.
- Keep shutdown validation in the persistence checklist. A clean shutdown should
  signal user processes, sync filesystems, unmount non-root filesystems, stop
  block devices, and exit through PSCI.

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

1. Keep long-idle TTY/read wakeups under soak-test coverage.
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

## Kilo Editor Roadmap

Goal: make ArmOS capable of running a small full-screen terminal editor before
attempting heavier ncurses/nano work. `kilo` is the preferred first target
because it is a compact C editor that talks directly to the terminal with
`read()`, `write()`, and ANSI/VT100 escape sequences.

### Phase 0: Source Audit

- Keep a local review copy of upstream `kilo`.
- Identify assumptions that differ from ArmOS:
  - POSIX termios availability;
  - `ioctl(TIOCGWINSZ)` / window size;
  - non-blocking or raw terminal reads;
  - `errno` coverage;
  - file open/truncate/write behavior;
  - `malloc`, `realloc`, and line-buffer growth behavior.
- Decide whether the first port is:
  - an imported `kilo` with small compatibility patches; or
  - a tiny in-tree `aedit`/`kilo-armos` fork using the same design.

Done when:

- The syscall/libc gaps are listed.
- The first porting strategy is selected.

### Phase 1: Minimal Termios/TTY Contract

Implement enough terminal behavior for fullscreen tools:

- `tcgetattr()` and `tcsetattr()` wrappers through newlib.
- `ICANON` off for raw/non-canonical input.
- `ECHO` off.
- `ISIG` behavior defined while raw mode is active.
- `VMIN` / `VTIME` minimal semantics, even if initially simplified.
- Output post-processing policy:
  - preserve `\r` vs `\n` behavior on the serial console;
  - keep `ONLCR` behavior explicit.
- Restore terminal settings when a process exits or receives a terminating
  signal, where practical.

Done when:

- A test program can enter raw mode, read one byte at a time, print key codes,
  and restore normal shell behavior on exit.
- `Ctrl+C` policy in raw mode is documented and tested.

### Phase 2: ANSI/VT100 Screen Basics

Support the terminal escape sequences needed by `kilo`:

- clear screen;
- cursor movement;
- hide/show cursor;
- clear line;
- basic color passthrough;
- query cursor position if feasible.

ArmOS can continue to rely on the QEMU host terminal for actual rendering. The
kernel does not need a framebuffer terminal for this phase.

Done when:

- A userland demo can redraw a full-screen buffer without corrupting the shell
  prompt after exit.
- Arrow keys, Home/End if supported, Backspace/Delete, Enter, and printable
  characters are decoded consistently.

### Phase 3: File Editing MVP

Port the smallest useful subset:

- open a text file;
- display file contents;
- move cursor;
- insert printable characters;
- Backspace/Delete;
- save with truncation/rewrite;
- quit cleanly.

Useful first command name:

- `kilo` if close to upstream behavior;
- `aedit` if it is an ArmOS-specific adaptation.

Done when:

- `kilo /tmp/test.txt` can edit and save a file.
- The file survives reboot when stored on ext2.
- Returning to `mash` leaves the terminal usable.

### Phase 4: Robustness Pass

Use the editor to stress interactive kernel/userland paths:

- repeated open/save cycles;
- editing files larger than one page;
- malloc/realloc growth and shrink;
- interrupted editor with `Ctrl+C` / signal;
- background job output while editor is foreground;
- terminal resize fallback when no window-size syscall exists.

Done when:

- No shell prompt corruption after repeated editor exits.
- No file truncation corruption.
- No leaked foreground process group or stuck TTY state.
- `lps` and `/proc` counters remain sane after editor stress.

### Phase 5: Path Toward Nano/Ncurses

Only after the kilo path is stable:

- add a minimal window-size API (`ioctl(TIOCGWINSZ)` or equivalent);
- evaluate a reduced termcap/terminfo strategy;
- attempt a small ncurses build with one terminal type first;
- use `nano` as a maturity target, not as the first editor port.

Notes:

- `kilo` is the practical bridge between the current shell and a real editor.
- A working small editor will expose TTY bugs faster than synthetic tests.
- The first editor does not need to be perfectly POSIX; it needs to be small,
  inspectable, and brutal on the terminal path.

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
