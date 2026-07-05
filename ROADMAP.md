# ArmOS Roadmap

This file tracks medium-term project direction. `STABILITY.md` keeps runtime
baselines and bug notes; this roadmap keeps feature sequencing and design
decisions.

## Near-Term Stability

- Release baseline: v0.6 keeps `SMP_CPUS=1` as the stable public profile.
  `SMP_CPUS>1` is valuable for developer stress and is much more mature than
  earlier bring-up work, but it is not promoted as the public contract yet.
- Keep UART `tty0` as the mandatory recovery path. Graphical `tty1`, ncurses,
  nano, and future console work must remain additive.
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

Goal: keep UART/QEMU as the recovery transport, while supporting credible
full-screen terminal programs through the shared TTY core.

Current v0.6 state:

- `tty0` is UART-backed and must remain a complete rescue console.
- `tty1` is optional VirtIO-GPU plus VirtIO input.
- `termios`, canonical/raw mode, VMIN/VTIME, job control, terminal signals,
  `/dev/tty`, `/dev/tty0`, `/dev/tty1`, `/dev/console`, and `/dev/null` exist.
- `kilo`, `top`, `cursestest`, and the early nano port are the practical
  terminal regression programs.

Priority order:

1. Keep long-idle TTY/read wakeups under soak-test coverage.
2. Preserve raw/non-canonical behavior under `ttytest --interactive-*`.
3. Keep graphical console redraw/flush stable under CPU and I/O load.
4. Add richer scrollback/copy behavior only after the base path stays boring.
5. Keep `TERM=armos` aligned with the ANSI sequences the kernel actually
   implements.

## Userland Commands

- Keep the POSIX-like `ps` as the normal command and `lps` as the ArmOS
  diagnostic view.
- Keep `top`, `lps`, `/proc/sched`, and `/proc/smp` aligned so scheduler
  diagnostics tell the same story.
- Keep expanding script-friendly commands only when their behavior is clear and
  testable.

## Full-Screen Editors And Curses

Status: kilo is usable, ncurses/nano are early optional ports.

Current state:

- `kilo` is the small always-available editor and remains the best interactive
  TTY regression tool.
- ncurses can be cross-built as a static bundle with compiled fallback terminfo.
- nano can be cross-built in a small static configuration and staged under
  `/opt/nano/bin`.

Next steps:

1. Keep `cursestest` small and ruthless: arrows, colors, resize query, and
   timeout behavior.
2. Validate nano on both UART `tty0` and graphical `tty1`.
3. Avoid declaring broad ncurses compatibility until more programs than nano
   have run.
4. Keep generated ncurses/nano bundles out of Git; commit scripts and source
   notes, not built artifacts.

## Newlib Direction

- New userland work should prefer the newlib-based toolchain path.
- The old libc and old binaries are archived under `userland/legacy/`; do not
  double-maintain commands there.
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

- more ncurses programs beyond nano;
- richer shell/script utilities;
- TCC-hosted userland experiments inside ArmOS;
- larger POSIX tools once syscall and libc gaps are clearer;
- eventually a second concrete platform/architecture branch based on the v0.6
  baseline, not on speculative abstractions.
