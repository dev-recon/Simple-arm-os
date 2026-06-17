# Stability Notes

This file records runtime baselines that are useful when changing scheduler,
MMU, VFS, block I/O or process lifecycle code.

## Current Stress Baseline

Configuration:

- Platform: QEMU virt, ARM Cortex-A15
- Timer quantum: 1 ms
- Root filesystem: ext2
- Compatibility mount: FAT32 on `/mnt`
- Shell: newlib `mash`

Stress command:

```sh
systest &; systest &; systest &; systest &; systest &
```

Observed result:

- All 5 `systest` jobs completed with `status=0`.
- No data abort, prefetch abort, dead-task scheduling refusal, VFS tokenizer
  corruption, or task-list corruption.
- ASID rollover was exercised repeatedly.

Post-stress `ps` baseline:

```text
Life:  metric         live     +new    -done   forkfail     0  sched-refuse 29  ready-refuse 0
       tasks             4     8275     8271   asid-roll    12
       zombies           0     8271     8271
Alloc: metric         live   +alloc    -free
       kstack          16p   33100p   33084p
       phys           892p  336123p  335231p
Diag:  state-set      12246   signal-wake      193   tty-stale          0   unintr-timeout      12
```

Important invariants:

- `tasks live` returns to the expected idle/init/shell/ps set.
- `zombies live` returns to `0`.
- `tasks +new -done == tasks live`.
- `zombies +new -done == 0`.
- `kstack live == 16p` for four live tasks with 16 KiB stacks.
- `ready-refuse == 0`.
- `tty-stale == 0`.

Counters to watch:

- `sched-refuse`: currently non-zero under heavy stress. This should be split
  later into real schedule refusals vs stale critical-section repairs.
- `unintr-timeout`: should stay low and not increase while the system is idle.

Keep the 1 ms quantum while hardening the kernel. It exposes races and critical
section mistakes that longer quanta can hide.

## Notes From 2026-06-17 Procfs Stress

Configuration change:

- Runtime quantum was moved back to 5 ms by hand because the 1 ms quantum made
  the system feel laggy during disk-heavy and procfs-heavy workloads
  (display output, keyboard input, and filesystem access latency).
- Boot still reports `tick 1000 us`; this is now stale/misleading and should be
  tied to the configured scheduler quantum or printed as timer tick vs scheduler
  quantum explicitly.

Stress command:

```sh
systest &; systest &; systest &; systest &; systest &
```

Observation while stress was still running:

- `ls -l /proc` showed many live-looking PID directories, mixed with entries
  rendered by `ls` as:

```text
??????????  ? root root        ?            <pid>
```

- This most likely means the procfs root `getdents()` result included a task
  that exited before `ls` performed `lstat()` on `/proc/<pid>`. That is
  Linux-like in spirit because proc entries are transient, but the userland
  display is noisy. Later work should decide whether to:
  - tolerate this as normal transient `/proc` behavior,
  - make `ls` print a cleaner vanished-process marker,
  - or make procfs root listing snapshot stronger for one directory read.

Post-stress `ps` baseline:

```text
Life:  metric         live     +new    -done   forkfail     0  sched-refuse 25  ready-refuse 0
       tasks             4     8277     8273   asid-roll    12
       zombies           0     8273     8273
Alloc: metric         live   +alloc    -free
       kstack          16p   33108p   33092p
       phys           892p  324830p  323938p
Diag:  state-set      13739   signal-wake      347   tty-stale          0   unintr-timeout      10
```

Post-stress procfs cleanup:

- `/proc` returned to the expected stable set:
  `meminfo`, `uptime`, `mounts`, `stat`, `tasks`, `cpuinfo`, `filesystems`,
  `partitions`, `self`, `1`, `2`, and the foreground `ls` process.
- No persistent zombie/task/procfs leak was visible from the final `ps` and
  `ls -l /proc` snapshots.

Follow-up items:

- Fix the boot timer line so it does not keep saying `tick 1000 us` when the
  scheduler quantum is configured differently.
- Investigate whether procfs root `readdir` should snapshot PIDs per open/read
  to reduce transient `ls -l /proc` noise under fork/exit storms.
- Profile the perceived lag with 1 ms quantum separately for block I/O,
  terminal output, and procfs traversal before changing scheduler policy again.

## Notes From 2026-06-17 Long Idle Run

Observed after leaving the kernel idle at the shell prompt for roughly one hour:

- Typing a command such as `ps` still displays the characters before submit.
- Pressing Enter (`\r` on the serial console) moves the cursor/prompt to the
  next line, but the command does not appear to execute.
- After that point there is no visible echo/output from the shell.
- `Ctrl+C` does not recover the foreground shell/command.
- The QEMU session must be exited with `Ctrl+A`, then `x`.

This should be treated as a stability issue distinct from fork/exec stress:
the system survives active workloads, but can lose interactive progress after a
long idle period.

Follow-up hypotheses to check:

- TTY read path stuck waiting after receiving `\r`, or line discipline state not
  waking the foreground process.
- Foreground process group/session state becoming stale while idle.
- Timer or sleep wakeup accounting drifting after long idle time.
- Shell blocked in `waitpid`, `read`, or job-control bookkeeping with signals no
  longer interrupting it.
- UART/TTY interrupt or polling state losing input delivery after prolonged
  inactivity.

Reproduction target:

1. Boot normally and leave `mash` idle at the prompt for at least one hour.
2. Type `ps` and submit with serial Enter (`\r`).
3. If it hangs, capture `ps` counters before the idle run in a prior session and
   compare with a shorter idle interval.

## Shell/Userland Command Notes

Future `ps` split:

- Keep the current detailed ArmOS diagnostic process view, but rename it to
  `lps` ("local ps" / "long ps").
- Add a POSIX-like `ps` command with the compact default format:

```text
  PID TTY           TIME CMD
 2152 ttys000    0:01.22 -zsh
 2171 ttys000    0:00.01 -zsh
```

Rationale:

- The current `ps` is very useful for kernel debugging but much more verbose
  than the expected Unix/POSIX default.
- A compact `ps` makes scripts and interactive usage feel more familiar.
- `lps` does not appear to conflict with a common POSIX command name and is a
  reasonable ArmOS-specific diagnostic alias.

## TODO: TTY Hardening

Priority order:

1. Fix long-idle TTY/read wakeups.
   - Reproduce the one-hour idle shell hang.
   - Inspect shell task state, TTY input buffer, foreground process group,
     ready queue membership, IRQ state, and timer counters when the hang occurs.
   - Confirm whether `mash` is blocked in `read`, `waitpid`, job-control logic,
     or not being woken by the TTY path.

2. Add minimal termios support.
   - Implement `tcgetattr` / `tcsetattr` or compatible ioctl-backed support.
   - Support at least `ICANON`, `ECHO`, `ISIG`, `OPOST`, and `ONLCR`.
   - Make newline/carriage-return behavior explicit and consistent on the
     serial console.

3. Complete terminal signal behavior.
   - `Ctrl+C` sends `SIGINT` to the foreground process group.
   - `Ctrl+\` sends `SIGQUIT`.
   - `Ctrl+Z` sends `SIGTSTP`.
   - `SIGCONT` resumes stopped foreground/background jobs cleanly.

4. Strengthen foreground process group handling.
   - Keep `tcgetpgrp` / `tcsetpgrp` behavior consistent.
   - Detect stale foreground process groups.
   - Decide how strictly to enforce background TTY reads/writes.

5. Clean up device nodes.
   - Provide stable `/dev/tty`, `/dev/tty0`, and `/dev/console` semantics.
   - Keep UART-backed console support as the practical transport for QEMU.
   - Add/verify `isatty()` and `ttyname()` userland behavior.

6. Improve interactive line editing in `mash`.
   - History navigation with robust redraw.
   - Tab completion without lag.
   - Cursor movement, delete/backspace in the middle of the line, Home/End.
   - Prompt redraw when background jobs complete while the user is typing.

7. Prepare raw mode for future tools.
   - Add non-canonical input path.
   - Support no-echo mode.
   - Prepare enough terminal control for future `less`, `vi`, or ncurses-like
     programs.
