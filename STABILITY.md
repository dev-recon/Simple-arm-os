# Stability Notes

This file records runtime baselines that are useful when changing scheduler,
MMU, VFS, block I/O or process lifecycle code.

## Test Discipline

- Prefer local build and unit/smoke coverage from the host when it is enough.
- Ask the developer to run trivial interactive QEMU checks, such as simple
  shell commands, editor keystrokes, and visual confirmation flows.
- Reserve assistant-driven interactive QEMU sessions for subtle debugging:
  scheduler, TTY wakeups, signal delivery, MMU faults, VFS races, VirtIO, or
  cases where kernel logs and precise timing matter.
- When asking for manual interactive validation, provide a short command
  checklist and the expected result.

## Current Stress Baseline

### v0.6 Release Contract

ArmOS v0.6 is published with this stability statement:

- `SMP_CPUS=1` is the stable public runtime profile.
- `SMP_CPUS>1` is a developer stress profile. It is useful and much more robust
  than earlier bring-up work, but it is not the public support contract yet.
- UART `tty0` is the mandatory recovery console in every boot mode.
- VirtIO-GPU `tty1`, ncurses, and nano are optional layers that must never make
  `boot.sh`/`tty0` unusable.
- Generated native tool bundles under `/opt/tcc`, `/opt/ncurses`, and
  `/opt/nano` are build artifacts, not Git-tracked source of truth.

Before promoting SMP to stable, repeat the mixed stress matrix below until it
is boring across multiple runs and shutdown paths.

Configuration:

- Platform: QEMU virt, ARM Cortex-A15
- Stable public CPU profile: `SMP_CPUS=1`
- Experimental SMP profile: `SMP_CPUS>1`
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

- `sched-refuse`: real scheduler entry refusals. This must stay explainable.
- `sched-crit`: stale critical-section flag repairs. Any non-zero value means
  a caller attempted to enter the scheduler while the per-CPU critical-section
  guard was still set; investigate the source instead of treating it as normal.
- `unintr-timeout`: should stay low and not increase while the system is idle.

Keep the 1 ms quantum while hardening the kernel. It exposes races and critical
section mistakes that longer quanta can hide.

## SMP Stability Contract

The public stable baseline is currently single CPU:

```sh
SMP_CPUS=1 ./boot.sh
```

This is the configuration to use for release notes, contributor onboarding, and
normal user testing.

`SMP_CPUS=2` and above are developer stress modes. They intentionally exercise
new scheduler, TLB shootdown, task ownership, allocator, VFS, procfs, and TTY
paths. They are valuable precisely because they expose races that the mono-CPU
profile cannot reveal, but they should not be treated as the supported runtime
profile yet.

Before promoting SMP to stable, the minimum stress matrix should pass with no
task-list corruption, runqueue corruption, kernel data abort, stale `RUNNING`
task, or lost shell:

```sh
schedtest --smp
kload &; kload &; kload &; kload &
memstress 2048 5 &
systest &; systest &; systest &
vfstest &; vfstest &
top
lps
/sbin/shutdown
```

Until that matrix is boring, the release statement remains: stable on
`SMP_CPUS=1`, SMP bring-up experimental.

SMP shutdown invariant:

- `/sbin/shutdown` must terminate user processes first, then park scheduler
  participation on secondary CPUs before VFS sync/unmount and PSCI
  `SYSTEM_OFF`.
- Parked secondary CPUs keep interrupts enabled and wait in WFI so they can
  still acknowledge kernel-scope TLB shootdowns during final cleanup.

TLB shootdown invariants:

- A CPU that publishes a TLB shootdown must wait for all targeted CPUs to ACK.
  Continuing after a missed ACK is memory corruption by design.
- Do not initiate TLB shootdown while holding `task_lock`; the remote CPU may
  need scheduler/task state to reach or leave an interrupt-safe point. If a
  future debug lock-owner facility exists, assert this rule there.
- If a target CPU stops acknowledging after repeated SGI re-emissions, panic
  instead of spinning forever.

## Notes From Scheduler Debt Fairness

ArmOS currently reports this scheduler policy through `/proc/sched`:

```text
policy priority-rr-debt
description priority round-robin with bounded aging and CPU debt fairness
```

Validation target:

```sh
cat /proc/sched
memstress --cpu 20 &; memstress --cpu 20 &
cat /proc/sched
systest > /tmp/sched-debt-systest.out &
tail -1 /tmp/sched-debt-systest.out
```

Expected result:

- `debt_selections` increases when multiple CPU-bound tasks compete.
- `aging_selections` may also increase under contention.
- `systest` still reports `systest: all tests passed`.
- Interactive commands remain responsive while CPU-bound background work runs.

Observed baseline after two concurrent `memstress --cpu 20` jobs:

```text
aging_selections 19
debt_selections 74
```

This confirms that the scheduler is no longer pure FIFO within a fixed priority
queue. CPU-bound tasks accumulate debt, and waiting ready tasks can be selected
ahead of them without changing their visible priority.

Follow-up items:

- Stress with mixed workloads: `kload`, `memstress`, parallel `systest`, `top`,
  and normal shell commands.
- Watch whether `debt_selections` grows under CPU contention but stays stable
  when the system is idle.
- If `MAX_TASKS` grows significantly, revisit the ready-queue scan cost.

## Shutdown Baseline

The expected shutdown path is now signal-based and logged:

```sh
sleep 300 &
/sbin/shutdown
```

Expected log shape:

```text
System shutdown requested
Shutdown: sending SIGTERM to user processes
Shutdown: SIGTERM delivered to 1 process(es)
Shutdown: SIGTERM grace complete
Shutdown: VFS mounted filesystems
Shutdown: VFS sync start
Shutdown: VFS sync complete
Shutdown: VFS unmount non-root filesystems
Shutdown: flushing and stopping block device
Shutdown: block device stopped
Shutdown: interrupts disabled
Shutdown: entering PSCI SYSTEM_OFF
```

Important invariant:

- The shell/init ancestor chain that invoked shutdown must not be killed early.
  If it is killed during the grace period, userland init may restart a shell
  while the kernel is already powering off.
- Shutdown logs should remain readable on UART `tty0`. Userland `shutdown` and
  init write their shutdown status lines through single `write(2)` calls so the
  TTY write lock can serialize them against kernel logs and other processes.
- `/sbin/shutdown` gives init/mash a short grace period before entering the
  kernel poweroff path so login shells can persist command history before VFS
  sync/unmount.

Manual validation:

1. Boot with `./boot.sh`.
2. Start a long-running background process.
3. Run `/sbin/shutdown`.
4. Confirm QEMU exits by PSCI, not by `Ctrl+A, X`.
5. Boot again and verify recent filesystem writes if the test touched storage.

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
