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
