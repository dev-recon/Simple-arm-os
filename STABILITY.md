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
