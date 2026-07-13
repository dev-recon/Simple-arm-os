# ArmOS Roadmap

This roadmap tracks the Linux-1.0-inspired workstreams currently active in
ArmOS. The goal is not to clone Linux line by line, but to converge toward the
same useful Unix contracts while keeping the kernel understandable and
debuggable.

## v0.6 Baseline

The v0.6 baseline is:

- stable public profile: `SMP_CPUS=1`;
- developer stress profile: `SMP_CPUS>1`;
- UART `tty0` is the required recovery console;
- optional graphical `tty1` remains additive;
- ext2 root is 512 MB inside a real MBR-partitioned `disk.img`;
- newlib is the supported libc;
- TinyCC is the native end-user compiler path;
- ncurses and nano are optional generated bundles;
- multi-arch work includes an ARM64/QEMU-virt EL1 serial bootstrap, exception
  vectors, a minimal long-descriptor identity MMU, GICv2/generic-timer IRQ
  delivery, a shared early page allocator, and FDT-driven RAM/reservation
  discovery, allocated TTBR0 L1/L2/L3 tables, and a permission-checked TTBR1
  kernel alias now used for the live PC, stack, and vectors after retiring the
  complete low kernel/MMIO map; isolated user-only TTBR0 tables and ASID
  switching are validated; a first EL0t smoke payload runs with separate
  RX and RW/NX mappings, returns through SVC, and preserves timer IRQ delivery,
  and a bootstrap user-VM object now owns its tables, pages, mappings, and ASID,
  while a bounded `svc #0` dispatcher validates the AArch64 register ABI,
  user-buffer faults, unknown calls, and `exit`; EL0 entry and lower-EL
  exception capture now share an explicit register image with generated
  C/assembly offsets and preservation checks; a bootstrap task context also
  performs a validated two-stack cooperative switch of `x19-x30`, SP and its
  resume PC, and the switch boundary now activates and verifies each context's
  TTBR0/ASID identity; mapping generations preserve unchanged resident ASIDs
  without per-switch TLBI on the single bootstrap CPU; the bootstrap task now
  allocates, clears, and releases its owned high-half kernel stack with exact
  page-accounting checks, and that probe now uses the generic `task_t` identity,
  state, stack metadata, and lifetime guards; task-level switching now moves
  `RUNNING/BLOCKED` state and CPU ownership between the borrowed bootstrap stack
  and owned probe stack; a bounded single-CPU generic FIFO now publishes the
  blocked probe as ready, rejects duplicate publication, selects it, and drives
  two validated cooperative switch cycles; two simultaneously ready tasks now
  rotate deterministically in `A, B, A, B` order with independent owned stacks
  and balanced page recovery; a reusable dispatcher now owns current-task,
  yield, block, requeue, rollback, and safe-point preemption policy; a
  generic EL0 task now yields through SVC, resumes after the trap, and exits by
  blocking through that dispatcher; physical timer events now coalesce into
  `need_resched`, defer while preemption is disabled, and switch a kernel task
  only after IRQ acknowledgement at a complete exception-return frame; a real
  lower-EL timer IRQ also suspends an EL0 task on its owned kernel stack, runs a
  kernel peer, and resumes the interrupted user computation before normal
  exit; the full Unix kernel and userland remain ARM32.

Post-v0.6 hardware milestone:

- Raspberry Pi 3 boots as a dedicated AArch32 platform;
- four Cortex-A53 CPUs participate in scheduling and pass sustained `kload`;
- SD/eMMC, ext2 root, UART console, procfs diagnostics, and shutdown are usable;
- framebuffer/input/network remain future Raspberry Pi milestones;
- ASID-aware context-switch optimization remains blocked on a hardware-correct
  residency and invalidation design.

## 1. Unix Permissions

Status: started.

Immediate goals:
- Enforce read/write/execute permissions consistently at `open`, `access`, and
  `execve` boundaries.
- Keep root (`uid 0`) semantics explicit.
- Tighten ownership rules for administrative calls such as `chown`.
- Add regression coverage for user/root access decisions.

First milestone: implemented.
- `open()` maps its access flags to inode permission checks.
- `O_TRUNC` happens only after write permission is granted.
- `systest` covers read/write permission denial for non-root users.

## 2. `/dev` And TTY

Status: active and usable.

Immediate goals:
- Preserve tty0/UART as the recovery console in every boot mode.
- Keep tty1/virtio-gpu optional and isolated from tty0 failure paths.
- Continue improving termios, canonical/raw behavior, job control, and device
  aliases such as `/dev/tty`, `/dev/tty0`, `/dev/tty1`, `/dev/console`, and
  `/dev/null`.
- Prepare the line discipline so future framebuffer/keyboard backends do not
  leak backend details into userland.

First milestone:
- `/dev/tty` resolves through the process controlling terminal.

## 3. `/proc`

Status: active.

Immediate goals:
- Keep Linux-like low-risk files (`meminfo`, `uptime`, `stat`, `mounts`,
  `interrupts`, `tty`, `net/dev`) readable from userland.
- Expand per-process entries (`status`, `stat`, `maps`, `fd`, `cwd`, `exe`,
  `root`) without holding scheduler locks while formatting large outputs.
- Add simple network visibility under `/proc/net`.

First milestone: implemented.
- Add `/proc/net/tcp` as a minimal TCP visibility endpoint.

## 4. Syscalls And Toolchain Support

Status: active.

Immediate goals:
- Keep newlib as the reference libc.
- Keep `arm-none-eabi-gcc` as the kernel compiler and move userland toward
  native TinyCC incrementally.
- Fill the syscalls needed by small Unix tools and TCC before attempting larger
  packages.
- Keep syscall ABI glue documented and tested in `systest`.
- Avoid kernel changes driven only by TCC quirks unless they match a real Unix
  contract.

First milestone:
- Maintain `getcwd`, `fcntl`, `ioctl`, `stat`, `lstat`, `fstat`, `statfs`, and
  process-control syscalls as stable contracts.
- Keep experimental TCC sources out of the default userland build unless
  `ENABLE_TCC=1` is set.
- Native TCC can compile and run `hello.c`, and can compile/link the ArmOS kilo
  source as a first non-trivial interactive program.
- Optional ncurses/nano build scripts exist and should become part of a regular
  terminal UI validation profile.

## 5. VFS And ext2 Hardening

Status: active.

Immediate goals:
- Keep ext2 read/write paths robust under parallel userland tests.
- Improve cross-filesystem behavior for userland tools (`cp`, `mv`, `rm`).
- Add lightweight consistency checks for ext2 metadata and block allocation.
- Keep FAT32 as a compatibility filesystem mounted manually on `/mnt`.

First milestone:
- Keep permission checks and mount metadata coherent across VFS filesystems.

## 6. Minimal Networking

Status: active.

Immediate goals:
- Keep virtio-net DTB probing automatic.
- Maintain `/proc/net/dev` counters and IRQ visibility.
- Keep the current TCP echo path as a diagnostic stepping stone, not a full TCP
  stack contract.
- Add small userland tools before adding broad socket semantics.

First milestone: started.
- Expose TCP diagnostic state in `/proc/net/tcp`.
- Add a small `netstat` command based on `/proc/net/dev` and `/proc/net/tcp`.

## 7. Userland Init

Status: active.

Immediate goals:
- Keep `/sbin/init` in userland as PID 1.
- Keep zombie reaping reliable.
- Restart tty shells cleanly without coupling tty0 and tty1 lifetimes.
- Move toward a small declarative init configuration once the current behavior
  remains stable.

First milestone:
- Preserve tty0 user shell and optional tty1 root shell startup behavior.

## 8. Terminal UI Stack

Status: early but usable.

Immediate goals:
- Keep `TERM=armos` honest: terminfo should declare only ANSI capabilities that
  the console backend really implements.
- Use `cursestest`, `nano`, `kilo`, `top`, and `ttytest --interactive-*` as the
  terminal UI regression set.
- Keep ncurses/nano optional until build time and runtime behavior are boring.
- Preserve UART `tty0` behavior before every graphical or curses-related change.

First milestone: implemented.
- Static ncurses cross-build with compiled fallback terminfo.
- Tiny GNU nano cross-build staged under `/opt/nano/bin`.

## 9. Multi-Arch Preparation

Status: phase 0 landed.

Immediate goals:
- Restart the next multi-arch branch from the v0.6 `main` baseline.
- Continue replacing ambiguous address values with `paddr_t`, `vaddr_t`, and
  `pfn_t`.
- Keep generated `asm-offsets` as the only source of truth for C/ASM structure
  offsets.
- Keep FDT parsing centralized instead of adding more hardcoded QEMU addresses.
- Do not create a speculative HAL before a second concrete target exists.
- Track the active migration sequence in
  [`docs/MULTIARCH_MIGRATION.md`](MULTIARCH_MIGRATION.md).

First milestone: implemented.
- Generated assembly offsets.
- Shared FDT parser.
- Address-type groundwork.
