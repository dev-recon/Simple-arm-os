# ArmOS POSIX Compatibility Roadmap

This document tracks source-level POSIX compatibility work for ArmOS. It is
not a certification claim and it is not a request to mirror another kernel's
syscall ABI. POSIX specifies application-visible behavior; ArmOS remains free
to implement that behavior with a smaller architecture-neutral kernel ABI and
newlib wrappers.

The current common dispatcher exposes 100 syscall entries. It already covers
the central Unix process, VFS, descriptor, signal, virtual-memory, TTY, polling
and identity contracts. The next stage is therefore semantic completion and a
small number of missing primitives, not one syscall for every function listed
in the POSIX System Interfaces volume.

## Design Rules

- All architectures use the same syscall numbers, kernel implementations and
  POSIX behavior. Architecture code only marshals registers and handles
  CPU/MMU-specific state.
- Add a syscall only when the behavior cannot be implemented correctly in
  newlib from existing primitives.
- A symbol that always succeeds without enforcing its contract is not treated
  as implemented.
- Optional POSIX facilities must be reported honestly through `<unistd.h>`,
  `sysconf()`, `pathconf()` and `fpathconf()`.
- Every new contract must be tested on the reference `arm32/qemu-virt` target
  and then on `arm64/qemu-virt` and `arm64/raspi3` where applicable.

## Current Baseline

The following families are already connected to the common kernel:

| Area | Existing foundation |
| --- | --- |
| Processes | `fork`, `execve`, `_exit`, `waitpid`, `wait4`, process groups and sessions |
| Descriptors | `open`, `close`, `read`, `write`, `readv`, `writev`, `lseek`, `dup`, `dup2`, partial `fcntl` |
| VFS | `stat`, `lstat`, `fstat`, `getdents`, links, directories, ownership, permissions and truncation |
| Signals | `kill`, `sigaction`, `sigprocmask`, `sigpending`, `sigsuspend` and signal return |
| Memory | `brk`, private `mmap`, `munmap`, partial `mprotect` and ArmOS shared-memory calls |
| Waiting | `select`, `poll`, `nanosleep`, pipes and blocking TTY I/O |
| Time and accounting | `time`, `gettimeofday`, `clock_gettime`, `clock_getres`, `times`, `getrusage`, priorities and capability-aware `sysconf` |
| Networking | Minimal passive IPv4/TCP socket, `bind`, `listen` and `accept` path |

## Priority Axes

### P0 - ABI Truth And Core Primitives

This axis removes misleading or incomplete contracts and supplies primitives
needed by a broad range of otherwise simple Unix programs.

| Interface or family | Current state | Required work |
| --- | --- | --- |
| `sched_yield` | Implemented | Common scheduler handler and symmetric ARM32/ARM64 wrappers |
| `clock_gettime`, `clock_getres` | Realtime and monotonic clocks implemented | Preserve the common UAPI and improve realtime resolution when hardware RTC support grows |
| `clock_nanosleep` | Missing | Build absolute and relative sleep on the scheduler deadline mechanism |
| `pread`, `pwrite` | Implemented for seekable files | Preserve the shared open-file offset and reject non-seekable descriptors with `ESPIPE` |
| `openat` and `*at` path operations | Missing | Add dirfd-aware VFS path resolution, then expose `fstatat`, `unlinkat`, `renameat` and `mkdirat` |
| `fchmod`, `fchown` | Missing | Apply ownership and mode changes through an open descriptor |
| `fdatasync` | Missing | Reuse filesystem flush machinery while excluding unrelated metadata where possible |
| `sysconf` | Limits, memory, CPUs, I/O vectors and selected capabilities implemented | Keep partial facilities explicitly unsupported and add selectors only with their complete contracts |

Acceptance criteria:

- the interfaces have identical semantics on ARM32 and ARM64;
- invalid descriptors, pointers, clocks and flags return the documented error;
- `pread` and `pwrite` do not move the descriptor offset;
- dirfd-relative operations remain correct if the process working directory
  changes concurrently;
- `systest` contains ABI and behavioral tests for every added primitive.

### Delivered P0 Foundation

The first P0 increment establishes three contracts shared by every
architecture:

- `sched_yield()` enters the common scheduler and never carries
  architecture-specific scheduling policy;
- `clock_gettime()` and `clock_getres()` expose `CLOCK_MONOTONIC` from the ARM
  generic counter and `CLOCK_REALTIME` from the current ArmOS wall-clock
  source;
- a fixed UAPI time structure isolates the kernel from newlib's different
  ARM32 and ARM64 `struct timespec` layouts. The released 32-bit `nanosleep`
  wire layout remains stable and newlib translates it explicitly.

Realtime resolution is currently one second because ArmOS only has a
second-resolution wall-clock source. The monotonic clock uses the effective
platform counter frequency and reports its corresponding nanosecond
resolution. Neither result is derived from a CPU delay-loop calibration.

`sysconf()` now distinguishes three outcomes: a numeric limit, a supported
optional capability, and a known but unsupported capability. The latter
returns `-1` without changing `errno`, as POSIX requires. In particular,
ArmOS does not yet claim `_SC_VERSION`, `_SC_TIMERS`, `_SC_MAPPED_FILES`,
`_SC_MEMORY_PROTECTION`, `_SC_SHARED_MEMORY_OBJECTS`, or saved-ID support.

Positioned I/O uses a fixed signed 64-bit offset in the ArmOS UAPI. The common
kernel creates a private view of the open file for each `pread()` or `pwrite()`
operation, so backend reads and writes can advance that private cursor without
changing the offset shared by `dup()` or `fork()`. `pwrite()` also honors its
explicit offset on an `O_APPEND` descriptor. Current ext2 and FAT32 inode sizes
remain 32-bit; newlib reports `EOVERFLOW` before entering the kernel when an
application requests an offset outside that filesystem range.

### P1 - Complete Existing Contracts

This axis turns currently partial implementations into dependable POSIX
building blocks.

| Interface or family | Current limitation | Required work |
| --- | --- | --- |
| `mmap` | No non-zero file offset, `MAP_SHARED`, `MAP_FIXED` or `PROT_NONE` | Pass an offset through the ABI, support shared mappings and define safe fixed-map replacement rules |
| `mprotect` | Only accepts an exact complete VMA | Split and merge VMAs for arbitrary page-aligned subranges |
| `msync` | Missing | Flush dirty shared file-backed pages through VFS |
| `fcntl` locks | Lock requests are accepted but not enforced | Add open-file-description lock state, conflict detection and interruptible `F_SETLKW` waiting |
| `pselect`, `ppoll` | Mask change and wait are separate operations | Make signal-mask replacement and blocking atomic in the kernel |
| `getrlimit`, `setrlimit` | Mostly static newlib responses | Store and enforce at least file, address-space, data, stack, core and CPU limits |
| `statvfs`, `fstatvfs` | Only non-POSIX `statfs` exists | Add a stable POSIX structure and VFS translation |
| `futimens`, `utimensat` | Only second-resolution `utime` exists | Support descriptor-relative nanosecond timestamps |
| Process identity | Basic UID/GID only | Add effective-ID changes, supplementary groups and complete permission checks |
| `waitid` | Missing | Expose non-destructive status queries and the required selection modes |

Acceptance criteria:

- partial mappings can be protected and unmapped without damaging adjacent
  regions;
- shared mappings are visible between processes and persist through `msync`;
- descriptor locks block and wake without spinning;
- signal delivery cannot be lost between mask replacement and `pselect` or
  `ppoll` sleep;
- resource limits are enforced by the subsystem that consumes the resource.

### P2 - Threads And POSIX Synchronization

The generic task and SMP scheduler foundations already exist, but ArmOS does
not yet expose a POSIX thread runtime. This axis should introduce a small
kernel substrate instead of a syscall per `pthread_*` function.

Kernel primitives required:

- create and exit a thread sharing its process VM and descriptor table;
- join or wait for thread termination;
- set and restore architecture-specific thread-local storage;
- wait on and wake a user-memory word, with timeout and signal interruption;
- preserve per-thread signal masks, CPU accounting and robust cleanup state.

Newlib can then implement mutexes, condition variables, read/write locks,
barriers, `pthread_once`, thread-specific data and most semaphore operations in
userspace. Named semaphores and process-shared objects may use VFS/shared-memory
objects plus the same wait/wake primitive.

Acceptance criteria:

- thread creation does not duplicate the process VM;
- blocking synchronization consumes no CPU while waiting;
- process exit terminates and reaps all threads safely;
- SMP stress covers contention, timeout, signal interruption and owner death.

### P3 - Complete Socket And Asynchronous Interfaces

The existing network path is a diagnostic passive TCP server, not yet a POSIX
socket implementation.

| Family | Required work |
| --- | --- |
| Connected TCP | Complete active `connect`, retransmission, close and error state |
| Data transfer | Add `sendto`, `recvfrom`, `sendmsg` and `recvmsg` |
| Socket control | Add `getsockopt`, `setsockopt`, `getsockname`, `getpeername` and socket `shutdown` |
| Local IPC | Add `socketpair`, preferably over a generic local socket backend |
| Datagram support | Add UDP only after generic socket state and addressing are separated from netecho |
| POSIX timers | Add `timer_create`, `timer_settime`, `timer_gettime`, overrun accounting and deletion |
| Asynchronous I/O | Begin with a newlib worker-thread implementation; add kernel support only if measurements justify it |

Network work must not bake VirtIO details into the socket API. Raspberry Pi
and QEMU network drivers must feed the same protocol and descriptor layers.

## Interfaces That Should Stay In Newlib

These functions can be composed from the kernel primitives and should not
receive dedicated syscalls:

- `system`, `popen`, `posix_spawn` and the `exec*` family;
- `sleep`, `usleep`, directory streams and pathname helpers;
- `mkfifo`, `realpath`, `dirname`, `basename` and passwd-file lookup;
- static portions of `pathconf`, `fpathconf` and `confstr`;
- most pthread synchronization operations once wait/wake and TLS exist;
- an initial asynchronous-I/O implementation based on worker threads.

## ABI Cleanup

Two current ArmOS names conflict with established POSIX contracts:

- ArmOS `shm_open(name, size, flags)` is not POSIX `shm_open(name, oflag,
  mode)`. Keep the existing mechanism under an ArmOS-specific name while a
  descriptor-based POSIX shared-memory interface is introduced.
- `ARMOS_NR_SHUTDOWN` powers off the machine, while POSIX `shutdown()` operates
  on a socket. Rename the internal operation to `poweroff` before adding socket
  shutdown, while preserving the old syscall number as a compatibility alias.

The public syscall-number header should eventually describe the complete
shared ABI. Kernel-only duplicate number definitions should be reduced once
ARM32 and ARM64 wrappers consume that header from generated assembly constants.

## Delivery Order

1. Wire `sched_yield`; add monotonic/realtime clock queries and honest
   capability reporting.
2. Add position-based I/O and dirfd-aware path resolution.
3. Complete file metadata, synchronization and atomic polling contracts.
4. Complete `mmap`/`mprotect`, then provide POSIX shared memory and `msync`.
5. Add the minimal thread wait/wake and TLS substrate, then implement pthreads
   primarily in newlib.
6. Generalize the socket layer and only then broaden network protocols.
7. Maintain a generated conformance matrix mapping every targeted POSIX
   interface to `kernel`, `newlib`, `optional`, `partial` or `unsupported`.
