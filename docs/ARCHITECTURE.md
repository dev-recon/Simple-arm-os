# ArmOS Architecture Notes

This document describes the current high-level architecture of ArmOS. It is
intended for contributors who need to understand the kernel before touching MMU,
task switching, process memory, filesystems, drivers, or userland ABI code.

ArmOS currently targets ARMv7-A on the QEMU `virt` machine, using a Cortex-A15
CPU model, short-descriptor page tables, split `TTBR0` / `TTBR1`, ASIDs, an
ext2 root filesystem, a FAT32 compatibility mount, procfs, VirtIO block I/O,
and a UART-backed TTY.

## Boot And DTB Detection

QEMU passes a Device Tree Blob (DTB/FDT) pointer to the kernel at boot. ArmOS
saves that pointer very early in `kernel/boot.S`, before clearing `.bss`, into
the global `dtb_address`.

Current boot contract:

```text
QEMU / ARM boot protocol  -> r2 contains ATAGS/DTB pointer
boot.S                    -> stores r2 in dtb_address
kernel C code             -> reads dtb_address
```

Some old comments still mention `R0 = DTB address`; the code path that matters
today stores `r2`. Treat the comments as cleanup candidates unless the boot
protocol is intentionally changed.

### FDT Parser Scope

ArmOS has a small in-kernel FDT parser, not a full libfdt port.

Implemented helpers include:

- FDT magic validation;
- big-endian `fdt32_to_cpu` conversion;
- node scan by prefix/name;
- property lookup inside a node;
- simple device-presence checks.

The parser is intentionally narrow. It is currently used for early platform
detection, not as a complete generic device model.

### Memory Detection From DTB

`kernel/memory/memory_detect.c` first tries to read the `/memory` node and its
`reg` property. On QEMU `virt`, that gives the RAM base and size.

Expected memory shape:

```text
memory.reg -> base 0x40000000, size detected from QEMU
```

If DTB parsing fails, ArmOS falls back to probing/intelligent detection paths.
The DTB path is preferred because it avoids guessing.

### DTB Reservation

The physical allocator reserves the DTB area before handing pages to the buddy
allocator.

Current behavior:

- `reserve_dtb_pages()` uses `dtb_address`;
- reserves a conservative 1 MB DTB window;
- moves `buddy_base` after the reserved DTB area;
- marks those pages used in the physical allocator.

This is important because QEMU places the DTB in RAM. If the buddy allocator
reused those pages, later DTB reads or platform probes could become corrupted.

### VirtIO Detection From DTB

The VirtIO block driver can discover its MMIO base from DTB.

Current behavior:

1. scan FDT nodes matching `virtio_mmio`;
2. read `reg`;
3. convert the physical MMIO base to the private kernel MMIO alias;
4. verify VirtIO magic and block-device ID;
5. derive or read the IRQ;
6. fall back to the old fixed VirtIO address if DTB probing fails.

The driver currently prefers the local QEMU virtio-mmio IRQ numbering derived
from the MMIO slot when available. DTB interrupt cells are parsed, but the GIC
routing still uses ArmOS' local interrupt numbering model.

### Contributor Rules For DTB Work

1. Keep DTB parsing read-only after boot unless a proper FDT ownership model is
   introduced.
2. Reserve DTB memory before the buddy allocator can reuse it.
3. Do not assume every device has hardcoded QEMU `virt` addresses forever.
4. Prefer DTB-derived MMIO base and IRQ values, with explicit fallback paths.
5. Be careful with endianness: FDT cells are big-endian.
6. Keep the parser small unless there is a concrete platform-porting need.

### DTB Cleanup Targets

- Fix stale boot comments that describe the wrong argument register.
- Use the real FDT `totalsize` for reservation instead of a fixed 1 MB window.
- Centralize FDT helpers in a dedicated `kernel/platform/` or `kernel/devicetree/`
  module if more drivers start using DTB.
- Parse `#address-cells`, `#size-cells`, and interrupt-parent data properly
  before relying on non-QEMU platforms.
- Expose useful platform facts through procfs later, for example
  `/proc/device-tree` or a minimal `/proc/platform`.

## Address Space Model

ArmOS uses a split virtual address space:

```text
0x00000000 - 0x3FFFFFFF   TTBR0   per-process user address space
0x40000000 - 0xFFFFFFFF   TTBR1   global kernel address space
```

The effective split boundary is `0x40000000`. The MMU setup writes `TTBCR.N=2`
for this layout. Some older comments and helper names still mention other split
sizes; treat those as historical unless the runtime register setup says
otherwise.

### Kernel Direct Map

Kernel RAM is still direct-mapped:

```text
kernel virtual address == physical RAM address
```

The QEMU `virt` RAM base is `0x40000000`, and kernel/RAM sections at and above
that address are mapped through `TTBR1` with the same virtual and physical
address.

This is a deliberate simplifying contract used throughout the kernel:

- the buddy allocator returns addresses in kernel RAM;
- those returned addresses can be dereferenced directly by the kernel;
- the same numeric address is often used as the physical frame address inserted
  into user page tables;
- block drivers and low-level memory code assume RAM pages are directly
  reachable by the kernel.

Example pattern:

```c
void *page = allocate_page();
map_user_page(vm->pgdir, user_vaddr, (uint32_t)page, flags, vm->asid);
```

This works because `page` is both a valid kernel pointer and the physical RAM
address of the frame.

Do not replace this with arbitrary virtual mappings without first introducing
explicit translation helpers such as:

```c
phys_to_kva(pa)
kva_to_phys(va)
is_kernel_direct_map(va)
```

The direct map is simple and fast on QEMU `virt`, but it is also a portability
boundary. Raspberry Pi, AArch64, high memory, stricter DMA, or non-identity
kernel mappings would require making this contract explicit everywhere.

### User Address Spaces

User processes do not run identity-mapped.

Each process owns a `vm_space_t` with its own `TTBR0` page directory and ASID.
User virtual addresses below `0x40000000` map to physical frames allocated from
kernel RAM.

Typical user layout:

```text
0x00008000 / 0x00010000   ELF text/data area
0x08000000                user heap start
0x30000000 - 0x33FFFFFF   shared memory window
0x3F000000                user stack top
0x3FFFF000                upper user/signal boundary
```

Example mapping:

```text
user VA 0x00008000 -> PA 0x54ABC000
user VA 0x08000000 -> PA 0x54DEF000
```

So from userland, virtual addresses are stable process-local addresses. They are
not physical addresses and must never be trusted by the kernel without
`copy_from_user`, `copy_to_user`, or a controlled temporary mapping path.

### TTBR Responsibilities

`TTBR0`:

- active user process mappings;
- process-specific page tables;
- ASID-tagged translations;
- switched on context switch.

`TTBR1`:

- global kernel mapping;
- direct-mapped kernel RAM;
- kernel text/data/bss/stacks;
- kernel temporary mappings;
- private MMIO aliases;
- not copied into user address spaces.

The task context stores the process `TTBR0` and ASID. The scheduler/task switch
path restores them when switching to another user process. Kernel mappings stay
global through `TTBR1`.

## MMU Runtime Model

ArmOS uses ARMv7-A short-descriptor page tables.

At runtime:

- `TTBR0` points to the active process page directory;
- `TTBR1` points to the global kernel page directory;
- `TTBCR.N=2` selects the `0x40000000` split boundary;
- user translations are ASID-tagged;
- kernel translations are global through `TTBR1`.

The MMU bring-up path creates enough early mappings to keep the kernel running
while switching from physical execution assumptions to the final split model.
After that point, contributors should reason in terms of:

```text
user pointer      -> TTBR0, process-local, must be copied/validated
kernel pointer    -> TTBR1, global, direct-map or kernel alias
physical address  -> frame/device address inserted into descriptors or MMIO
```

Do not treat these three categories as interchangeable, even though direct-map
RAM currently makes some numeric values equal.

### Page Table Shape

The kernel uses:

- L1 section mappings for large kernel/RAM and MMIO regions;
- coarse L1 entries pointing to L2 tables for user pages;
- 4 KB small pages for normal user mappings.

User page table helpers create L2 tables lazily. If a user page is mapped,
unmapped, remapped, made read-only, or made writable, the code must keep the PTE
and TLB state coherent for the target ASID.

## ASID Model

ASIDs let ArmOS keep user TLB entries tagged by process address space instead
of globally flushing on every context switch.

Current expectations:

- each `vm_space_t` owns an ASID;
- the task context stores the active `TTBR0` and ASID;
- context switch restores both the page directory and ASID;
- user TLB invalidations should target the page/ASID when possible;
- ASID rollover must flush stale user translations before reusing identifiers.

The ASID pool is intentionally small on ARMv7. Stress tests that create many
short-lived processes can trigger ASID rollover. That is expected; stale
translations after rollover are not.

Contributor rules:

1. Never reuse an ASID without going through the VM/ASID allocator.
2. Do not cache process address-space assumptions outside `vm_space_t` and task
   context.
3. Any code that changes a user PTE must invalidate the relevant user
   translation.
4. Treat ASID rollover as a normal runtime path, not an exceptional debug-only
   path.

Useful diagnostics:

- `lps` reports ASID rollover counters;
- crash dumps print `TTBR0`, `TTBR1`, `TTBCR`, and page-table walks;
- procfs/task diagnostics should remain ASID-aware.

## MMIO Mapping

Drivers should use the private kernel MMIO aliases, not raw low physical device
addresses.

Current aliases:

```text
0xF0000000   GIC
0xF0100000   UART / RTC window
0xF0200000   VirtIO window
```

These aliases live in `TTBR1`, keeping runtime driver access in kernel space.
Some low identity/device mappings may still exist for bootstrapping and
compatibility, but new driver work should prefer the high aliases.

## Page Mapping Rules

Contributors should follow these rules:

1. User virtual addresses must be below the split boundary.
2. Kernel pointers must not be accepted from userland.
3. A value returned by `allocate_page()` is currently a kernel direct-map
   pointer and a physical frame address.
4. User page table entries should receive physical frame addresses, not random
   kernel virtual addresses outside the direct map.
5. On changes to user PTEs, invalidate the relevant TLB entry with the correct
   ASID.
6. Do not map MMIO into user `TTBR0` unless a real device-user ABI is being
   designed.
7. Keep `copy_from_user` / `copy_to_user` boundaries strict, especially around
   `execve`, signals, filesystem syscalls, and pipes.

## Process Memory

Process memory is represented by VMAs plus page-table state.

Important regions include:

- executable mappings loaded by `execve`;
- user heap grown by `brk` / `sbrk`;
- user stack;
- signal frame region;
- shared memory mappings;
- copy-on-write fork mappings.

The fork path creates a child address space with its own `TTBR0`. Copy-on-write
state is tracked through page permissions and page fault handling. Kernel RAM
identity mapping makes it possible for the kernel to copy and inspect physical
frames directly, but the user-visible mappings remain process-local.

## Context Switching And Syscalls

The kernel supports switching away from a process while it is inside a syscall.
This matters for syscalls such as `waitpid`, `nanosleep`, pipe I/O, TTY reads,
and block I/O waits.

The key rule is:

```text
If a task yields while still executing in kernel/SVC context, it must resume in
kernel/SVC context with its saved kernel stack pointer.
```

The task switch path must not confuse:

- a syscall returning normally to user mode; with
- a blocked syscall resuming its kernel call chain.

ArmOS stores both user context and kernel/SVC context. The syscall entry path
saves the canonical user registers. The task switch path saves the current
kernel stack pointer when switching out. Resuming a blocked syscall must restore
that saved kernel stack, not reset to the top of the SVC stack.

This was a historically important bug class in ArmOS: if a blocked syscall was
restored as if it were ready to return directly to userland, the kernel call
chain was abandoned and the SVC stack appeared corrupted.

## Scheduler

ArmOS uses kernel tasks and user processes represented by `task_t`. User
processes have an attached process structure and VM space; pure kernel threads
do not necessarily have user memory.

Important scheduler concepts:

- each task has a dedicated kernel stack;
- each user task stores user registers and kernel/SVC resume state;
- ready/running/sleeping/stopped/zombie states drive scheduling decisions;
- the scheduler must never run a dead or zombie task;
- the idle task is a kernel task and remains built into the kernel;
- init is currently a userland process and is responsible for userland process
  supervision/reaping policy.

The ready queue is a kernel-owned structure. Code that changes task state must
be careful about interrupt state and queue membership. A task should not be
inserted twice into the ready queue, and a task that is no longer runnable must
not remain schedulable.

### Blocking In Kernel

Many kernel paths may block before their syscall has completed:

- `waitpid`;
- `nanosleep`;
- pipe reads/writes;
- TTY reads;
- VirtIO waits;
- filesystem/block I/O paths.

When this happens, the task is still executing on its kernel stack. The context
switch must save and later restore that kernel stack exactly. Returning directly
to userland is only valid after the syscall handler has completed the syscall
return path.

This is one of the most important invariants in the kernel.

## Timer And Preemption

The ARM generic timer drives periodic scheduling.

The timer interrupt updates kernel time and may request rescheduling. ArmOS is
designed to tolerate timer-driven preemption around syscall boundaries and
inside carefully controlled kernel wait paths.

Practical model:

- the timer IRQ should keep its own work short;
- it may set a reschedule flag;
- syscall return paths and scheduler-safe points honor that request;
- sleeping tasks are woken when their deadline expires;
- long critical sections should avoid keeping interrupts disabled longer than
  necessary.

The scheduler quantum is a tuning parameter, but it is also a stress tool. A
short quantum exposes missing critical sections and context-save bugs quickly.
A longer quantum can make the system feel more responsive under slow emulated
I/O because it reduces context-switch churn.

Contributor rules:

1. Do not call heavy filesystem or block code directly from timer IRQ context.
2. Keep IRQ-disabled sections small.
3. Assume a task can be interrupted frequently.
4. Any code that yields in kernel mode must preserve the kernel call chain.
5. Treat `nanosleep`, TTY reads, pipe waits, and VirtIO waits as preemption
   test cases.

## Interrupts And Exception Context

ARM exception modes have banked registers and stacks. ArmOS relies on separate
mode stacks for exception handling.

Important implications:

- SVC mode owns the syscall/kernel execution stack for a task;
- IRQ mode handles interrupts and must not corrupt SVC task state;
- abort/undefined handlers need valid mode stacks before printing diagnostics;
- user banked `SP/LR` must be restored correctly before returning to user mode;
- exception dumps should capture banked registers early, before helper calls
  clobber useful state.

When debugging crashes, prefer preserving exception diagnostics over making the
handler pretty. The page-table walk information in abort handlers is often the
fastest way to distinguish user pointer bugs, kernel pointer bugs, stale ASIDs,
and missing mappings.

## Block Device, VFS, Ext2 And FAT32

The storage stack is layered:

```text
VirtIO block driver
        |
sector read/write API
        |
fixed ArmOS disk partition layout
        |
filesystem drivers: ext2, FAT32
        |
VFS inode/file_operations layer
        |
syscalls: open/read/write/getdents/stat/link/unlink/rename/...
        |
newlib/userland commands
```

### VirtIO Block

The active block driver is `kernel/drivers/virtio_block.c`.

Current model:

- VirtIO MMIO device on QEMU `virt`;
- DTB-based MMIO base discovery when possible;
- fallback fixed MMIO base for compatibility;
- private kernel MMIO alias through `KERNEL_MMIO_VIRTIO_ADDR`;
- one global legacy split virtqueue;
- synchronous read/write request submission;
- interrupt-driven completion when available;
- polling/timeout fallback around used-ring progress;
- one active block operation serialized by `virtio_blk_lock`;
- optional device flush support if `VIRTIO_BLK_F_FLUSH` is negotiated;
- read-only device detection through VirtIO feature bits;
- request bounds checks against detected device capacity.

The driver exposes the generic sector API used by filesystems:

```c
int blk_read_sectors(uint64_t lba, uint32_t count, void *buffer);
int blk_write_sectors(uint64_t lba, uint32_t count, void *buffer);
int blk_read_sector(uint64_t lba, void *buffer);
int blk_write_sector(uint64_t lba, void *buffer);
```

Contributor rules:

1. Keep VirtIO request buffers in kernel direct-map RAM unless DMA translation
   is introduced explicitly.
2. Do not hold unrelated filesystem locks while waiting for VirtIO completion.
3. Always clear pending wait state after request completion, timeout, or error.
4. Treat timeout as device failure and avoid silently reusing a bad queue.
5. Keep cache/DMA barriers around descriptor, avail ring, used ring, data, and
   status buffers.
6. Keep QEMU `virt` limitations visible: this is not yet a general PCI/VirtIO
   transport layer.

### Disk Partition Layout

ArmOS currently uses a simple fixed disk image layout described in
`include/kernel/disk_layout.h`:

```text
virtio0p1   ext2    LBA 0             64 MB   root filesystem
virtio0p2   FAT32   LBA after p1      64 MB   compatibility mount
```

The root filesystem is ext2. FAT32 is kept for compatibility and cross-checking,
not as the canonical full userland filesystem.

This is intentionally simpler than parsing a real MBR/GPT. If real partition
table support is added later, keep this static layout as a fallback until the
new path is heavily tested.

### VFS

The VFS layer provides common in-memory `inode_t`, `file_t`,
`inode_operations_t`, and `file_operations_t` abstractions.

VFS responsibilities:

- path lookup and symlink resolution;
- mount table dispatch;
- file descriptor allocation;
- permission checks;
- open/read/write/lseek/getdents/stat/fstat/lstat routing;
- common handling for `/`, `/proc`, `/dev`, `/mnt`, and mounted roots.

Mount table entries store:

```text
mount path
source
filesystem type
options
root inode
```

The root ext2 filesystem is considered the base filesystem. Additional mounts
such as procfs and FAT32 are resolved by longest matching mount path.

### Ext2

Ext2 is the primary ArmOS filesystem.

Implemented capabilities include:

- mount from a partition LBA;
- superblock and group descriptor parsing;
- inode load/store;
- directory lookup and readdir;
- regular file read/write;
- file creation/truncation/append;
- mkdir/rmdir;
- unlink;
- rename inside ext2;
- hard links;
- symlinks and readlink;
- chmod/chown metadata updates;
- stat/statfs/fstat support;
- block and inode bitmap updates;
- direct, single-indirect, and double-indirect block paths as implemented by
  the driver.

Ext2 operations are protected by an ext2 operation lock. This keeps the current
implementation simple. Be careful not to hold that lock across unrelated
blocking paths longer than necessary.

Contributor rules:

1. Keep on-disk metadata updates ordered and check every write return.
2. Update inode metadata in memory and on disk consistently.
3. Keep link counts correct for files, directories, hard links, and symlinks.
4. Never leave partially-created directory entries after allocation failure.
5. Test create/write/truncate/append/rename/unlink/rmdir paths through
   `systest`.
6. Run persistence tests with `sync`, `shutdown`, then `boot.sh`.

### FAT32

FAT32 is the compatibility filesystem, usually mounted at `/mnt`.

It exists to keep a simple exchange/test filesystem around, but it is no longer
expected to mirror the full ext2 root filesystem.

Current role:

- list/read/write simple files;
- compatibility mount for `/mnt`;
- exercise VFS cross-filesystem behavior;
- provide an intentionally simpler filesystem for regression comparison.

Important differences from ext2:

- FAT32 permissions are synthesized, not native Unix metadata;
- ownership/link semantics are limited;
- long filename support may differ from ext2;
- cross-filesystem rename needs userland fallback (`copy` + `unlink`) rather
  than a pure VFS rename;
- directory and allocation semantics are less Unix-like.

Contributor rules:

1. Do not assume ext2 features exist on FAT32.
2. Keep user-facing tools tolerant of cross-filesystem differences.
3. Test `/mnt` explicitly when changing VFS-generic code.
4. Prefer ext2 for canonical ArmOS behavior and FAT32 for compatibility.

### Sync And Persistence

The persistence path is:

```text
filesystem metadata/data writes
        |
blk_write_sector(s)
        |
virtio request
        |
optional VirtIO flush
        |
shutdown / boot.sh verification
```

For changes that touch storage, a useful manual test is:

```sh
echo persistent > /tmp/persist.txt
sync
shutdown
./boot.sh
cat /tmp/persist.txt
```

If QEMU is killed with `Ctrl+A, X`, recent userland state such as shell history
or filesystem writes may not have the same clean shutdown behavior. Prefer the
ArmOS `shutdown` command when validating persistence.

## Filesystem Layout

The default runtime layout is:

```text
/                  ext2 root filesystem
/proc              procfs
/mnt               FAT32 compatibility mount when mounted
/dev               device nodes
/bin               core utilities
/sbin              system programs
/usr/bin           ArmOS user programs
/opt/<tool>/bin    imported external tools
/legacy            archived legacy userland
```

Ext2 is the primary filesystem. FAT32 remains useful for compatibility and
testing, but it is not expected to mirror the full root filesystem.

## Userland Direction

Newlib is the supported C library path for current userland development.

The older in-tree libc and older programs are archived for reference and
bring-up archaeology. New commands should use the newlib build path unless a
specific legacy investigation requires otherwise.

## Portability Notes

The current architecture is intentionally practical for QEMU `virt`. The main
assumptions to revisit for another board or architecture are:

- RAM starts at `0x40000000`;
- kernel RAM is directly mapped as `VA == PA`;
- device MMIO addresses match QEMU `virt`;
- ARMv7 short-descriptor page tables are used;
- the split boundary is `0x40000000`;
- the kernel runs 32-bit ARM, not AArch64;
- DMA-capable buffers are reachable through the direct map.

Before porting, introduce explicit physical/virtual conversion helpers and
audit all places where a `uint32_t` is used interchangeably as a physical
address, kernel pointer, or user virtual address.

## Known Cleanup Targets

- Rename or fix stale TTBR split comments and helper names.
- Audit linker symbols that are wider than 32-bit address space expectations.
- Make physical addresses and kernel virtual addresses distinct in type names.
- Continue reducing old MMU debug paths that no longer represent the runtime
  design.
- Keep crash dumps and page-table walkers; they are still valuable diagnostics.
