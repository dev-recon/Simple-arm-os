# ARM64 Port

ArmOS now has an initial AArch64 target alongside the stable ARM32 kernel. The
first target is QEMU `virt`; Raspberry Pi 3 remains an AArch32 hardware target
until the generic ARM64 kernel contracts are ready.

## Completed Milestones

### Milestone 1: EL1 Serial Bootstrap

The current ARM64 target deliberately implements only the earliest boot path:

- AArch64 entry at `0x40080000`;
- boot CPU selection through `MPIDR_EL1`;
- EL2 to EL1h transition when required;
- 64 KiB boot stack and BSS initialization;
- PL011 output on QEMU `virt`;
- preservation and reporting of the QEMU DTB pointer.

It does not yet provide dynamic virtual memory, the full buddy allocator,
scheduler, filesystems, syscalls, SMP, or an ARM64 userland. Those remain on
the working ARM32 kernel while the 64-bit contracts are brought across
incrementally.

### Milestone 2: EL1 Exception Vectors

The bootstrap now installs a 2 KiB-aligned `VBAR_EL1` table with all 16 ARMv8-A
vector slots. Every entry builds a 288-byte architecture-local frame containing
`x0`-`x30`, `ELR_EL1`, `SPSR_EL1`, `ESR_EL1`, `FAR_EL1`, and the vector number.

Boot includes a recoverable `BRK #0x64` smoke test. The C dispatcher verifies
the current-EL/SPx synchronous vector and BRK exception class, advances
`ELR_EL1`, and returns through `ERET`. Unexpected exceptions print the same
register diagnostics and park the CPU.

### Milestone 3: EL1 Identity MMU

The bootstrap now enables ARMv8-A stage-1 translation with a 4 KiB granule and
a 39-bit TTBR0 address space. A 4 KiB L1 table installs two 1 GiB blocks:

- `0x00000000-0x3fffffff` as Device-nGnRE, outer-shareable and execute-never;
- `0x40000000-0x7fffffff` as normal WBWA, inner-shareable RAM.

`MAIR_EL1`, `TCR_EL1`, and `TTBR0_EL1` are installed before enabling the
`M`, `C`, and `I` bits in `SCTLR_EL1`. The bootstrap uses `AT S1E1R` and
`PAR_EL1` to verify that UART and kernel addresses translate while
`0x80000000` remains unmapped. A second BRK/ERET test runs after MMU activation
to prove that vectors, stack, code and MMIO remain coherent.

### Milestone 4: GICv2 And Generic Timer IRQ

The ARM64 QEMU profile explicitly selects `virt,gic-version=2`. The bootstrap
initializes the distributor and CPU interface at the standard QEMU addresses,
enables physical timer PPI 30, and programs `CNTP_TVAL_EL0` from
`CNTFRQ_EL0`. When boot entered through EL2, `CNTHCTL_EL2` grants EL1 physical
counter and timer access before `ERET`.

The smoke test unmasks IRQs, waits in `WFI`, handles three timer interrupts
through the current-EL/SPx IRQ vector, acknowledges each interrupt through
GICC IAR/EOIR, then masks and disables the timer. QEMU 10.0.2 reports a
62.5 MHz counter for the selected Cortex-A72 profile.

### Milestone 5: Shared Early Page Allocator

The first architecture-neutral kernel component now runs on ARM64. A small
bitmap allocator in `kernel/memory` manages 4 KiB physical pages before the
full memory manager, scheduler, and spinlocks exist. Its address and page types
come from the common kernel type contract, backed by ARM64 page and cache
geometry headers.

The QEMU bootstrap manages the page-aligned range after `__kernel_end`. Its
smoke test:

- reserves the first page and verifies that allocation skips it;
- allocates one page and a contiguous three-page extent;
- writes and reads patterns at both ends of the allocated memory;
- frees and reallocates a page to verify deterministic reuse;
- restores the initial free-page count after releasing temporary allocations.

This allocator is intentionally single-CPU and bounded. It is an early-boot
building block, not yet a replacement for the ARM32 buddy allocator.

### Milestone 6: FDT Memory Topology

A dependency-free reader in `kernel/lib/fdt_memory.c` now discovers physical
memory instead of relying on a platform constant. It validates all FDT block
offsets and lengths, supports one- and two-cell address/size tuples, and reads:

- every top-level `/memory` range;
- the FDT memory-reservation map;
- child `reg` ranges under `/reserved-memory`;
- the DTB's own address and exact `totalsize`.

With the QEMU 10.0.2 1 GiB profile, the bootstrap discovers RAM at
`0x40000000-0x7fffffff`, manages pages from the end of the kernel to
`0x80000000`, and reserves the 1 MiB DTB at `0x48000000`. The early bitmap is
explicitly sized for at most 1 GiB of RAM; larger profiles are rejected until
allocator metadata becomes dynamic.

### Milestone 7: Allocated L1/L2/L3 Tables

The static boot L1 table is now only the bridge used to enable translation.
After FDT discovery and early-page initialization, the bootstrap allocates
three contiguous 4 KiB pages for a new L1/L2/L3 hierarchy, cleans them to the
point of coherency, and switches `TTBR0_EL1` to the allocated L1.

The MMIO range remains a Device 1 GiB L1 block. The 1 GiB RAM range is split
into 2 MiB L2 blocks, while its first 2 MiB containing the kernel, stack, and
allocated tables is split again into 4 KiB L3 pages.

The replacement follows the required ordering around the TTBR write and a
local stage-1 TLB invalidation. Translation probes for PL011, kernel RAM, and
the unmapped `0x80000000` boundary are repeated after the switch. A dedicated
page is then removed from L3, checked as faulting through `AT S1E1R`, restored,
and checked for its original contents after a targeted `TLBI VAE1`. A BRK/ERET
round trip and a second three-interrupt timer test finally prove that vectors,
code, stack, MMIO, and IRQ delivery remain usable through the new hierarchy.

SMP-wide TLB invalidation is not enabled yet.

### Milestone 8: TTBR1 Kernel Alias And Permissions

The linker now aligns text, read-only data, and writable data on 4 KiB
boundaries and exports their exact ranges. Before switching to the allocated
tables, L3 descriptors enforce:

- kernel text: EL1 read/execute, read-only, inaccessible to EL0;
- kernel rodata: EL1 read-only and execute-never, inaccessible to EL0;
- kernel data, BSS, stacks, and allocator pages: EL1 read/write and
  execute-never, inaccessible to EL0.

A fourth allocated L1 is installed in `TTBR1_EL1`. It reuses the existing RAM
L2/L3 hierarchy and exposes the same physical pages at the canonical 39-bit
kernel offset `0xFFFFFF8000000000`; kernel text therefore appears at
`0xFFFFFF8040080000`. `TCR_EL1` now defines 4 KiB, inner-shareable WBWA walks
for both TTBR0 and TTBR1.

The smoke test compares data through low and high aliases, verifies their PAR
physical addresses, checks privileged read/write permissions, and confirms
that EL0 translation probes fail for text, rodata, and data.

### Milestone 9: High-Half Execution And Low Identity Retirement

An assembly trampoline now transfers the live PC, stack pointer, and
`VBAR_EL1` to their canonical TTBR1 aliases. Because kernel code is linked as
one position-preserving image, PC-relative calls and data references continue
to resolve within the same physical image after the offset is applied.

Once execution is demonstrably in `0xFFFFFF80...`, the high-half C entry clears
only TTBR0 L1 entry 1, which removes the `0x40000000-0x7fffffff` RAM identity
window. TTBR0 L1 entry 0 remains mapped as Device memory for the early PL011,
GICv2, and timer paths. TTBR1 retains the shared RAM L2/L3 hierarchy.

The post-transition smoke test verifies that the low kernel address faults,
the high text address still translates, and PL011 MMIO remains available. It
then takes and returns from a BRK through the high VBAR and receives three
physical timer interrupts with no low RAM alias present.

### Milestone 10: User-Only TTBR0 And ASIDs

The TTBR1 L1 now also maps the physical MMIO gigabyte as EL1-only Device
memory. Early UART and GIC accessors derive either the physical address or its
canonical kernel alias from the current PC, so the same drivers work on both
sides of the high-half trampoline. Once execution is high, both low L1 entries
are retired and no kernel RAM or MMIO mapping remains in TTBR0.

The bootstrap then exercises the first user-address-space contract. ASID 1
owns a private three-level TTBR0 with one RW/NX EL0 page at `0x00400000`;
ASID 2 owns an empty L1. Switching to ASID 2 makes the page fault, while
TTBR1 kernel text and MMIO remain translated. Switching back to ASID 1 restores
the page and its contents without changing TTBR1.

This is the page-table and context-switch primitive for future processes, not
yet integration with `task`, `vm_space`, the full allocator, or EL0 execution.

### Milestone 11: First EL0 Execution And SVC Return

The bootstrap now enters EL0t through an `ERET` trampoline with a private
three-page user layout: RX code at `0x00400000`, RW/NX data at `0x00401000`,
and an RW/NX stack at `0x00402000`. The code page is copied into place before
entry and receives the required data-cache clean and instruction-cache
invalidation. Mapping helpers reject writable executable user pages.

The copied payload uses its EL0 stack, invokes a private smoke-test SVC, resumes
in EL0 with the returned value, stores `0x1235` in its data page, and invokes a
second SVC to return to a registered EL1h continuation. The lower-EL AArch64
synchronous vector dispatches both calls and preserves the architectural SVC
return PC. A physical timer IRQ after the round trip confirms that exception
and interrupt state remains usable.

These two SVC numbers are bring-up probes only. They are not the public ArmOS
syscall ABI, and this payload is not yet owned by a scheduler task or
`vm_space`.

### Milestone 12: Owned Bootstrap User Address Spaces

User tables, mapped pages, and ASIDs are now grouped in an
`arm64_user_vm_t` instead of being assembled as unrelated values in the QEMU
platform bootstrap. The object creates its own three-level TTBR0 hierarchy,
allocates user pages through the early allocator, records mappings, enforces a
single L3 window and W^X, activates its own ASID, and can return every owned
page and the ASID on destruction.

An explicit lifecycle smoke test creates an address space, maps a page, rejects
an RWX mapping without leaking its temporary page, destroys the space, checks
the allocator balance, and verifies ASID reuse. The live EL0 and empty
isolation spaces are then created through the same API. This establishes the
ownership boundary that the future generic `vm_space` backend can adopt; the
allocator and ASID pool remain intentionally single-CPU bootstrap components.

### Milestone 13: AArch64 Syscall Register ABI

EL0 now uses `svc #0` with the AArch64 calling convention: the syscall number
is in `x8`, up to six arguments are in `x0` through `x5`, and the signed result
is returned in `x0`. The numeric namespace is shared with the existing ArmOS
ABI through `include/uapi/armos/syscall.h`; `exit` remains 1 and `write`
remains 4.

The bootstrap dispatcher implements bounded console `write` and controlled
`exit`. Before dereferencing an EL0 buffer, it asks the active
`arm64_user_vm_t` to validate every covered page and the required read
permission. The payload verifies a successful write, an unmapped-buffer
`-EFAULT`, an unknown-call `-ENOSYS`, and `exit(42)`. These are now real
register and error-return semantics, but `write` is still an early-console
backend rather than the generic VFS syscall implementation.

### Milestone 14: Explicit EL0 Register Context

EL0 entry no longer accepts loose entry-point and stack arguments. It consumes
an `arm64_user_context_t` containing `x0` through `x30`, `SP_EL0`, the return
PC, and PSTATE. The lower-EL exception frame embeds that exact structure as
its prefix, so syscall entry can capture a complete user register image and a
future task switch can reuse the same contract.

The C compiler now emits the context and exception-frame offsets consumed by
`el0.S` and `vectors.S`. The frame is 16-byte aligned and any layout change is
checked at compile time instead of relying on duplicated numeric offsets in
assembly. The EL0 smoke test seeds nonvolatile registers, crosses all four
syscall paths, and verifies the captured `x19`, `x20`, `x29`, `x30`, stack,
resume PC, and PSTATE before reporting `ARM64_EL0_CONTEXT_OK`.

This is a bootstrap register image, not yet a schedulable `task_context_t`.
Kernel callee-saved state, TTBR0 ownership, and scheduler switching will be
attached in later milestones.

### Milestone 15: Bootstrap Task Context Switch

The architecture now groups kernel callee-saved state, the existing EL0 image,
and TTBR0/ASID identity in an `arm64_task_context_t`. The kernel half saves
`x19` through `x30`, SP, and an explicit resume PC through offsets generated
from the C structure. Address-space switching remains separate so this
primitive can be tested before scheduler and runtime-ASID integration.

A cooperative probe starts on a dedicated 4 KiB kernel stack, switches back to
the bootstrap stack, resumes on its own stack, verifies preservation
sentinels, and switches back a second time. The live EL0 register image and its
TTBR0/ASID metadata are then carried by the same task-context object. Successful
boot reports `ARM64_TASK_CONTEXT_SWITCH_OK` before entering EL0.

This validates the architectural register-switch mechanism only. It does not
yet provide runnable queues, preemption, per-task stack allocation, or generic
`task_t` ownership.

### Milestone 16: Address-Space-Aware Context Switch

The task-switch boundary now validates the incoming context's TTBR0/ASID pair
and activates it before transferring kernel register state. Kernel-only
bootstrap contexts use an explicit zero pair; partially initialized pairs are
rejected. The assembly switch remains focused on registers while the C wrapper
owns MMU policy and error handling.

The two-stack probe is reused with the mapped user VM attached to the bootstrap
context and the empty VM attached to the secondary context. The secondary
context records `TTBR0_EL1` on both resumptions. Each observation must contain
the empty VM table and ASID, while each return to the bootstrap context must
restore the mapped user VM and its readable data page. Success reports
`ARM64_TASK_TTBR0_SWITCH_OK`.

The bootstrap MMU helper still invalidates the incoming ASID conservatively on
each activation. Residency tracking and avoiding unnecessary TLBI operations
belong to the synchronized runtime ASID backend.

### Milestone 17: Single-CPU ASID Residency

Each bootstrap user VM now carries a mapping generation. The ASID manager
records which table and generation are resident for every allocated ASID. A
first activation, ASID reuse, or mapping change takes the conservative
`TLBI ASIDE1` path; switching back to an unchanged resident VM writes TTBR0
without discarding that ASID's translations.

Task contexts reference their owning VM as well as caching its TTBR0/ASID
identity. The switch boundary rejects mismatched metadata and delegates the
activation decision to the VM. The mapped/empty two-context probe snapshots
the flush and preserve counters and requires all four of its context switches
to preserve resident translations. The serial marker includes the counters
and reports `ARM64_TASK_TLB_RESIDENCY_OK`.

This residency table is intentionally single-CPU. Before ARM64 SMP, it must
gain synchronization, per-CPU residency state, rollover handling, and remote
shootdown rules.

### Milestone 18: Owned Bootstrap Kernel Stack

The bootstrap ARM64 task object now owns the physical pages backing its kernel
stack. Initialization allocates and clears the stack through its TTBR1 alias,
normalizes the initial entry point to the high kernel mapping, and seeds the
task context with its optional user-VM identity. Destruction refuses the active
context and returns every owned stack page to the early allocator.

Both cooperative context-switch probes now use a dynamically allocated 4 KiB
stack instead of an embedded static array. They snapshot the allocator's free
page count before task creation and require exact balance after destruction.
This also validates that allocator metadata retained from low bootstrap is
usable through TTBR1 after the low mapping is retired. Success reports
`ARM64_TASK_STACK_LIFECYCLE_OK`.

At this milestone the lifetime object remained architecture-local. Milestone
19 replaces that parallel object with the generic `task_t` layout.

### Milestone 19: Generic Task Lifetime

The cooperative ARM64 probe is now a real generic `task_t`. Its common fields
hold the task identity, blocked state, kernel-task type, priority, CPU
ownership sentinels, stack bounds, physical stack allocation, and lifetime
magic. The ARM64 backend initializes only those fields and its concrete
`task_context_t`; it does not publish the task to a runqueue.

The architecture boundary now exposes the ARM64 context through the generic
`task_context_t` name. It also supplies the lower 39-bit user virtual layout
and DAIF-based local IRQ/FIQ save/restore primitives required for the generic
task contract to compile in AArch64 builds.

The runtime probe verifies all common metadata, exact stack bounds, active-task
destruction refusal, dead-object marking, and balanced stack-page release.
Success reports `ARM64_GENERIC_TASK_LIFECYCLE_OK`. Scheduler publication,
runtime task allocation, and synchronization remain deliberately outside this
bootstrap milestone.

### Milestone 20: Generic Task State Switch

Both sides of the cooperative switch are now generic `task_t` objects. The
bootstrap task describes the live high-half boot stack as borrowed storage,
while the probe task owns its allocated stack. The task-level switch validates
both lifetime guards and stack bounds before delegating TTBR0/ASID activation
and register transfer to the ARM64 context backend.

Each departure moves the previous task from `RUNNING` to `BLOCKED`, clears its
CPU ownership, promotes the incoming task to `RUNNING` on bootstrap CPU0, and
increments the outgoing switch count. If address-space activation fails before
the register transfer, all state changes are rolled back. The two probes each
require two departures per task and a final bootstrap state of `RUNNING` on
CPU0. Success reports `ARM64_TASK_STATE_SWITCH_OK`.

This is still cooperative and explicitly selected. The next scheduler step is
a bounded generic runqueue that chooses the next ready task; timer preemption
and SMP ownership remain later milestones.

### Milestone 21: Bounded Cooperative Runqueue

The first generic ARM64 runqueue is a bounded, intrusive FIFO over the existing
`task_t` runqueue links. Publication accepts only live `BLOCKED` tasks, rejects
duplicate insertion and capacity overflow, and promotes accepted tasks to
`READY`. Selection removes the oldest ready task while preserving that state
for the task-switch boundary, which then performs the final transition to
`RUNNING`.

The bootstrap probe uses a capacity-one queue to exercise the complete
cooperative cycle twice: publish, reject a duplicate, select, switch from the
borrowed-stack bootstrap task to the owned-stack probe, return, republish, and
select again. It validates the queue links, count, capacity, task states, CPU
ownership, and balanced switch counts at each boundary. Success reports
`ARM64_COOPERATIVE_RUNQUEUE_OK`.

This queue is intentionally single-CPU and lockless. The next scheduler
milestone will publish multiple ready tasks and make selection deterministic
across them before timer-driven preemption or SMP runqueue ownership is added.

### Milestone 22: Deterministic Multi-Task Rotation

The cooperative runqueue probe now owns two generic tasks with independent
kernel stacks and saved contexts. Both tasks are published simultaneously in
FIFO order. After the first task runs and blocks, republishing it places it
behind the still-ready second task; the same rotation is then repeated in the
opposite direction.

The probe requires the exact dispatch order `A, B, A, B`, two departures from
each owned task, four departures from the bootstrap task, valid queue links at
every selection boundary, and exact recovery of both allocated stack pages.
It also verifies that a task already present in the full queue cannot be
published again. Success reports `ARM64_MULTITASK_RUNQUEUE_OK`.

Task selection is now deterministic for multiple ready contexts, but the boot
probe still performs selection and switching explicitly. The next milestone
is a reusable cooperative dispatcher that owns dequeue, switch, and requeue
policy before timer preemption is introduced.

### Milestone 23: Cooperative Dispatcher

A generic single-CPU dispatcher now owns the current task, bounded ready queue,
architecture switch callback, dispatch count, and last scheduling reason. The
three reasons are voluntary `YIELD`, future timer `PREEMPT`, and `BLOCK`.
Yield and preemption rotate the current task to the tail; blocking leaves it
off the ready queue. Failed architecture activation restores task states, CPU
ownership, counters, and the original FIFO order.

Two kernel-only probe tasks now invoke the dispatcher from their own saved
contexts. The bootstrap yields into A, A yields into B, and B yields back to
the bootstrap. A second round runs the same order while A and B block instead
of requeueing themselves. The probe requires six dispatches, two departures
per task, an empty final queue, and balanced stack-page recovery. Success
reports `ARM64_COOPERATIVE_DISPATCHER_OK`.

The dispatcher exposes preemption as a separate policy operation. A timer
handler must first preserve the interrupted kernel or EL0 frame and defer
scheduling while preemption is disabled. Milestone 25 adds the `need_resched`
handoff used by the IRQ return path; the device handler never switches directly
from the middle of interrupt acknowledgement.

### Milestone 24: EL0 Yield Through SVC

The dispatcher now runs a generic user `task_t` with an owned kernel stack,
the validated user VM and ASID, and an EL0 register image. Its kernel entry
trampoline executes `ERET`; the lower-EL SVC vector then leaves the complete
exception frame on that task's kernel stack. Syscall number 158 follows the
Linux-compatible `sched_yield` slot and enters the same dispatcher used by
kernel-only tasks.

The probe schedules a user task and a kernel peer. The user payload writes its
message and yields from EL0, the peer yields, and the bootstrap observes both
tasks ready. A second bootstrap yield resumes the user immediately after its
`svc #0`; the payload completes its fault and unknown-syscall checks, then
`exit` blocks the user task. The peer resumes once more, blocks, and returns the
CPU to the bootstrap task.

The test validates five user syscalls, six dispatcher switches, the preserved
EL0 nonvolatile registers and stack, both blocked final states, an empty queue,
and exact recovery of both owned kernel stacks. Success reports
`ARM64_EL0_YIELD_DISPATCH_OK`. A yield with no dispatcher remains a successful
no-op, preserving the existing single-user bootstrap path.

This remains voluntary scheduling. The next milestone will let the timer set a
deferred `need_resched` request and service it only from an architecture-safe
exception-return boundary with a complete interrupted frame.

### Milestone 25: Deferred Timer Preemption

The GIC/timer layer now returns acknowledged event bits instead of invoking
scheduler policy. A physical-timer PPI reports `ARM64_IRQ_EVENT_TIMER` only
after the timer state is updated and the GIC end-of-interrupt write completes.
Both the EL1h IRQ vector and lower-EL AArch64 IRQ vector reach the same
exception dispatcher.

An active task dispatcher coalesces timer events into `need_resched`. It also
tracks a bounded preemption-disable depth plus request, deferral, and service
counters. The exception layer attempts service only after the IRQ device
dispatcher returns, while the complete interrupted frame remains on the
current task's kernel stack. A disabled dispatcher or an empty ready queue
keeps the request pending for a later safe point; a failed architecture switch
restores it.

The kernel-only probe first disables preemption and fires a real one-shot
physical timer. It requires one pending request, one deferral, no dispatch, and
an untouched worker. After preemption is enabled, a second timer IRQ switches
to the owned-stack worker at the IRQ-return boundary. The worker yields back,
is resumed once more to block, and its stack page is recovered exactly. The
test requires two requests, one serviced preemption, four total dispatches,
balanced task states, and reports `ARM64_DEFERRED_PREEMPT_OK`.

This milestone validates the mechanism on one CPU with a kernel task. A
periodic user quantum, scheduler critical-section integration, and SMP-safe
runqueue ownership remain later work; user tasks already preserve their full
EL0 frame when voluntarily yielding through SVC.

### Milestone 26: EL0 Timer Preemption

Scheduled EL0 tasks can now enter with IRQs enabled instead of the masked
bootstrap PSTATE. A nonblocking one-shot timer is armed while EL1 remains
masked; `ERET` to EL0t makes the timer interruptible. The lower-EL AArch64 IRQ
vector saves the complete user register image on that task's owned kernel
stack, acknowledges the physical-timer PPI, and services `need_resched` at the
same safe boundary validated for kernel tasks.

The preemption payload polls a user-visible completion flag with a bounded
timeout. The timer rotates it out before any syscall and selects a kernel-only
peer. That peer sets the flag, executes a memory barrier, and yields to the
bootstrap task. The bootstrap verifies that the user task and peer are both
ready while the original IRQ service remains suspended on the user stack. A
second yield resumes that exact service frame; `ERET` continues the interrupted
EL0 loop, which observes the flag and exits normally. The peer then resumes and
blocks back to the bootstrap task.

The probe requires one timer request, no deferral, one completed preemption,
six dispatches, preservation of the EL0 nonvolatile registers and stack,
evidence that the flag path beat the timeout, blocked final tasks, an empty
queue, and exact recovery of both owned stacks. Success reports
`ARM64_EL0_TIMER_PREEMPT_OK`.

This remains a deterministic one-shot and single-CPU test. Turning it into the
runtime scheduler tick requires periodic rearming, per-task/per-CPU preemption
state, IRQ-safe runqueue synchronization, and a quantum policy independent of
the timer device driver.

### Milestone 27: Bounded Periodic Mixed Preemption

The physical-timer bootstrap API can now arm an explicit finite number of
ticks. Its IRQ path rearms from the acknowledged PPI until the target count is
reached, while the exception layer continues to see one policy-neutral timer
event per tick. The dispatcher therefore receives independent `need_resched`
requests without learning timer register details.

The periodic probe starts with a bootstrap task, an IRQ-enabled EL0 task, and a
kernel-only peer. Tick 1 suspends EL0 and starts the peer. The peer publishes a
shared handshake value, enables IRQ locally, and tick 2 suspends it in turn,
returning control to the bootstrap task. At that boundary both timer-service
calls are still suspended on their owning stacks, so two requests and zero
completed services are required.

The bootstrap then selects EL0 again. Its first IRQ service completes and
`ERET` resumes the interrupted polling loop. EL0 advances the handshake and
blocks through `exit`, selecting the kernel peer. The peer's second IRQ service
then completes, its interrupted kernel loop observes the handshake, masks IRQ,
and blocks back to the bootstrap task. The exact order is therefore
`bootstrap, EL0, kernel, bootstrap, EL0, kernel, bootstrap` across six
dispatches.

The final invariants require two timer requests, two completed preemptions, no
deferral, two preserved exception frames, blocked worker tasks, an empty ready
queue, preserved EL0 registers, and exact stack-page recovery. Success reports
`ARM64_PERIODIC_MIXED_PREEMPT_OK`.

This is the transition from atomic mechanism probes to scheduler integration,
but the sequence remains finite and single-CPU. A continuous runtime tick must
next move timer lifetime out of the probe, define quantum accounting, and make
runqueue/preemption state IRQ-safe before it can replace the ARM32 scheduler
path.

### Milestone 28: Dispatcher Quantum Accounting

Timer frequency and scheduling policy are now separate. Every acknowledged
timer event enters `task_dispatcher_timer_tick`, which accounts total ticks and
the current slice. Only a configured quantum expiration increments the
expiration counter and coalesces `need_resched`; intermediate ticks return from
the exception without selecting another task. The default quantum remains one
tick for the earlier probes.

A successful voluntary or preemptive dispatch resets the incoming task's slice
to zero. The transactional switch path also saves and restores the previous
slice on architecture-switch failure, so a failed activation cannot silently
donate or consume runtime. Dispatcher validation rejects a zero quantum or a
slice outside its configured range.

The mixed periodic probe is now parameterized. Its original two-tick run uses a
one-tick quantum and preserves the milestone-27 behavior. A second run arms
four physical-timer ticks with a two-tick quantum: ticks 1 and 3 return to the
same EL0 and kernel tasks, while ticks 2 and 4 alone produce the two preemption
requests. The final state requires four accounted ticks, two expirations, two
completed services, zero residual slice, the same six-dispatch order, and exact
resource recovery. Success reports `ARM64_QUANTUM_ACCOUNTING_OK`.

The remaining runtime step is no longer basic timer preemption. It is ownership
and concurrency: move the bounded timer lifetime into scheduler initialization,
protect runqueue and preemption state against IRQ re-entry, and attach quantum
selection to the generic task policy before enabling continuous scheduling.

### Milestone 29: Scheduler-Owned Continuous Tick

The timer backend now distinguishes finite bring-up sequences from a continuous
periodic mode. Continuous mode rearms every acknowledged PPI without a target
count and exposes only start, cancel, and observed-tick operations. It still
does not contain a quantum, task pointer, runqueue, or scheduling callback.

The parameterized mixed scheduler probe runs a third time with a two-tick
quantum and an unbounded timer. After four physical ticks and two quantum
expirations, FIFO rotation resumes the bootstrap task while IRQ remains masked
by the second exception. The bootstrap task, acting as scheduler owner, cancels
the timer before inspecting state or resuming either suspended worker.

Both the timer backend and dispatcher must report exactly four ticks. The rest
of the established contract remains unchanged: two preemption requests, two
suspended services at the bootstrap boundary, later completion of both IRQ
frames, six dispatches, normal EL0 exit, kernel-peer block, and balanced stack
recovery. Success reports `ARM64_CONTINUOUS_TICK_LIFECYCLE_OK`.

Continuous lifetime is therefore available without making the timer driver a
scheduler. The next integration boundary is local concurrency: scheduler and
runqueue mutations need architecture-provided IRQ save/mask/restore operations
before this mode can stay enabled outside a controlled probe.

### Milestone 30: IRQ-Safe Dispatcher Mutation

The generic dispatcher now accepts architecture callbacks that save and mask
local interrupts, then restore the exact previous state. The FIFO runqueue
remains architecture-neutral and deliberately lockless; dispatcher operations
that publish, yield, block, change preemption state, configure a quantum, or
request or service a pending preemption provide its single-CPU serialization
boundary. ARM64 supplies those callbacks with `DAIF` save, IRQ/FIQ mask, and
restore.

The timer tick accounting path is not masked a second time because it is called
only after architectural IRQ entry has already masked local interrupts. Its
safe-point service uses the protected dispatcher path. A section may span an
architecture context switch: restoration then occurs when the suspended task
resumes its dispatcher call, preserving the interrupt state that belonged to
that exact execution context.

All ARM64 dispatcher probes now use the same initialized hooks. The mixed
periodic tests additionally require exactly `4 + timer_ticks` protected
operations when the bootstrap first resumes and `7 + timer_ticks` after both
workers block. This covers quantum setup, publication, voluntary dispatch,
every timer safe point, and final blocking without relying on timing. Success
reports `ARM64_IRQ_SAFE_DISPATCH_OK`.

This completes local IRQ serialization, not SMP synchronization. Direct
runqueue users must still serialize externally, and future multicore dispatch
requires a real spinlock plus per-CPU current-task and preemption ownership.

### Milestone 31: Generic VM-Space Backend Binding

The owned ARM64 user-VM object now embeds a generic `vm_space_t` identity. It
publishes the TTBR0 table through `pgdir`, records the raw table allocation,
initializes the architecture-provided heap and stack layout, and mirrors its
ASID. A new opaque `arch_private` field in `vm_space_t` points back to the
owning backend; ARM32 initializes that field to `NULL`, while ARM64 requires it
to resolve to the exact object containing the generic identity.

Every ARM64 VM operation validates a backend magic plus agreement between the
generic table/ASID fields and the concrete L1/ASID state. Task contexts now
hold `const vm_space_t *` instead of `const arm64_user_vm_t *`. Task creation,
TTBR0 switching, ASID-residency activation, and bootstrap SVC buffer validation
all resolve the concrete backend from that generic reference. The duplicated
TTBR0/ASID fields in the architecture context remain transactional switch
metadata and are checked against `vm_space_t` before activation.

Because the bootstrap objects are created through the low identity alias and
later used through TTBR1, high-half entry explicitly rebinds `arch_private`
after validating all persistent fields. This replaces only the virtual owner
pointer; table physical addresses, ASID, layout, mappings, and generation must
already agree. The low alias can then be retired without leaving a stale
backend pointer in the generic identity.

The lifecycle probe validates both directions of the generic/backend adapter.
The task address-space probe then carries mapped and empty `vm_space_t` objects,
rejects a deliberately mismatched TTBR0, switches both ASIDs through the
generic identity, and preserves the existing TLB-residency counts. The final
EL0 syscall path also validates its write buffer through the same generic
reference. Success reports `ARM64_GENERIC_VM_SPACE_OK`.

This is an identity and ownership bridge, not yet the full runtime VM. ARM64
still uses its bounded bootstrap mapping array and early page allocator; VMA
management, anonymous mappings, fork/COW, synchronized ASID allocation, and
ELF64 loading remain to be connected to generic memory services.

### Milestone 32: Generic VMA Ownership

Each bounded ARM64 bootstrap mapping now embeds a generic `vma_t`. The
architecture-private duplicate virtual-address and permission fields have been
removed: the sorted list rooted at `vm_space_t.vma_list` is the source of truth
for user ranges and `READ`, `WRITE`, and `EXEC` permissions. Compile-time
assertions require the ARM64 page permission bits to match the generic VMA
bits exactly.

Mapping insertion rebuilds a deterministic sorted list, rejects duplicate
pages, and records the owned physical page alongside its VMA. Identity
validation walks the complete list and requires page alignment, one-page
ranges, non-overlap, readable mappings, W^X, valid owned physical pages, and
exact agreement with the bounded mapping count. Lookup and SVC range checks
now traverse these generic VMAs to recover permissions and physical ownership.

The high-half backend rebind also rebuilds every VMA link, because their
in-object pointers were initially formed through the low identity alias. The
lifecycle probe maps two pages in reverse virtual order and requires a sorted
generic list, then proves that a W+X insertion fails without consuming a page.
The main EL0 VM requires the exact code, data, stack chain before low-map
retirement. Success reports `ARM64_GENERIC_VMA_OK`.

The nodes and mapped pages are still allocated from a fixed bootstrap object
and the early allocator. Milestone 33 extends that bounded owner across a
dynamic page-table hierarchy and adds page retirement; dynamic VMA allocation
and the synchronized physical allocator remain later work.

### Milestone 33: Runtime Page-Table Growth And Unmap

An ARM64 user VM now starts with only its L1 table. L2 tables are allocated on
demand for each occupied 1 GiB region and L3 tables are allocated on demand for
each occupied 2 MiB window. The bounded owner inventories every table by its
L1/L2 index, validates parentage and physical uniqueness, and releases mapped
pages, L3 tables, L2 tables, and the L1 table in strict ownership order.

Table access is valid both during identity-mapped bootstrap and after low-map
retirement: physical table addresses are dereferenced through the live TTBR1
kernel alias. Mapping a page installs a permission-checked PTE and invalidates
that exact `(ASID, VA)` translation. Unmapping clears the PTE, cleans it to the
point of coherency, performs the same targeted `TLBI VAE1`, returns the owned
physical page, removes its generic VMA, and advances the mapping generation.
If that ASID/table pair is already resident, the targeted operation publishes
the new generation so a later context switch can preserve the remaining TLB
entries instead of flushing the complete ASID.

The high-half runtime probe creates a temporary VM spanning two L1 regions and
three L3 windows. It activates the VM, checks EL0 read/write translations,
removes the middle page, requires that translation to fault immediately while
both neighbours remain mapped, restores the main user VM, and verifies exact
allocator balance after destruction. Success reports
`ARM64_DYNAMIC_USER_VM_OK`.

This is still a bounded single-CPU backend. Milestone 34 adds eager anonymous
ranges and empty-table reclamation; dynamic VMA nodes, synchronized page
allocation, remote TLB shootdowns, anonymous demand paging, and ELF64 segment
loading remain to be connected.

### Milestone 34: Transactional Anonymous Ranges

The bounded ARM64 VM backend now exposes eager anonymous range operations over
the page primitive. A range must be non-empty, page-aligned, contained in the
39-bit user address space, permission-valid, and small enough for the remaining
mapping inventory. Every page is checked for overlap before allocation starts.
If a later page allocation fails, the operation unmaps the pages already
created in reverse order, returning their physical ownership and any hierarchy
that became empty.

Single-page unmap now reclaims structure as well as data. Once the VMA and PTE
are gone, an empty L3 is detached only if its parent descriptor still names the
expected physical table and all 512 child descriptors are invalid. An L2 with
no remaining L3 children follows the same rule. Each parent descriptor is
cleaned and invalidated for the active `(ASID, VA)` before the table page is
returned to the allocator. A multi-page unmap prevalidates the complete range
before applying that sequence page by page.

The high-half probe maps a two-page anonymous range beginning at `0x7ff000`,
so the second page enters a different 2 MiB L3 window. Both pages are readable
and writable immediately in the resident ASID. A duplicate range is rejected
without changing free-page accounting. Range unmap then faults both
translations, preserves mappings on either side, collapses both empty L3
tables, and returns to the exact pre-range allocation count. Final VM
destruction still restores the original allocator count. Success reports
`ARM64_ANON_RANGE_VM_OK`.

These ranges are eagerly populated and still represented by one bounded VMA
node per page. The next memory milestone is a dynamically allocated range VMA
whose nonresident pages can be supplied by the EL0 data-abort path.

### Milestone 35: Persistent Kernel Tasks

ARM64 now leaves the bounded boot probes and enters a persistent single-CPU
scheduler. Two generic `task_t` objects own independent high-half kernel
stacks and use the empty TTBR0 address space: `idle0` waits in `WFI`, while
`kinit` performs the first kernel-init lifecycle. The borrowed bootstrap task
publishes both tasks and blocks permanently instead of remaining the implicit
execution context.

The physical timer remains periodic after bring-up. A narrow exception-layer
tick hook applies wakeup policy before the normal deferred-preemption decision.
`kinit` publishes a wake deadline with local IRQs masked, blocks, and is made
ready by that hook after five ticks. The same IRQ return then preempts `idle0`
and resumes `kinit` on its saved stack. Repeating this cycle exercises kernel
tasks that yield through blocking kernel code, IRQ-frame suspension, timer
preemption, and idle execution as a continuing runtime rather than a finite
probe.

The first completed wake validates that bootstrap is blocked, `kinit` is
running, `idle0` is ready, and at least three dispatches occurred. Success
reports `ARM64_BOOTSTRAP_RETIRED`, `ARM64_IDLE_KINIT_SWITCH_OK`, and
`ARM64_RUNTIME_SCHEDULER_OK`. This is kernel `kinit`, not `/sbin/init`: generic
process creation, ELF64 loading, VFS-backed `execve`, and the full syscall
surface still separate this milestone from a 64-bit userland init.

### Milestone 36: Syscalls, Processes, ELF64 And Lazy VM

ARM64 now enters the architecture-neutral syscall dispatcher with the native
AArch64 register width and all six argument registers. The dispatcher owns the
complete ArmOS syscall-number table, reports `ENOSYS` for absent entries, and
keeps call/rejection accounting outside the exception layer. The bootstrap
registers process, signal, VM, and console handlers without changing the
existing ARM32 syscall path.

The generic process model now covers parent/child linkage, fork inheritance,
exec address-space replacement, zombie publication, wait/reap selection,
orphaning, pending signals, blocked signals, and signal dispositions. These
state transitions are exercised independently of a concrete scheduler task.
The ARM64 bootstrap syscall backend exposes the subset that can operate before
VFS migration; creation of a runnable fork child and path-backed `execve`
remain part of the VFS/process integration milestone.

The generic ELF64 loader validates little-endian AArch64 `ET_EXEC` images,
program-header bounds, segment alignment, user-address overflow, and load
permissions. It maps, copies, and zero-fills `PT_LOAD` segments through VM
callbacks, so image acquisition remains separate from loading. An in-memory
ELF64 image proves executable mapping and BSS zeroing and reports
`ARM64_PROCESS_MODEL_OK` and `ARM64_ELF64_LOADER_OK`.

ARM64 `brk` and private anonymous `mmap` now reserve nonresident VMAs. Lower-EL
translation faults allocate a zeroed page, install its L3 descriptor with the
reserved permissions, publish a targeted ASID generation, and retry the EL0
instruction. `munmap` releases the resident page and any empty page-table
hierarchy. A dedicated EL0 payload reaches this path through the generic
dispatcher and reports `ARM64_GENERIC_SYSCALL_ABI_OK`,
`ARM64_PROCESS_SYSCALLS_OK`, and `ARM64_BRK_MMAP_PAGE_FAULT_OK`.

## Toolchain

On macOS, install the AArch64 bare-metal compiler and QEMU:

```sh
brew install aarch64-elf-gcc
./tools/build_qemu_10_0_2.sh
```

On Debian/Ubuntu, the distro cross compiler can build the freestanding
bootstrap. Select its prefix explicitly:

```sh
sudo apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
export ARCH=aarch64-linux-gnu-
```

The pinned QEMU build now produces both `qemu-system-arm` and
`qemu-system-aarch64`.

## Build And Boot

Build without launching QEMU:

```sh
TARGET_ARCH=arm64 TARGET_PLATFORM=qemu-virt ./build.sh
```

Build and boot with the exact emulator baseline:

```sh
QEMU_REQUIRED_VERSION=10.0.2 \
TARGET_ARCH=arm64 TARGET_PLATFORM=qemu-virt ./run.sh
```

The expected serial milestone is:

```text
ArmOS ARM64 bring-up
Architecture: AArch64
Current EL: EL1
DTB: 0x0000000048000000
ARM64_BOOT_OK
Testing EL1 synchronous vector with BRK #0x64
Exception vector: 0x0000000000000004
ESR_EL1: 0x00000000F2000064 EC: 0x000000000000003C
ARM64_VECTOR_OK
ARM64_EXCEPTION_RETURN_OK
Enabling ARMv8 4K identity MMU
ARM64_MMU_OK
Testing synchronous vector with MMU enabled
ARM64_VECTOR_OK
ARM64_MMU_EXCEPTION_OK
Testing GICv2 physical timer PPI 30
CNTFRQ_EL0: 0x0000000003B9ACA0 timer ticks: 0x0000000000000003
ARM64_TIMER_IRQ_OK
Early pages: base=0x000000004009F000 end=0x0000000080000000 ...
FDT RAM: base=0x0000000040000000 size=0x0000000040000000 ...
ARM64_FDT_MEMORY_OK
ARM64_PHYS_ALLOC_OK
TTBR0 allocated: old=... new=... L2=... L3=...
ARM64_L3_PAGE_TLBI_OK
TTBR1 kernel alias: table=... text=0xFFFFFF8040080000 TCR=...
ARM64_TTBR1_PERMISSIONS_OK
ARM64_USER_VM_LIFECYCLE_OK
ARM64_DYNAMIC_PGTABLE_OK
High kernel: PC=0xFFFFFF80... SP=0xFFFFFF80... VBAR=0xFFFFFF80...
ARM64_TTBR1_EXECUTION_OK
ARM64_HIGH_MMIO_OK
ARM64_LOW_MAP_RETIRED_OK
ARM64_TASK_CONTEXT_SWITCH_OK
ARM64_TASK_STACK_LIFECYCLE_OK
ARM64_GENERIC_TASK_LIFECYCLE_OK
ARM64_TASK_STATE_SWITCH_OK
ARM64_COOPERATIVE_RUNQUEUE_OK
ARM64_MULTITASK_RUNQUEUE_OK
ARM64_COOPERATIVE_DISPATCHER_OK
User TTBR0: mapped=0x0001... empty=0x0002... VA=0x0000000000401000 PA=...
ARM64_USER_TTBR0_ASID_OK
ARM64_TASK_TTBR0_SWITCH_OK
ARM64_GENERIC_VM_SPACE_OK
ARM64_GENERIC_VMA_OK
ARM64_DYNAMIC_USER_VM_OK
ARM64_ANON_RANGE_VM_OK
ARM64_PROCESS_MODEL_OK
ARM64_ELF64_LOADER_OK
ASID residency: flush=... preserve=...
ARM64_TASK_TLB_RESIDENCY_OK
ARM64 syscall write OK
ARM64_EL0_YIELD_DISPATCH_OK
ARM64_EL0_TIMER_PREEMPT_OK
ARM64_PERIODIC_MIXED_PREEMPT_OK
ARM64_QUANTUM_ACCOUNTING_OK
ARM64_CONTINUOUS_TICK_LIFECYCLE_OK
ARM64_IRQ_SAFE_DISPATCH_OK
Testing high VBAR synchronous vector
ARM64_VECTOR_OK
ARM64_GENERIC_SYSCALL_DISPATCH_OK
Entering EL0 at 0x0000000000400000 stack=0x0000000000403000
ARM64 syscall write OK
EL0 exit status: 0x000000000000002A syscall count: 0x000000000000000D
ARM64_EL0_SYSCALL_ABI_OK
ARM64_EL0_CONTEXT_OK
ARM64_GENERIC_SYSCALL_ABI_OK
ARM64_PROCESS_SYSCALLS_OK
ARM64_BRK_MMAP_PAGE_FAULT_OK
Testing timer IRQ after EL0 return
ARM64_TIMER_IRQ_OK
ARM64_HIGH_KERNEL_OK
ARM64_IDLE0_KINIT_READY
ARM64_KINIT_RUNNING
ARM64_BOOTSTRAP_RETIRED
ARM64_IDLE_KINIT_SWITCH_OK
ARM64_RUNTIME_SCHEDULER_OK
```

Generated artifacts are isolated from ARM32 under:

```text
build/images/kernel-arm64-qemu-virt.bin
build/images/kernel-arm64-qemu-virt.elf
build/images/kernel-arm64-qemu-virt.map
build/images/kernel-arm64-qemu-virt.dis
```

## Next Milestones

1. Bring VFS image acquisition, file descriptors, pipes, console TTY, and
   runnable fork/exec task ownership to ARM64, then execute `/sbin/init` from
   an ELF64 file.
2. Build the AArch64 ArmOS newlib sysroot and validate progressively larger C
   programs before moving `init` and `mash`.
3. Replace the bounded ARM64 VMA/table inventories and early allocator with
   dynamic range nodes and synchronized physical-page backends.
4. Add SMP synchronization, per-CPU scheduler ownership, ASID rollover, and
   remote TLB shootdowns when secondary ARM64 CPUs are introduced.
