# arm-os
Arm V7 simple kernel for cortex-a15 running on qemu virt

This started as a joke... Is it possible to develop an ARM kernel, Linux like, from scratch by using AI support ?
After some weeks of hard work, this is not a joke anymore :).
Small kernel is in place with the following features:
  - Platform QEMU Virt
  - CPU cortex-a15
  - MMU split N=2 and Asid support
  - Context switching
  - Kernel tasks and processes support (both user ans kernel)
  - Userland programs
  - RAMFS (home made - did not get virtio blk device to work properly so far - would need some help on this one).
    - RAMFS specs : 64 MB - using real userfs where user programs are stored (compiled in userland and then copied to userfs)
  - Syscalls:
    - fork: userland and kernel - I know Posix does not allow forks in kernel but this kernel does (and it's cool :)).
    - execve: userland and kernel
    - write: for now used to output to uart - so printf works well from user programs.
    - getpid
    - getppid: these were the easy ones :)

Code is still dirty and not well documented (need some help for this as well).
I'm using Mac M4 to developp and cross-compile, not a big deal to adapt makefiles to make it compile and work in Linux.

I was developping in C long time ago, but have had hard time to get up to speed again.
I will continue to developp it and and features for the sake of learning new stuff.
I also think that this kernel can also be used by teachers and students that wants to learn bare metal programming and kernel development.

Contributors are very welcome :)
