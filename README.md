# Simple arm-os
Arm V7 simple kernel for cortex-a15 running on qemu virt

This started as a joke... Is it possible to develop an ARM kernel, Linux like, from scratch by using AI support?
After some weeks of hard work, this is not a joke anymore :).

This Kernel can be used to teach system programming or kernel development and can be easily customized to your own needs.

Small kernel is in place with the following features:
  - Platform QEMU Virt
  - CPU cortex-a15
  - MMU split N=2 and Asid support
  - Context switching
  - Kernel tasks and processes support (both user ans kernel)
  - premptive kernel with yield, schedule_to and timer based preempt.
  - Userland programs
  - Virtio blk device.
    - Disk specs : 64 MB - using real userfs where user programs are stored (compiled in userland and then copied to userfs)
  - Syscalls: 30 posix syscalls implemented
    - fork, execve, exit, waitpid, ... userland and kernel
    - write, read, open, close, lseek, unlink, ... (files management working user and kernel).
    - getpid, getppid, ... (these were the easy ones :)
    - pipe, dup, dup2, stats, chdir, rmdir, getcwd ...
    - signal, sigaction, sighandler, ...
  - Basic libc: printf, tty, terminal management, malloc, free, ...
  - Basic shell: work in progress, called ``mash`` (Moon Shell).

Userland currently includes small coreutils-style commands such as `cat`,
`echo`, `pwd`, `ls`, `cp`, `mv`, `rm`, `mkdir`, `rmdir`, `touch`, `sleep`,
`kill`, `ps` and `stat`. The `stat` command exercises the kernel `stat(2)` and
`fstat(2)` syscalls and reports file type, mode, size, block count and
timestamps on both the ext2 root filesystem and the FAT32 compatibility mount.
Some fields are still intentionally simple: `st_dev` is not mount-aware yet and
`st_nlink` is currently reported as 1.

Code is still dirty and not well documented (need some help for this as well).
I'm using Mac M4 to developp and cross-compile, not a big deal to adapt makefiles to make it compile and run on Linux.

I was developping in C long time ago, but have had hard time to get up to speed again.
I will continue to developp it and and features for the sake of learning new stuff.
I also think that this kernel can also be used by teachers and students that wants to learn bare metal programming and kernel development.

# Documentation

Will publish a documentation on how to:
  1. Setup environment: check `INSTALLATION_macos.md`for mac users.
  1. Create and modify user programs.

Runtime stress baselines are tracked in `STABILITY.md`.

Roadmap for now id to develop the following features (to have a proper userland shell working):
  - virtio mmio block device with wait queues.
  - Files: create, write, lseek, dup.
  - display (ram based) and keyboard management: base is in place (need testing and debuging)
  - tty (VT100)
  - .... so many things to do :)
  - ideas very welcome as well.
  - plan to port it to different Raspberry Pi platforms (Pi 2-4). So if anywone would like to help build abstractions, feel free.

Contributors are very welcome :)

## Contributing  

Found a bug or have an idea? Fork the repo, make changes, and submit a pull request.  

Please read `CONTRIBUTING.md` for guidelines.  

## License  

This project is licensed under the MIT License.  
See the `LICENSE` file for details.  

## Contact  

Created by [Dev Recon]  
Feel free to reach out with questions or suggestions.  
