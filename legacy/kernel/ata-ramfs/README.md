# Archived ATA/IDE/RAMFS Bring-Up Code

This directory keeps the removed storage bring-up code for reference only.
It is intentionally outside `kernel/` and is not part of any ArmOS build.

Archived components:

- `drivers/ata.c` and `include/ata.h`: compatibility wrappers that exposed
  `ata_*` names while the active block backend was already VirtIO.
- `drivers/ide.c` and `include/ide.h`: legacy QEMU/PCI IDE probing code.
- `drivers/ramfs.c`, `drivers/tar_parser_ramfs.c`, and matching headers:
  the old RAMFS + TAR-to-FAT32 experiment.
- `fs/userfs_loader.c` and `include/userfs_loader.h`: old userfs loader glue.
- `ls_process.c`: early kernel-side `ls` process/debug helper, superseded by
  real userland commands.
- `task/task_test.c`: early in-kernel task scheduler smoke tests, superseded
  by userland `schedtest`, `systest`, and stress workloads.

The active kernel block path is `blk_*` through `kernel/drivers/block_device.c`
and the platform-specific block initializer. If ArmOS grows an initramfs later,
it should be implemented as a clean VFS/rootfs facility rather than reviving
this legacy FAT32-in-RAM compatibility layer.
