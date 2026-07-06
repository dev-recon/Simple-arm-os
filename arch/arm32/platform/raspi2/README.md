# Raspberry Pi 2 Platform Staging

This directory is a staging area for the next ARM32 platform target.
It is intentionally not buildable yet: there is no `platform.mk`, so
`TARGET_PLATFORM=raspi2` must fail fast.

The first Raspberry Pi 2 pass should establish the real board contract before
sharing code with `qemu_virt`:

- boot entry and firmware handoff assumptions;
- RAM base/size discovery path;
- interrupt controller choice and routing;
- timer source;
- UART backend for `tty0`;
- block device strategy, if any;
- FDT availability and exact compatible strings.

Keep UART `tty0` as the recovery console while bringing this up. The graphical
console is not a prerequisite for the first board boot.
