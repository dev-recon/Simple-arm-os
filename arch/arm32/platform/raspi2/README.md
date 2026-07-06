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

## Minimal Files For First Bring-Up

Do not make this platform buildable until these files contain real values:

- `arch/arm32/include/asm/platform/raspi2.h`
  - `ARMOS_PLATFORM_RAM_START`
  - `ARMOS_PLATFORM_UART0_PHYS_BASE`
  - `ARMOS_PLATFORM_UART0_CLOCK_HZ`
  - `ARMOS_PLATFORM_UART0_BAUD`
  - `ARMOS_PLATFORM_UART_IRQ`
  - timer IRQ and fallback frequency
  - device/peripheral physical window
  - GIC/interrupt-controller capability flags
- `arch/arm32/platform/raspi2/platform.mk`
  - CPU flags for the target core
  - `ARMOS_PLATFORM_RASPI2` define
  - platform object list
- `arch/arm32/platform/raspi2/devices.c`
  - UART-only `platform_devices_init()` first
  - block and graphics hooks may remain warning-only in the first milestone
- optional `arch/arm32/platform/raspi2/qemu.sh`
  - only if the QEMU `raspi2b` model is used as the first test target

The first successful milestone is deliberately small: boot logs on tty0, no
graphics, no network, and no block-device requirement.
