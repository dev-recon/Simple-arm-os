# Raspberry Pi 3

Raspberry Pi 3 Model B/B+ is the ArmOS hardware reference platform. The
production hardware target is AArch64:

```text
TARGET_ARCH=arm64 TARGET_PLATFORM=raspi3
```

It boots through the Raspberry Pi firmware as `kernel8.img`, runs all four
Cortex-A53 cores in the common scheduler, and keeps PL011 `tty0` as the
mandatory recovery console. QEMU `virt` remains the reference environment for
kernel feature development and regression testing.

## Platform Contract

- CPU: Cortex-A53 in AArch64 mode, four scheduler CPUs
- Kernel load address: `0x02010000`
- Firmware image: `kernel8.img` with `arm_64bit=1`
- Firmware DTB: `bcm2710-rpi-3-b-plus.dtb`
- UART: PL011 `uart0`, 115200 baud
- Bluetooth overlay: `disable-bt`, preserving PL011 on GPIO14/GPIO15
- Storage: BCM2835/BCM2837 SD/eMMC controller
- Root: ext2 partition
- Boot: dedicated FAT32 LBA firmware partition
- Graphics, USB input, and networking: not yet provided by this profile

The compatibility target `arm32/raspi3` remains useful for architecture
comparison. The `raspi2` target names the QEMU `raspi2b` platform; in project
discussions, `pi2` therefore means QEMU and `raspi3` means real Pi 3 hardware.

## Build

Build the AArch64 kernel and disk image:

```sh
make TARGET_ARCH=arm64 TARGET_PLATFORM=raspi3 platform-kernel platform-disk
```

The generated artifacts are isolated by architecture and platform:

```text
build/images/kernel-arm64-raspi3.bin
build/images/disk-arm64-raspi3.img
```

For hardware iteration, the generic script accepts an explicit pair:

```sh
tools/build_raspberry_sd.sh --arch arm64 --platform raspi3 --mode none
```

`tools/build_pi3_sd.sh` is a compatibility wrapper selecting that same target.
Both scripts reuse newlib and TCC by default; set their build variables only
when the corresponding toolchain or sysroot changed.

## Write An SD Card

Firmware files are expected under `../PI2/firmware/boot`. On macOS, identify
the whole removable disk carefully before using raw mode:

```sh
diskutil list
tools/build_raspberry_sd.sh --arch arm64 --platform raspi3 \
  --mode raw --raw-device /dev/rdiskN --yes
```

Raw mode builds a complete MBR image, stages firmware and ArmOS files in its
FAT32 partition, then writes through the end of the last real partition. The
unused QEMU padding is not copied to the card. A target marker prevents a later
boot-only update from mixing an ARM32 root filesystem with an ARM64 kernel.

The generated firmware configuration is equivalent to:

```ini
kernel=kernel8.img
kernel_address=0x02010000
arm_64bit=1
enable_uart=1
uart_2ndstage=1
device_tree=bcm2710-rpi-3-b-plus.dtb
init_uart_baud=115200
dtoverlay=disable-bt
```

After the complete card has been initialized, a mounted boot partition can be
updated without rewriting ext2:

```sh
tools/build_pi3_sd.sh --skip-build --mode boot \
  --boot-volume /Volumes/RASPI3
```

## UART Console On macOS

Connect adapter GND, RX, and TX only; do not connect its power pin. GPIO14 is
Pi TX and GPIO15 is Pi RX, so each signal crosses to the opposite adapter pin.

```sh
tools/pi2_uart_screen.sh --list
tools/pi2_uart_screen.sh \
  --device /dev/cu.usbserial-XXXX --baud 115200
```

Despite its historical filename, the helper supports Pi 3. Quit `screen` with
`Ctrl-A`, then `K`, then `y`.

## A53 Boot Invariant

The Pi 3 firmware path validated by ArmOS enters the kernel through EL2. The
Cortex-A53 `CPUECTLR_EL1.SMPEN` bit is enabled in the EL2 drop paths before
`eret`:

- boot CPU: `.Ldrop_from_el2`;
- secondary CPUs: `.Lsecondary_drop_from_el2`.

Do not move access to implementation-defined register `S3_1_C15_C2_1` into
`.Lenter_el1`, `.Lsecondary_enter_el1`, or the C
`arch_enable_smp_coherency()` hook. On the tested hardware that change stops
boot immediately after the firmware message `arm_loader: Starting ARM`, before
the first ArmOS line. A future direct-EL1 firmware path must be diagnosed and
implemented independently instead of reusing the validated EL2 sequence.

## Timer Contract

The architectural counter must be configured per architecture, not merely per
board:

- AArch32 Pi 3 uses the validated 1 MHz effective-counter quirk even when
  `CNTFRQ` reports 19.2 MHz.
- AArch64 Pi 3 uses the 19.2 MHz rate reported by `CNTFRQ_EL0`; the AArch32
  quirk must not be inherited.

Using 1 MHz in AArch64 makes the 19.2 MHz counter expire 19.2 times too soon.
The visible results are shortened sleeps, excessive timer preemption and
context switches, and SD/eMMC command timeouts that are also 19.2 times too
short. `BogoMIPS` in the boot banner is only a timer-derived diagnostic label;
it is not scheduler calibration and must not drive timer policy.

The expected AArch64 boot line is:

```text
Timer: ARM generic timer @ 19200000 Hz, tick 1000 us
```

## Hardware Validation

Run the basic parity and stress sequence after every kernel or disk update:

```sh
sleep 1
cat /proc/smp
mmaptest
vfstest
systest
kload -s 120 -m 2048 -c 4 -u 25 -p 8 -f 1 &
top -s 1
lps
cat /proc/smp
/sbin/shutdown
```

Expected properties:

- `sleep 1` takes approximately one wall-clock second;
- `online`, `seen_mask`, and `sched_mask` report all four CPUs;
- worker tasks migrate across CPUs without spinlock diagnostics;
- idle and `top` context-switch counts grow at the scheduler rate, not by tens
  of thousands per second;
- `forkfail`, `sched-refuse`, and `ready-refuse` remain zero;
- zombies and live physical/kernel-stack allocations return to baseline;
- SD reads and writes complete without EMMC timeout diagnostics;
- shutdown parks secondary CPUs, syncs ext2, stops the block device, and enters
  firmware powerdown without an exception.

## Current Limitations

- Only UART and SD-backed console/root workflows are supported.
- The FAT32 firmware partition is separate from the ext2 root and is mounted
  only when explicitly requested.
- ARM64 still uses a conservative local TLB invalidation strategy during
  address-space switches; any optimization requires repeated Pi 3 stress, not
  only QEMU validation.
