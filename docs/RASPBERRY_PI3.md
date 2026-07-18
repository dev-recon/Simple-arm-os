# Raspberry Pi 3

Raspberry Pi 3 Model B+ is the ArmOS AArch64 hardware reference platform. The
production hardware target is:

```text
TARGET_ARCH=arm64 TARGET_PLATFORM=raspi3
```

It boots through the Raspberry Pi firmware as `kernel8.img`, runs all four
Cortex-A53 cores in the common scheduler, and keeps PL011 `tty0` as the
mandatory recovery console. QEMU `virt` remains the reference environment for
kernel feature development and regression testing. QEMU's `raspi3b` machine is
also supported as a focused CPU-entry and SD/eMMC functional test; it does not
replace hardware timing and signal validation.

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
- Graphics: optional HSD028309 B6 / ILI9341 GPIO parallel display on `/dev/fb0`
- USB input and networking: not yet provided by this profile

The separate `arm32/raspi2` target supports Raspberry Pi 2 Model B v1.1
hardware and is also exercised with QEMU's `raspi2b` machine.

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

Boot the same platform through QEMU's Raspberry Pi 3 model:

```sh
TARGET_ARCH=arm64 TARGET_PLATFORM=raspi3 ./boot.sh
```

The QEMU profile loads the raw kernel at `0x02010000`. Unlike Raspberry Pi
firmware, QEMU enters this raw image in EL3, so the common ARM64 bootstrap
normalizes EL3 to EL2 before using the same validated EL2-to-EL1 path as
hardware. No DTB pointer is supplied in this mode.

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

Staging is target-specific. The script copies the base firmware files, the
Pi 3 B+ DTB, `kernel8.img`, `config.txt`, and only overlays requested by the
configuration. It does not copy every DTB and overlay found in the firmware
source tree. This keeps normal boot-only updates bounded by the kernel and the
small target firmware set.

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

## HSD028309 B6 / ILI9341 Display

The Raspberry Pi 3 profile includes a write-only 8-bit 8080 backend for the
2.8-inch HSD028309 B6 shield. The panel controller is ILI9341-compatible and
is initialized from the sequence validated by the original 6502/6821 test
program. It uses the same framebuffer ABI as QEMU:

- `/dev/fb0` is always the active framebuffer;
- QEMU `virt` attaches the VirtIO-GPU backend;
- Raspberry Pi 3 attaches the ILI9341 GPIO backend;
- kernel rendering remains ARGB8888 and the ILI9341 backend converts dirty
rectangles to RGB565 while flushing them.

The backend is enabled by default for `raspi3`. Set `ENABLE_ILI9341=no` in
`armos.conf` to leave the GPIOs untouched and keep an UART-only profile.

The initial mode is portrait `240x320x32`. With the current VGA `8x16` TTY
font this provides a readable `30x20` terminal. Runtime landscape mode is
`320x240x32` and provides `40x15`. An `80x24` terminal would require a font no
wider than four pixels and is therefore not the default for this panel.

Connect the shield as follows. Physical pin numbers are included to avoid
confusing Raspberry Pi header positions with BCM GPIO numbers:

| Shield signal | BCM GPIO | Pi physical pin |
| --- | ---: | ---: |
| `LCD_D0` | 4 | 7 |
| `LCD_D1` | 17 | 11 |
| `LCD_D2` | 18 | 12 |
| `LCD_D3` | 27 | 13 |
| `LCD_D4` | 22 | 15 |
| `LCD_D5` | 23 | 16 |
| `LCD_D6` | 24 | 18 |
| `LCD_D7` | 25 | 22 |
| `LCD_CS` | 5 | 29 |
| `LCD_RS` / D-C | 6 | 31 |
| `LCD_WR` | 12 | 32 |
| `LCD_RST` | 13 | 33 |
| `LCD_RD` | tie high to 3.3 V | 1 or 17 |
| `GND` | ground | 6, 9, 14, 20, 25, 30, 34, or 39 |
| `5V` | 5 V supply | 2 or 4 |

Power the Pi down before changing any connection. The board shown in the
hardware notes contains an AMS1117-3.3 regulator and
two LVC245A level translators. Supply the shield through its labelled `5V`
and `GND` pins and leave its labelled `3V3` pin disconnected unless the exact
board schematic proves that it is an input. Do not join the Pi 5 V and 3.3 V
rails through the shield. `LCD_RD` must remain high because this first driver
does not read the controller bus.

The selected GPIOs leave PL011 on GPIO14/GPIO15 untouched and avoid the SPI0
pins. The display is output-only, so `tty0` remains the interactive UART and
`tty1` renders to the panel.

After wiring and rebuilding the Pi 3 target, expect these boot lines:

```text
GPU: ILI9341 GPIO parallel 240x320x32                   [ OK ]
TTY: console tty1 on ILI9341 /dev/fb0                   [ OK ]
Input: GPIO display is output-only                      [WARN]
```

Use the UART console for the first smoke test:

```sh
fbtest
fbview /path/to/image.png
ttyinfo
echo 'ILI9341_OK' > /dev/tty1
```

The panel starts in portrait mode. Its orientation can be changed while the
system is running:

```sh
fbctl orientation
fbctl rotate landscape
fbctl rotate portrait
```

The landscape geometry is 320x240 and gives a 40-column by 15-line `tty1`
with the current 8x16 font. Portrait mode is 240x320 and gives 30 columns by
20 lines. A successful rotation redraws the framebuffer, updates the tty1
window size, and sends `SIGWINCH` to its foreground process group. Backends
without hardware rotation support reject `ARMOS_FBIOSET_ORIENTATION` with
`ENOTSUP`.

Public-domain PNG, JPEG, and TIFF samples are installed in
`/home/user/images` for framebuffer and local XV testing:

```sh
fbview /home/user/images/test-pattern.png
fbview /home/user/images/jpeg-landscape.jpg
fbview /home/user/images/test-pattern-320x240.tiff
```

The panel should start black, then show the `tty1` output. Keep the UART
connected during initial tests so a wiring error cannot hide kernel logs.

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
iobench -f /tmp/iobench-ext2.dat -m 8 -b 64 -k
nano /tmp/arm64-smoke.c
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
- repeated `nano`, `ls`, `top`, fork/exec and COW activity does not produce
  lower-EL faults after tasks migrate between CPUs;
- shutdown parks secondary CPUs, syncs ext2, stops the block device, and enters
  firmware powerdown without an exception.

Storage throughput and the final SD-card validation sequence are documented in
[STORAGE_PERFORMANCE.md](STORAGE_PERFORMANCE.md).

## Current Limitations

- The ILI9341 backend is write-only, polling, and uses GPIO PIO;
  it does not yet use DMA, touch input, or controller readback.
- UART remains the only interactive console on Raspberry Pi 3.
- The FAT32 firmware partition is separate from the ext2 root and is mounted
  only when explicitly requested.
- ARM64 still uses a conservative local TLB invalidation strategy during
  address-space switches; any optimization requires repeated Pi 3 stress, not
  only QEMU validation.
