# Raspberry Pi 3 AArch32

ArmOS has a dedicated 32-bit hardware profile for Raspberry Pi 3 Model B/B+.
It boots through the Raspberry Pi firmware as `kernel7.img`, runs the Cortex-A53
cores in AArch32, and keeps the PL011 UART as the mandatory recovery console.

This profile is a hardware-development milestone. The ArmOS v0.6 public release
baseline remains QEMU `virt` with one CPU.

## Platform Contract

- Target: `TARGET_ARCH=arm32 TARGET_PLATFORM=pi3`
- CPU: Cortex-A53, AArch32, four scheduler CPUs
- Kernel load address: `0x02010000`
- Firmware DTB: `bcm2710-rpi-3-b-plus.dtb`
- UART: PL011 `uart0`, 115200 baud
- Bluetooth overlay: `disable-bt`, keeping PL011 on the GPIO UART header
- Storage: SD/eMMC block device
- Root: ext2 partition
- Boot: hidden FAT32 firmware partition
- Graphics, input, and networking: not yet provided by this hardware profile

The `raspi2` target remains the QEMU `raspi2b` profile. In project discussions,
`pi2` therefore means QEMU and `pi3` means real Raspberry Pi 3 hardware.

## Build

Build the kernel and disk image without rebuilding newlib or TinyCC:

```sh
TARGET_PLATFORM=pi3 make platform-kernel platform-disk
```

The resulting artifacts are:

```text
build/images/kernel-pi3.bin
build/images/disk-pi3.img
```

The convenience wrapper selects the correct target, DTB, and Bluetooth
overlay:

```sh
tools/build_pi3_sd.sh --mode none
```

## Write An SD Card

The firmware files are expected under `../PI2/firmware/boot`. To write the full
MBR image on macOS, first identify the raw disk carefully:

```sh
diskutil list
tools/build_pi3_sd.sh --skip-build --mode raw \
  --raw-device /dev/rdiskN --yes
```

Raw mode stages the firmware, DTB, overlay, kernel, and `config.txt` into the
FAT32 partition before writing only the sectors used by the two MBR partitions.
The large QEMU padding at the end of the image is skipped.

The generated firmware configuration is equivalent to:

```ini
kernel=kernel7.img
kernel_address=0x02010000
arm_64bit=0
enable_uart=1
uart_2ndstage=1
device_tree=bcm2710-rpi-3-b-plus.dtb
init_uart_baud=115200
dtoverlay=disable-bt
```

## UART Console On macOS

Connect only adapter GND, RX, and TX; do not connect the adapter power pin.
GPIO14 is TX and GPIO15 is RX, so adapter RX connects to Pi TX and vice versa.

List serial devices and open the console:

```sh
tools/pi2_uart_screen.sh --list
tools/pi2_uart_screen.sh --device /dev/cu.usbserial-XXXX --baud 115200
```

Despite its historical name, the UART helper is suitable for PI3. Quit macOS
`screen` with `Ctrl-A`, then `K`, then `y`.

## SMP Validation

The minimum post-build hardware check is:

```sh
sleep 1
cat /proc/smp
mmaptest
kload -s 120 -m 2048 -c 4 -u 25 -p 8 -f 1 &
top -s 1
lps
cat /proc/smp
/sbin/shutdown
```

Expected properties:

- `online`, `seen_mask`, and `sched_mask` report all four CPUs;
- worker tasks migrate across CPUs without spinlock diagnostics;
- `forkfail`, `sched-refuse`, and `ready-refuse` remain zero;
- zombies and live physical/kernel-stack allocations return to baseline;
- `top` continues refreshing during and after `kload`;
- shutdown parks secondary CPUs, syncs ext2, stops the block device, and enters
  Raspberry Pi firmware powerdown without a data abort.

## MMU And ASID Constraint

The PI3 hardware result is stricter than QEMU:

- user mappings are non-global and tagged with an 8-bit ASID;
- ASID pool operations are protected by a spinlock;
- TTBR page-table walks use shareable WBWA attributes;
- the context switch performs a full local `TLBIALL` after selecting TTBR0 and
  CONTEXTIDR.

Do not replace the full local flush with `TLBIASID` or `TLBIASIDIS` solely
because QEMU passes. Both variants survived QEMU stress but later produced
stale user instruction mappings and undefined-instruction faults on PI3.
A future optimization needs explicit per-CPU ASID residency/generation state,
cross-CPU invalidation rules, and repeated hardware stress.

Read-only page-table inspection uses the permanent kernel direct map instead
of temporary global mappings. This removes avoidable map/unmap maintenance
without weakening the context-switch safety rule.

## Current Limitations

- The boot banner and shared low-level driver directory still contain some
  historical `raspi2` naming; the target selection and CPU detection are PI3
  specific.
- The timer uses the validated 1 MHz platform timebase rather than trusting the
  firmware-provided `CNTFRQ` value.
- Only UART and SD-backed console/root workflows are supported; HDMI graphics,
  USB input, and networking are later milestones.
- The firmware FAT32 partition is intentionally hidden from normal desktop
  browsing. ArmOS mounts ext2 as `/`; FAT32 remains available for explicit
  compatibility work.
