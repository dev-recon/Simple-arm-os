# Raspberry Pi 2

Raspberry Pi 2 Model B v1.1 is the supported ArmOS ARM32 hardware platform:

```text
TARGET_ARCH=arm32 TARGET_PLATFORM=raspi2
```

It runs the ARMv7-A common kernel on four Cortex-A7 CPUs. The same target is
also exercised with QEMU's `raspi2b` machine, but hardware boots through the
Raspberry Pi firmware and uses the physical SD/eMMC controller.

## Platform Contract

- CPU: Cortex-A7 in ARMv7-A mode
- Kernel load address: `0x02010000`
- Firmware image: `kernel7.img` with `arm_64bit=0`
- Firmware DTB: `bcm2709-rpi-2-b.dtb`
- UART: PL011 `uart0`, 115200 baud
- Storage: BCM2835/BCM2836 SD/eMMC controller
- Root: ext2 partition
- Boot: dedicated FAT32 LBA firmware partition
- Graphics, USB input and networking: not yet provided by this profile

## Build And SD Card

Build the kernel and complete disk image:

```sh
make TARGET_ARCH=arm32 TARGET_PLATFORM=raspi2 platform-kernel platform-disk
```

Stage a complete Raspberry Pi firmware image, or write a raw SD device:

```sh
tools/build_raspberry_sd.sh --arch arm32 --platform raspi2 --mode image
tools/build_raspberry_sd.sh --arch arm32 --platform raspi2 \
  --mode raw --raw-device /dev/rdiskN --yes
```

The generated artifacts are:

```text
build/images/kernel-arm32-raspi2.bin
build/images/disk-arm32-raspi2.img
```

Firmware files are read from `../PI2/firmware/boot`. The generated FAT32 boot
partition contains `kernel7.img`, `config.txt`, the Pi 2 DTB and firmware. The
ext2 root remains a separate partition and is identical in layout to the other
ArmOS targets.

The staging script selects the Pi 2 DTB and configured overlays instead of
copying the complete Raspberry Pi firmware tree. After the initial raw image
write, use boot-only mode for normal kernel iteration:

```sh
tools/build_pi2_sd.sh --skip-build --mode boot \
  --boot-volume /Volumes/PI2
```

## UART Console

Connect adapter GND, RX and TX only. GPIO14 is Pi TX and GPIO15 is Pi RX:

```sh
tools/pi2_uart_screen.sh --list
tools/pi2_uart_screen.sh --device /dev/cu.usbserial-XXXX --baud 115200
```

UART `tty0` is the mandatory recovery console. QEMU success does not replace a
hardware boot, SD I/O, scheduler and shutdown validation on the Model B v1.1.
