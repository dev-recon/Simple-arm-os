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

## HSD028309 B6 / ILI9341 Wiring

The Raspberry Pi 2 Model B v1.1 uses the same 40-pin header and BCM GPIO
numbering as the Raspberry Pi 3 for the HSD028309 B6 / ILI9341 8-bit parallel
display. The wiring below deliberately preserves PL011 on GPIO14/GPIO15, so the
UART recovery cable can remain connected while bringing up the panel.

```text
HSD028309 B6 shield                         Raspberry Pi 2 40-pin header

 LCD_D0  --------------------------------> BCM4   (physical pin 7)
 LCD_D1  --------------------------------> BCM17  (physical pin 11)
 LCD_D2  --------------------------------> BCM18  (physical pin 12)
 LCD_D3  --------------------------------> BCM27  (physical pin 13)
 LCD_D4  --------------------------------> BCM22  (physical pin 15)
 LCD_D5  --------------------------------> BCM23  (physical pin 16)
 LCD_D6  --------------------------------> BCM24  (physical pin 18)
 LCD_D7  --------------------------------> BCM25  (physical pin 22)

 LCD_CS  --------------------------------> BCM5   (physical pin 29)
 LCD_RS  (D/C) --------------------------> BCM6   (physical pin 31)
 LCD_WR  --------------------------------> BCM12  (physical pin 32)
 LCD_RST --------------------------------> BCM13  (physical pin 33)
 LCD_RD  --------------------------------> 3.3 V  (physical pin 1 or 17)

 GND     --------------------------------> GND    (for example physical pin 6)
 5V      --------------------------------> 5 V    (physical pin 2 or 4)
 3V3     --------------------------------> leave disconnected

 SD_SS, SD_DI, SD_DO and SD_SCK ---------- leave disconnected
 GPIO14 / GPIO15 ------------------------> reserved for PL011 UART
```

The equivalent pin table is useful when checking individual jumper wires:

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

Power the Pi down before changing the wiring. The shield identified in the
hardware notes contains an AMS1117-3.3 regulator and two LVC245A level
translators: power it through its labelled `5V` and `GND` pins, and leave its
labelled `3V3` pin disconnected. `LCD_RD` must be held high because the ArmOS
driver is write-only. Do not connect the shield's `SD_*` pins; ArmOS boots from
the Pi SD/eMMC controller, not from the shield's microSD socket.

This section records the hardware contract shared with raspi3. The current
raspi2 profile remains UART-only until the GPIO/ILI9341 objects and display
routing are enabled and validated for `arm32/raspi2`; the wiring itself does
not need to change when that support is enabled.
