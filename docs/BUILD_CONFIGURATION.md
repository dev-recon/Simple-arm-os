# ArmOS Build Configuration

ArmOS can select an architecture, a platform, QEMU features, and optional
userland packages from one local `armos.conf` file. Existing environment and
`make` command-line workflows remain supported.

## Quick Start

Create a local configuration from the example:

```sh
cp armos.conf.example armos.conf
```

The local `armos.conf` is ignored by Git. Inspect the resolved values with:

```sh
./tools/armos_config.sh --show
make config
```

Then use the normal entry points:

```sh
./run.sh
./build.sh
./boot.sh
./boot-graphics.sh
./boot-net.sh
```

Without a local file or environment overrides, the reference target remains
`arm32/qemu-virt`.

## Profiles

Tracked profiles provide reproducible starting points without changing the
local file:

```sh
ARMOS_CONFIG=configs/qemu-virt-arm32.conf ./run.sh
ARMOS_CONFIG=configs/qemu-virt-arm64.conf ./run.sh
ARMOS_CONFIG=configs/raspi2-arm32.conf tools/build_pi2_sd.sh --mode none
ARMOS_CONFIG=configs/raspi3-arm64.conf tools/build_pi3_sd.sh --mode none
```

`ARMOS_CONFIG` paths are resolved from the repository root.

## Precedence

Values are resolved in this order, from highest to lowest priority:

1. script command-line options, when the script provides them
2. exported environment variables
3. the selected `ARMOS_CONFIG` file, or local `armos.conf`
4. entry-point defaults

For GNU make, command-line variable assignments remain highest priority:

```sh
make TARGET_ARCH=arm64 TARGET_PLATFORM=qemu-virt platform-kernel
```

An environment override also wins over a conflicting file value:

```sh
TARGET_ARCH=arm64 ARMOS_CONFIG=configs/qemu-virt-arm32.conf make config
```

## Main Options

The configuration format is strict `KEY=VALUE`. Blank lines and lines starting
with `#` are ignored. Unknown keys are rejected so spelling mistakes fail
before a long build begins.

Target and launch options:

```text
TARGET_ARCH=arm32
TARGET_PLATFORM=qemu-virt
SMP_CPUS=1
ENABLE_NET=no
ENABLE_GPU=no
ENABLE_HDMI=no
ENABLE_ILI9341=no
ENABLE_USB=no
HDMI_WIDTH=1280
HDMI_HEIGHT=720
```

`ENABLE_NET=yes` adds VirtIO-net and the configured host forwarding when QEMU
starts. `ENABLE_GPU=yes` opens the VirtIO-GPU display and adds the keyboard
device. Both can be enabled together. These two launch options require the
`qemu-virt` platform.

`boot-graphics.sh` always enables the graphical device for that invocation.
It does not require networking: with `ENABLE_NET=no`, no network arguments are
passed to QEMU. `boot-net.sh` similarly provides the explicit network-oriented
entry point.

`ENABLE_ILI9341` controls the HSD028309 B6 / ILI9341 GPIO display backend on
Raspberry Pi 3. The `raspi3` platform enables it by default; set it to `no`
when those GPIO pins are needed by another peripheral. It is not a QEMU launch
option and has no effect on `qemu-virt`.

`ENABLE_HDMI=yes` selects the Raspberry Pi firmware framebuffer and exposes it
through the same `/dev/fb0` and graphical `tty1` contract. It requires
`TARGET_PLATFORM=raspi3`; `HDMI_WIDTH` and `HDMI_HEIGHT` request an exact mode.
HDMI and ILI9341 are mutually exclusive because both are framebuffer backends.
These values select the boot mode. On a running Raspberry Pi HDMI system,
`fbctl mode WIDTHxHEIGHT` requests another exact firmware mode through
`/dev/fb0`.

`ENABLE_USB=yes` enables the Raspberry Pi 3 DWC2 host, internal hub support,
and boot-protocol keyboard/mouse input. This first milestone enumerates devices
present during startup and requires `TARGET_PLATFORM=raspi3`.

Optional userland components:

```text
BUILD_NEWLIB=yes
BUILD_ALL_USERLAND=no
BUILD_TCC=yes
BUILD_BSD=no
BUILD_NCURSES=no
BUILD_NANO=no
BUILD_XV_DEPS=no
BUILD_FBVIEW=no
```

`BUILD_NANO=yes` requires either `BUILD_NCURSES=yes` or an ncurses bundle
already installed in `userfs`. `BUILD_ALL_USERLAND=yes` enables the complete
third-party toolchain and graphics dependency set already handled by
`build.sh`.

Useful optional overrides include:

```text
QEMU_MEMORY=2G
NET_HOST_ADDR=127.0.0.1
NET_HOST_PORT=2323
NET_GUEST_PORT=2323
GPU_XRES=1024
GPU_YRES=768
SD_VOLUME=/Volumes/RASPI3
RASPI_FIRMWARE_DIR=../PI2/firmware/boot
```

Boolean values accept `yes/no`, `true/false`, `on/off`, or `1/0`.

## Compatibility

The previous commands continue to work unchanged:

```sh
TARGET_ARCH=arm64 TARGET_PLATFORM=qemu-virt ./run.sh
BUILD_BSD=1 BUILD_NCURSES=1 BUILD_NANO=1 ./build.sh
tools/build_raspberry_sd.sh --arch arm64 --platform raspi3 --mode raw \
  --raw-device /dev/rdisk4 --yes
```

This compatibility is intentional: `armos.conf` is a convenient default layer,
not a second build system.
