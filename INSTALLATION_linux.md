# ArmOS Linux Installation

This guide sets up ArmOS on Linux. Debian and Ubuntu are the primary reference
distributions for now.

ArmOS targets an ARMv7-A Cortex-A15 kernel running on QEMU `virt`.
The supported v0.2 reference emulator is QEMU 10.0.2. Other QEMU versions may
work, but 10.0.2 is the version to use when reproducing release behavior.

## Disk Layout

The default generated disk layout is:

- `ext2.img`: primary root filesystem, mounted as `/`
- `fat32.img`: secondary compatibility filesystem, mounted as `/mnt`
- `disk.img`: MBR at sector 0, ext2 as partition 1, FAT32 as partition 2

Generated images are build artifacts and should not be committed.

## 1. Install Required Packages

On Debian/Ubuntu:

```sh
sudo apt update
sudo apt install -y \
  build-essential \
  make \
  git \
  curl \
  xz-utils \
  gcc-arm-none-eabi \
  binutils-arm-none-eabi \
  qemu-system-arm \
  qemu-utils \
  mtools \
  dosfstools \
  e2fsprogs
```

Tool purpose:

- `build-essential`, `make`: host build tools
- `gcc-arm-none-eabi`, `binutils-arm-none-eabi`: ARM bare-metal toolchain
- `qemu-system-arm`, `qemu-utils`: emulator and disk tooling
- `mtools`: FAT image manipulation (`mcopy`, `mmd`, `mdir`)
- `dosfstools`: FAT image creation (`mkfs.fat`)
- `e2fsprogs`: ext2 tools (`mke2fs`, `debugfs`, `e2fsck`)
- `curl`, `xz-utils`: optional source package download/extraction helpers

## 2. Verify The Toolchain

```sh
make --version
arm-none-eabi-gcc --version
arm-none-eabi-ld --version
arm-none-eabi-objcopy --version
qemu-system-arm --version
mkfs.fat -V
mcopy -V
mmd -V
mke2fs -V
debugfs -V
e2fsck -V
```

## 3. Clone And Build

```sh
git clone https://github.com/dev-recon/Simple-arm-os.git arm-os
cd arm-os
chmod +x run.sh boot.sh tools/build_newlib.sh
./run.sh
```

`run.sh` performs a full local rebuild:

1. rebuilds libc/userland pieces
2. rebuilds `kernel.bin`
3. recreates `fat32.img`, `ext2.img`, and `disk.img`
4. boots QEMU

At the `mash$>` prompt, a quick smoke test is:

```sh
systest
ps
ls -la /
ls -la /proc
hello
```

Exit QEMU with:

```text
Ctrl+A, then X
```

## 4. Useful Commands

Build kernel only:

```sh
make kernel.bin
```

Rebuild disk images only:

```sh
rm -f disk.img ext2.img fat32.img
make disk.img
```

Inspect generated filesystems:

```sh
make check-disk
```

Verify ext2 without modifying it:

```sh
e2fsck -fn ext2.img
```

Boot without rebuilding:

```sh
./boot.sh
```

## 5. Optional Newlib Build

Build the optional repo-local newlib sysroot and include newlib-linked test
programs:

```sh
./tools/build_newlib.sh
BUILD_NEWLIB=1 ./run.sh
```

The script uses the local `newlib-4.4.0.20231231.tar.gz` archive when present.
If the archive is missing, it downloads it with `curl` from Sourceware.

The installed sysroot lives in:

```text
build/newlib-sysroot/arm-none-eabi
```

That directory is generated and should not be committed.

You can also point the build at another sysroot:

```sh
BUILD_NEWLIB=1 NEWLIB_SYSROOT=/path/to/arm-none-eabi ./run.sh
```

## 6. Common Problems

### `arm-none-eabi-gcc: command not found`

Install the cross compiler:

```sh
sudo apt install gcc-arm-none-eabi binutils-arm-none-eabi
```

Then verify:

```sh
which arm-none-eabi-gcc
```

### FAT tools not found

If `mkfs.fat`, `mcopy`, `mmd`, or `mdir` are missing:

```sh
sudo apt install dosfstools mtools
```

### Ext2 tools not found

If `mke2fs`, `debugfs`, or `e2fsck` are missing:

```sh
sudo apt install e2fsprogs
```

### QEMU starts but the terminal looks stuck

ArmOS runs QEMU with `-nographic`, so QEMU owns the terminal while it is
running.

Exit with:

```text
Ctrl+A, then X
```

### Permission problems on scripts

```sh
chmod +x run.sh boot.sh tools/build_newlib.sh
```

### Fresh disk images

To force fresh disk images:

```sh
rm -f disk.img ext2.img fat32.img
make disk.img
```

`./run.sh` already removes and recreates these images before booting.
