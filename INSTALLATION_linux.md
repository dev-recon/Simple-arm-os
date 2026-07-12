# ArmOS Linux Installation

This guide sets up ArmOS on Linux. Debian and Ubuntu are the primary reference
distributions for now.

ArmOS currently targets ARM32. `qemu-virt` is the reference platform for kernel
features and day-to-day development. Raspberry Pi 3 running AArch32 is the
reference hardware platform; see [docs/RASPBERRY_PI3.md](docs/RASPBERRY_PI3.md)
for SD-card and UART setup.

The reproducible v0.6 emulator baseline is QEMU 10.0.2. Newer releases can be
used for compatibility testing, but should not silently replace the baseline.

## Disk Layout

The build creates intermediate `ext2.img` and `fat32.img` files, then publishes
platform-specific artifacts under `build/images/`:

- `kernel-qemu-virt.bin` and `disk-qemu-virt.img`: QEMU development images;
  ext2 root is partition 1 and FAT32 compatibility storage is partition 2
- `kernel-pi3.bin` and `disk-pi3.img`: PI3 hardware images; hidden FAT32 boot
  is partition 1 and ext2 root is partition 2

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
  e2fsprogs \
  ninja-build \
  pkg-config \
  python3-venv \
  libglib2.0-dev \
  libpixman-1-dev
```

Tool purpose:

- `build-essential`, `make`: host build tools
- `gcc-arm-none-eabi`, `binutils-arm-none-eabi`: ARM bare-metal toolchain
- `qemu-system-arm`, `qemu-utils`: emulator and disk tooling
- `mtools`: FAT image manipulation (`mcopy`, `mmd`, `mdir`)
- `dosfstools`: FAT image creation (`mkfs.fat`)
- `e2fsprogs`: ext2 tools (`mke2fs`, `debugfs`, `e2fsck`)
- `curl`, `xz-utils`: optional source package download/extraction helpers
- `ninja-build`, `pkg-config`, `python3-venv`, `libglib2.0-dev`,
  `libpixman-1-dev`: host dependencies for the exact QEMU 10.0.2 build

### Install Exactly QEMU 10.0.2

The distro package installs the version carried by the configured Debian or
Ubuntu release. The reliable cross-distribution method is an isolated source
build:

```sh
./tools/build_qemu_10_0_2.sh
```

The script downloads the [official QEMU 10.0.2 source archive](https://download.qemu.org/qemu-10.0.2.tar.xz),
checks its pinned SHA-256, builds `arm-softmmu` and `aarch64-softmmu`, and
installs the binaries under:

```text
build/qemu-10.0.2/install/bin/qemu-system-arm
build/qemu-10.0.2/install/bin/qemu-system-aarch64
```

ArmOS boot scripts automatically prefer that binary. APT can install an exact
package only if that package version is present in the configured repositories:

```sh
apt-cache madison qemu-system-arm
sudo apt install qemu-system-arm='EXACT_APT_VERSION'
sudo apt-mark hold qemu-system-arm
```

The APT version includes distro epoch/revision fields and usually does not map
to a portable `10.0.2` command, so the source build is the documented baseline.

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

For a strict baseline run, make a version mismatch fatal:

```sh
QEMU_REQUIRED_VERSION=10.0.2 ./boot.sh
QEMU_REQUIRED_VERSION=10.0.2 ./boot-graphics.sh
```

## 3. Clone And Build

```sh
git clone https://github.com/dev-recon/Simple-arm-os.git arm-os
cd arm-os
chmod +x run.sh boot.sh tools/build_newlib.sh tools/build_qemu_10_0_2.sh
./run.sh
```

`run.sh` performs a full local rebuild:

1. rebuilds libc/userland pieces
2. rebuilds `build/images/kernel-qemu-virt.bin`
3. recreates `build/images/disk-qemu-virt.img`
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
TARGET_PLATFORM=qemu-virt make platform-kernel
```

Rebuild disk images only:

```sh
rm -f disk.img ext2.img fat32.img build/images/disk-qemu-virt.img
TARGET_PLATFORM=qemu-virt make platform-disk
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

## 6. Native TinyCC And Shipped Sources

ArmOS v0.6 can build small C programs from inside the running system. This is
for end-user programming and experiments inside ArmOS; the project itself still
uses the macOS/Linux cross toolchain for kernel work, stabilization, and release
builds.

The standard build scripts stage TinyCC under:

```text
/opt/tcc
```

and install the user-facing wrapper:

```text
/usr/bin/tcc
```

The root filesystem also contains a userland source snapshot:

```text
/usr/src/armos/userland
```

Inside `mash`, try:

```sh
tcc /usr/src/armos/userland/coreutils/src/ls.c -o /tmp/ls-tcc
/tmp/ls-tcc /proc
```

Set `BUILD_TCC=0` when running `build.sh` or `run.sh` if you want to skip the
native TinyCC bundle during local development.

## 7. Optional ncurses And nano

ArmOS v0.6 can also stage static ncurses and nano bundles:

```sh
BUILD_NCURSES=1 BUILD_NANO=1 ./build.sh
```

This installs generated bundles under `/opt/ncurses` and `/opt/nano`, plus
`/usr/bin/cursestest` for a small runtime smoke test. These directories are
generated artifacts and are not committed to Git.

## 8. Common Problems

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
chmod +x run.sh boot.sh tools/build_newlib.sh tools/build_qemu_10_0_2.sh
```

### Fresh disk images

To force fresh disk images:

```sh
rm -f disk.img ext2.img fat32.img build/images/disk-qemu-virt.img
TARGET_PLATFORM=qemu-virt make platform-disk
```

`./run.sh` already removes and recreates these images before booting.
