# ArmOS macOS Installation

This guide sets up ArmOS on macOS. The project is primarily developed on Apple
Silicon, but Intel Homebrew paths are noted where they differ.

ArmOS targets an ARMv7-A Cortex-A15 kernel running on QEMU `virt`.
The supported v0.2 reference emulator is QEMU 10.0.2. QEMU 11.0.1 has been
smoke-tested, but its macOS/Cocoa graphical window scaling differs from 10.0.2.

## Disk Layout

The default generated disk layout is:

- `ext2.img`: primary root filesystem, mounted as `/`
- `fat32.img`: secondary compatibility filesystem, mounted as `/mnt`
- `disk.img`: MBR at sector 0, ext2 as partition 1, FAT32 as partition 2

Generated images are build artifacts and should not be committed.

## 1. Install Homebrew

If Homebrew is not installed yet:

```sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Make sure Homebrew is available in your shell:

```sh
eval "$(/opt/homebrew/bin/brew shellenv)"
```

On Intel Macs, Homebrew usually lives under `/usr/local` instead of
`/opt/homebrew`.

## 2. Install Required Tools

```sh
brew install make
brew install arm-none-eabi-gcc
brew install qemu
brew install mtools
brew install dosfstools
brew install e2fsprogs
brew install curl
brew install xz
```

Tool purpose:

- `make`: GNU make used by the root, libc, kernel, and userland Makefiles
- `arm-none-eabi-gcc`: ARM bare-metal compiler, assembler, linker, and binutils
- `qemu`: `qemu-system-arm`
- `mtools`: FAT image manipulation (`mcopy`, `mmd`, `mdir`)
- `dosfstools`: FAT image creation (`mkfs.fat`)
- `e2fsprogs`: ext2 tools (`mke2fs`, `debugfs`, `e2fsck`)
- `curl`: optional newlib source download when the local archive is absent
- `xz`: archive support for some upstream source packages

## 3. Configure PATH

`run.sh` prepends common Homebrew locations, including the `e2fsprogs` sbin
directory. For an interactive shell, this is still useful:

```sh
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:$PATH"
export PATH="/opt/homebrew/opt/e2fsprogs/sbin:$PATH"
```

For Intel Homebrew:

```sh
export PATH="/usr/local/bin:/usr/local/sbin:$PATH"
export PATH="/usr/local/opt/e2fsprogs/sbin:$PATH"
```

To make it permanent, add the relevant lines to `~/.zshrc`.

## 4. Verify The Toolchain

From a fresh terminal:

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

For ArmOS v0.2, `qemu-system-arm --version` should ideally report QEMU 10.0.2.
The scripts also accept an explicit QEMU binary:

```sh
QEMU=/opt/qemu-11.0.1/bin/qemu-system-arm ./boot.sh
QEMU=/opt/qemu-11.0.1/bin/qemu-system-arm ./boot-graphics.sh
```

If `mke2fs`, `debugfs`, or `e2fsck` are not found, your shell is missing the
`e2fsprogs` sbin path.

## 5. Clone And Build

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

## 6. Useful Commands

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

## 7. Optional Newlib Build

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

## 8. Adding Userland Programs

User programs live under `userland/` and are installed into the generated
`userfs` tree.

For newlib-linked tools, the current convention is:

- shell/init sources under `userland/system/`
- system tool sources under `userland/system/tools/`
- core utility sources under `userland/coreutils/src/`
- ArmOS program sources under `userland/programs/<name>/`
- imported external tool sources under `userland/opt/<name>/src/`
- system programs under `userfs/sbin`
- core utilities under `userfs/bin`
- ArmOS user programs under `userfs/usr/bin`
- imported external tools under `userfs/opt/<name>/bin`

The root filesystem is ext2, so long filenames are supported there. FAT32 is
still available under `/mnt`, but it is intentionally a smaller compatibility
filesystem.

## 9. Common Problems

### `arm-none-eabi-gcc: command not found`

Install the cross compiler and reopen your shell:

```sh
brew install arm-none-eabi-gcc
which arm-none-eabi-gcc
```

### `mke2fs` or `debugfs` not found

Install `e2fsprogs` and add its sbin directory to `PATH`:

```sh
brew install e2fsprogs
export PATH="/opt/homebrew/opt/e2fsprogs/sbin:$PATH"
```

On Intel Homebrew:

```sh
export PATH="/usr/local/opt/e2fsprogs/sbin:$PATH"
```

### FAT tools not found

If `mkfs.fat`, `mcopy`, `mmd`, or `mdir` are missing:

```sh
brew install dosfstools mtools
```

### QEMU starts but the terminal looks stuck

ArmOS runs QEMU with `-nographic`, so QEMU owns the terminal while it is
running.

Exit with:

```text
Ctrl+A, then X
```

### `make clean` does not remove disk images

`make clean` removes kernel objects and binaries. To force fresh disk images:

```sh
rm -f disk.img ext2.img fat32.img
make disk.img
```

`./run.sh` already removes and recreates these images before booting.
