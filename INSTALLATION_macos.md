# macOS Installation

This project is developed on macOS Apple Silicon and targets an ARMv7-A
Cortex-A15 kernel running on QEMU `virt`.

The default disk layout is now:

- `ext2.img`: primary root filesystem, mounted as `/`
- `fat32.img`: secondary compatibility filesystem, mounted as `/mnt`
- `disk.img`: concatenation of ext2 first, FAT32 second

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

## 2. Install required tools

```sh
brew install make
brew install arm-none-eabi-gcc
brew install qemu
brew install mtools
brew install dosfstools
brew install e2fsprogs
```

Tool purpose:

- `make`: GNU make used by the root, libc and userland Makefiles
- `arm-none-eabi-gcc`: ARM bare-metal compiler, assembler, linker and binutils
- `qemu`: `qemu-system-arm` emulator
- `mtools`: `mcopy`, `mmd`, `mdir` for FAT32 image handling
- `dosfstools`: `mkfs.fat` for FAT32 image creation
- `e2fsprogs`: `mke2fs`, `debugfs`, `e2fsck` for ext2 image creation and checks

## 3. Configure PATH

The `run.sh` script already prepends common Homebrew locations, including the
`e2fsprogs` sbin directory. For an interactive shell, this is still useful:

```sh
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:$PATH"
export PATH="/opt/homebrew/opt/e2fsprogs/sbin:$PATH"
```

For Intel Homebrew:

```sh
export PATH="/usr/local/bin:/usr/local/sbin:$PATH"
export PATH="/usr/local/opt/e2fsprogs/sbin:$PATH"
```

To make it permanent, add the relevant lines to your `~/.zshrc`.

## 4. Verify the toolchain

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

If `mke2fs`, `debugfs` or `e2fsck` are not found, your shell is missing the
`e2fsprogs` sbin path.

## 5. Clone and build

```sh
git clone https://github.com/dev-recon/Simple-arm-os.git arm-os
cd arm-os
chmod +x run.sh
./run.sh
```

`run.sh` performs a full local rebuild:

1. rebuilds `libc`
2. rebuilds all userland programs
3. rebuilds `kernel.bin`
4. recreates `fat32.img`, `ext2.img` and `disk.img`
5. boots QEMU

At the `mash$>` prompt, a quick smoke test is:

```sh
systest
ps
ls -la
hello
```

Exit QEMU with:

```text
Ctrl+A, then X
```

## 6. Useful build commands

Build kernel only:

```sh
make kernel.bin
```

Rebuild the disk images only:

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

Boot without rebuilding everything:

```sh
make run-userfs
```

Build the optional repo-local newlib sysroot and include the newlib smoke test
program in `/usr/bin`:

```sh
./tools/build_newlib.sh
BUILD_NEWLIB=1 ./run.sh
```

The script uses the local `newlib-4.4.0.20231231.tar.gz` archive when present.
If the archive is missing, it downloads it with `curl` from Sourceware. The
installed sysroot lives in `build/newlib-sysroot/arm-none-eabi`; that directory
is a generated build artifact and is not committed.

After extracting the vanilla archive, the script applies any arm-os patches
listed in `patches/newlib-4.4.0.20231231/series`. The current series is empty:
newlib itself stays vanilla, while the arm-os adaptation lives in tracked repo
code under `newlib-port/` and `userland/newlib-tests/include/`.

You can also point the build at another sysroot:

```sh
BUILD_NEWLIB=1 NEWLIB_SYSROOT=/path/to/arm-none-eabi ./run.sh
```

## 7. Adding userland programs

User programs live under `userland/` and are installed into `userfs/bin`.

To add a program:

1. copy an existing simple userland directory, for example `userland/coreutils`
   or `userland/systest`
2. add its build/install rules to `userland/Makefile`
3. make sure the final binary is copied to `userfs/bin`
4. run `./run.sh`

The root filesystem is ext2, so long filenames are supported there. FAT32 is
still available under `/mnt`, but it is intentionally a smaller compatibility
filesystem and should not be treated as the full system root.

Programs linked with the homegrown libc remain available in `/bin`.
Newlib-linked programs live under `userland/newlib-tests/<name>/`, use the
standalone `newlib-port/` syscall glue, and install their real binaries under
`userfs/opt/newlib/bin` when `BUILD_NEWLIB=1` is set. The build also creates
`/usr/bin` symlinks such as `/usr/bin/ls -> /opt/newlib/bin/nl-ls` and
`/usr/bin/nl-ls -> /opt/newlib/bin/nl-ls`, which lets the system test newlib
tools first while keeping the old `/bin` tools as a fallback.

## 8. Common problems

### `arm-none-eabi-gcc: command not found`

Install the cross compiler and reopen your shell:

```sh
brew install arm-none-eabi-gcc
```

Then verify:

```sh
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

### `mkfs.fat`, `mcopy`, `mmd` or `mdir` not found

Install FAT tooling:

```sh
brew install dosfstools mtools
```

### QEMU starts but the terminal looks stuck

Use `Ctrl+A`, then `X` to quit QEMU.

The kernel uses QEMU `-nographic`, so QEMU owns the terminal while it is
running.

### `make clean` does not remove disk images

`make clean` removes kernel objects and binaries. To force fresh disk images:

```sh
rm -f disk.img ext2.img fat32.img
make disk.img
```

`./run.sh` already removes and recreates these images before booting.
