# Contributing to ArmOS

Thanks for your interest in ArmOS.

ArmOS is a small ARMv7-A Unix-like kernel and userland project. Contributions
are welcome, but kernel work is easy to destabilize, so small, focused changes
are strongly preferred.

By contributing, you agree that your contributions are submitted under the
project license: Apache License, Version 2.0.

Please also follow the project [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Good Contribution Areas

Useful contributions include:

- bug reports with QEMU logs and reproduction steps
- kernel fixes
- scheduler, MMU, VFS, TTY, VirtIO, or process lifecycle hardening
- userland utilities
- newlib compatibility work
- tests and stress cases
- documentation and installation improvements
- cleanup of dead code and compiler warnings

## Before Opening a Pull Request

Please keep changes focused:

- one topic per pull request
- one subsystem per commit when possible
- avoid mixing kernel, userland, generated files, and documentation unless the
  change genuinely requires it
- do not commit generated binaries, disk images, object files, dependency files,
  or temporary QEMU logs

Typical generated files to avoid:

```text
kernel.bin
kernel.elf
kernel.map
kernel.dis
disk.img
ext2.img
fat32.img
userfs.bin
userfs.tar
*.o
*.d
build/
```

## Build And Test

On macOS, start with:

```text
INSTALLATION_macos.md
```

On Linux, start with:

```text
INSTALLATION_linux.md
```

Before submitting kernel or userland changes, run at least:

```sh
./run.sh
```

Then inside `mash`:

```sh
systest
ps
ls -la /
ls -la /proc
```

For scheduler, process, signal, pipe, VFS, or memory-management changes, also
run background stress:

```sh
systest &; systest &; systest &
```

If you cannot run QEMU locally, say so clearly in the pull request.

## Commit Messages

Use clear English commit messages.

Good examples:

```text
Harden waitpid state transitions
Add procfs cpuinfo entry
Fix ext2 truncate block accounting
Document Linux installation steps
```

Avoid vague messages such as:

```text
fix
update
misc
work
```

## Coding Style

The project is mostly C and ARM assembly.

General guidance:

- keep code simple and explicit
- prefer existing local patterns over new abstractions
- use fixed-width integer types where hardware layout matters
- use `uintptr_t` or project address types for addresses instead of assuming
  `uint32_t` in portable/core code
- validate user pointers before copying to or from userland
- keep interrupt/critical-section boundaries obvious
- avoid hidden allocation in scheduler, interrupt, or low-level MMU paths
- add comments for non-obvious hardware or context-switch behavior

For assembly:

- document register ownership and clobbers
- keep structure offsets synchronized with C definitions
- be explicit about CPU mode changes and banked registers
- avoid cleverness in exception, syscall, and context-switch paths

## Pull Request Checklist

Before requesting review:

- [ ] The change is focused.
- [ ] Generated artifacts are not included.
- [ ] Documentation was updated when behavior changed.
- [ ] `./run.sh` was tested, or the reason it was not tested is documented.
- [ ] `systest` was run for syscall/userland/kernel behavior changes.
- [ ] Stress testing was run for scheduler/process/VFS/memory changes.
- [ ] Any known risks or follow-up work are described.

## Branches

The main branch should remain the stable public entry point.

Experimental branches may carry larger work such as newlib migration, TTY/raw
mode, editor experiments, architecture split, or cleanup batches.

Avoid force-pushing shared branches unless explicitly coordinated.

## Security And Safety

ArmOS is not production-ready. Please do not run untrusted workloads in it and
do not treat it as a security boundary.

If you find a serious memory isolation, syscall validation, filesystem
corruption, or privilege issue, open an issue with enough detail to reproduce
it. If you believe disclosure should be private first, contact the maintainer
before publishing exploit details.
