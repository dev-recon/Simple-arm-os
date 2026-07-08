# BSD Userland Tools

This document tracks the optional BSD-style userland tool bundle for ArmOS.

The goal is not to replace the host build environment yet. The goal is to make
the running ArmOS system feel more like a small Unix workstation, with enough
real tools to write Makefiles, transform text, inspect trees, create archives,
and apply patches from inside `mash`.

## Build Flag

Build and stage the BSD bundle with:

```sh
BUILD_BSD=1 ./build.sh
```

For iterative work, once newlib and TinyCC are already built, the faster path
is usually:

```sh
BUILD_NEWLIB=0 BUILD_TCC=0 BUILD_BSD=1 BUILD_NCURSES=0 BUILD_NANO=0 ./build.sh
```

The tools are cross-built as static ArmOS binaries and staged into `userfs`.
Generated binaries under `userfs/opt/*` remain build artifacts.

## Installed Layout

Each imported tool keeps its source and compatibility layer under:

```text
userland/opt/<name>/
```

The generated runtime bundle is staged under:

```text
/opt/<name>/bin
```

Visible command entries are then installed under `/bin`, `/usr/bin`, or
`/usr/sbin`. Most entries are symlinks so `ls -l` immediately shows which
ported implementation is active.

Current BSD bundle entries:

| Command | Runtime entry | Visible entry |
| --- | --- | --- |
| `bmake` | `/opt/bmake/bin/bmake` | `/usr/bin/bmake` |
| `sed` | `/opt/bsdsed/bin/sed` | `/bin/sed -> ../opt/bsdsed/bin/sed` |
| `awk` | `/opt/bsdawk/bin/awk` | `/bin/awk -> ../opt/bsdawk/bin/awk` |
| `install` | `/opt/bsdinstall/bin/install` | `/usr/bin/install -> ../../opt/bsdinstall/bin/install` |
| `mtree` | `/opt/bsdmtree/bin/mtree` | `/usr/bin/mtree`, `/usr/sbin/mtree` |
| `xargs` | `/opt/bsdxargs/bin/xargs` | `/usr/bin/xargs -> ../../opt/bsdxargs/bin/xargs` |
| `diff` | `/opt/bsddiff/bin/diff` | `/usr/bin/diff -> ../../opt/bsddiff/bin/diff` |
| `patch` | `/opt/bsdpatch/bin/patch` | `/usr/bin/patch -> ../../opt/bsdpatch/bin/patch` |
| `pax` | `/opt/bsdpax/bin/pax` | `/usr/bin/pax -> ../../opt/bsdpax/bin/pax` |
| `tar` | `/opt/bsdpax/bin/tar` | `/usr/bin/tar -> ../../opt/bsdpax/bin/tar` |
| `m4` | `/opt/bsdm4/bin/m4` | `/usr/bin/m4 -> ../../opt/bsdm4/bin/m4` |

## Port Structure

Each BSD port should keep three things separate:

- upstream sources in `userland/opt/<name>/src`;
- small ArmOS compatibility shims in `userland/opt/<name>/compat`;
- cross-build orchestration in `tools/build_<name>.sh`.

When upstream sources need local source edits, document them in:

```text
userland/opt/<name>/patches/README.md
```

Prefer compatibility shims over modifying vendored sources when the behavior is
clearly an ArmOS/newlib portability issue.

## Current Compatibility Notes

- `bmake` runs with ArmOS-specific `MACHINE=armos` and `MACHINE_ARCH=arm`
  defaults.
- `sed`, `awk`, and `m4` are enough for useful Makefile-time text generation.
- `diff` and `patch` support unified patch workflows. The current `patch`
  behavior is validated when an explicit target file is passed.
- `pax` and `tar` currently use NetBSD's small pax profile; `cpio` mode and
  compression filters are intentionally not part of the first ArmOS bundle.
- `m4` builds NetBSD's extended profile and uses `/sbin/mash` for `esyscmd`.

## Smoke Tests

Basic visibility:

```sh
which bmake
which m4
ls -l /usr/bin/m4
```

`m4`:

```sh
printf 'changequote([,])dnl\ndefine([NAME],[ArmOS])dnl\nHello NAME\n' > hello.m4
m4 hello.m4
```

`bmake`, `sed`, `awk`, and `m4` together:

```sh
printf 'apple=3\npear=4\napple=2\n' > stock.txt
printf 'changequote([,])dnl\ndefine([TITLE],[Inventory])dnl\nTITLE\n' > title.m4
printf 'TITLE!=m4 title.m4\nTOTAL!=sed "s/=/ /" stock.txt | awk '\''{ s += $$2 } END { print s }'\''\nall:\n\t@echo $(TITLE) total=$(TOTAL)\n' > Makefile
bmake
```

Expected output:

```text
Inventory total=9
```

`tar` and `pax`:

```sh
mkdir -p /tmp/pax-test/src/sub /tmp/pax-test/out
cd /tmp/pax-test
printf 'alpha\n' > src/a.txt
printf 'beta\n' > src/sub/b.txt
tar cf sample.tar src/a.txt src/sub/b.txt
tar tf sample.tar
cd out
pax -r -f ../sample.tar
diff -u ../src/a.txt src/a.txt
diff -u ../src/sub/b.txt src/sub/b.txt
```
