ArmOS ncurses bring-up
======================

This directory contains the ArmOS-specific files used to cross-build a small,
static ncurses profile.

The first target is deliberately conservative:

- narrow ncurses, no wide-character dependency;
- no runtime terminfo database;
- a built-in `armos` fallback terminfo entry;
- no alternate screen, scroll regions, insert-line, or delete-line capability.

The graphical console currently repaints through a framebuffer backend. Omitting
the more advanced terminal capabilities lets ncurses fall back to cursor
positioning and full-line/full-screen repainting, which matches what ArmOS
implements reliably today.

Build with:

```
./tools/build_ncurses.sh
```

Stage into the generated filesystem with:

```
rsync -a build/ncurses/bundle/ userfs/
make disk.img ARCH=arm-none-eabi- CROSS_COMPILE=arm-none-eabi-
```
