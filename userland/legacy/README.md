# Legacy userland

This directory keeps old userland experiments for reference only.

The active shell and user commands are built by `userland/Makefile` from:

- `userland/system/` for system programs such as `init` and `mash`
- `userland/coreutils/src/` for command-line tools
- `userland/programs/` for tests and demo programs

Do not modify legacy code for current ArmOS behavior.

## Contents

- `homegrown-libc/`: pre-newlib libc programs and shell sources
- `myshell/`: standalone shell experiment used as design reference for `mash`
- `newlib-prototype/`: early standalone newlib bring-up experiments
