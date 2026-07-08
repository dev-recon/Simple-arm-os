# Local patches

The upstream sources are kept mostly intact, with one ArmOS portability patch:

- avoid `printf(3)` `%j` integer length modifiers in source output paths,
  because ArmOS' current libc prints them incorrectly.

ArmOS-specific build and compatibility code is kept in:

- `tools/build_bsdmtree.sh`
- `userland/opt/bsdmtree/compat/`
