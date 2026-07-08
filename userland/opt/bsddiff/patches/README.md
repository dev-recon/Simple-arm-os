# Local patches

The upstream sources are kept mostly intact, with two ArmOS portability
patches:

- compute `diffargs` from `strlen(argv[i])` instead of subtracting argument
  string pointers, because ArmOS does not guarantee contiguous argv strings.
- avoid `%zu` in `xmalloc.c` diagnostics, because ArmOS' current libc printf
  does not format the `z` integer length modifier correctly.

ArmOS-specific build and compatibility code is kept in:

- `tools/build_bsddiff.sh`
- `userland/opt/bsddiff/compat/`
