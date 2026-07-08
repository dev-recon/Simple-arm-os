# Local patches

The upstream sources are kept mostly intact, with two ArmOS portability
patches:

- replace `struct dirent.d_namlen` with `strlen(d_name)` in `backupfile.c`,
  because ArmOS' `struct dirent` does not carry the BSD `d_namlen` field.
- scan operands before `getopt_long(3)` sees them, because newlib's default
  argument permutation otherwise hides `origfile`.
- replace existing backup/output paths explicitly before `rename(2)`, because
  ArmOS currently returns `EEXIST` where BSD `rename(2)` would atomically
  replace the destination.

ArmOS-specific build and compatibility code is kept in:

- `tools/build_bsdpatch.sh`
- `userland/opt/bsdpatch/compat/`
