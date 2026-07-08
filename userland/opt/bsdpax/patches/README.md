# Local patches

The upstream sources are kept mostly intact. The ArmOS port currently applies
one source-level patch:

- record the startup current-directory fd in `pax.c`, so the local `fchdir(2)`
  compatibility shim can return to the original directory.
- stop `getoldopt(3)` after the first old-style tar option cluster, because
  ArmOS/newlib `getopt(3)` otherwise treats `src/a.txt` as more option letters
  after `tar cf archive ...`.

The rest of the portability layer is kept in:

- `tools/build_bsdpax.sh`
- `userland/opt/bsdpax/compat/`

The build defines `SMALL` and `NO_CPIO`, matching NetBSD's small pax profile.
