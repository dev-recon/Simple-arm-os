# BSD sed for ArmOS

This directory vendors NetBSD `usr.bin/sed` with a small ArmOS compatibility
layer.  The upstream sources in `src/` are kept unmodified; ArmOS-specific
helpers live in `compat/` and the build flow is in `tools/build_bsdsed.sh`.

The bundle installs the binary under `/opt/bsdsed/bin/sed`.  When
`BUILD_BSD=1`, the top-level build also stages `/bin/sed` as a symlink to that
binary, replacing the small fallback sed from `userland/coreutils/src/sed.c` in
the generated userfs.

The staged symlink is relative (`../opt/bsdsed/bin/sed`) so host-side image
generation can resolve it while preserving the same target inside ArmOS.
