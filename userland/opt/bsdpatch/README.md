# BSD patch for ArmOS

This directory vendors NetBSD `usr.bin/patch` as ArmOS' BSD-style `patch(1)`.

The build script cross-compiles it into:

```sh
/opt/bsdpatch/bin/patch
```

When `BUILD_BSD=1` is used, the top-level build stages a visible symlink:

```sh
/usr/bin/patch -> ../../opt/bsdpatch/bin/patch
```

## ArmOS compatibility notes

Local compatibility code provides small `err(3)`, `basename(3)`,
`dirname(3)`, `popen(3)`, and `pclose(3)` shims. `popen(3)` runs commands
through `/sbin/mash -c`, because ArmOS currently does not provide `/bin/sh`.

`madvise(2)` is a no-op compatibility macro for now.

Unified and context patches are the practical target. Ed-script patches still
require an `ed(1)` program at `/bin/ed`.
