# NetBSD m4 for ArmOS

This directory contains the ArmOS port of NetBSD `m4` from `usr.bin/m4`.

The build generates the yacc and flex sources out of tree, then cross-compiles
the resulting program into:

```sh
/opt/bsdm4/bin/m4
```

When `BUILD_BSD=1` is used, the top-level build stages a visible symlink:

```sh
/usr/bin/m4 -> ../../opt/bsdm4/bin/m4
```

## ArmOS compatibility notes

Local compatibility code provides `err(3)` and `setprogname(3)` shims, plus a
small `<paths.h>` override so GNU-style `syscmd` and `esyscmd` run commands via
ArmOS' `/sbin/mash`.

NetBSD's `EXTENDED` m4 profile is enabled. POSIX regex support comes from the
ArmOS newlib sysroot.
