# BSD xargs for ArmOS

This directory vendors NetBSD `usr.bin/xargs` as ArmOS' BSD-style `xargs(1)`.

The build script cross-compiles it into:

```sh
/opt/bsdxargs/bin/xargs
```

When `BUILD_BSD=1` is used, the top-level build stages a visible symlink:

```sh
/usr/bin/xargs -> ../../opt/bsdxargs/bin/xargs
```

## ArmOS compatibility notes

Local compatibility code provides small `err(3)`, `fgetln(3)`,
`setprogname(3)`, `getprogname(3)`, signal-name, and `sysconf(3)` shims.
`vfork(2)` is mapped to `fork(2)`.
