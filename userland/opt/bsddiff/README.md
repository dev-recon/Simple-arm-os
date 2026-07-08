# BSD diff for ArmOS

This directory vendors NetBSD `usr.bin/diff` as ArmOS' BSD-style `diff(1)`.

The build script cross-compiles it into:

```sh
/opt/bsddiff/bin/diff
```

When `BUILD_BSD=1` is used, the top-level build stages a visible symlink:

```sh
/usr/bin/diff -> ../../opt/bsddiff/bin/diff
```

## ArmOS compatibility notes

Local compatibility code provides small `err(3)`, `fgetln(3)`,
`fnmatch(3)`, `scandir(3)`, `alphasort(3)`, `pread(2)`, `execl(3)`,
and `reallocarr(3)` shims.

The side-by-side `-y` mode still depends on an external `pr(1)` program,
matching the upstream implementation.
