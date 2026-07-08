# BSD install for ArmOS

This directory vendors NetBSD `usr.bin/xinstall` as ArmOS' BSD-style
`install(1)`.

The build script cross-compiles it into:

```sh
/opt/bsdinstall/bin/install
```

When `BUILD_BSD=1` is used, the top-level build stages a visible symlink:

```sh
/usr/bin/install -> ../../opt/bsdinstall/bin/install
```

## ArmOS compatibility notes

The first ArmOS port targets the common self-hosting build patterns:

- `install -d DIR ...`
- `install [-m MODE] SOURCE TARGET`
- `install [-m MODE] SOURCE ... DIRECTORY`
- simple numeric or built-in `root`/`wheel`/`daemon`/`user` owner and group names

ArmOS provides path-based `chmod(2)` and `chown(2)`, while this upstream code
uses `fchmod(2)` and `fchown(2)` after opening the destination.  The local
compat layer tracks opened destination paths and maps those fd-based calls back
to ArmOS' path-based syscalls.

Advanced NetBSD build features are intentionally limited for now:

- `-N dbdir` user/group database lookup is unsupported.
- `-M` metalog output works for basic entries, but digest values requested with
  `-h` are emitted as `unsupported`.
- BSD file flags from `-f` are disabled in nbtool mode.
