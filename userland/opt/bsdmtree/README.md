# BSD mtree for ArmOS

This directory vendors NetBSD `usr.sbin/mtree` as ArmOS' BSD-style `mtree(8)`.

The build script cross-compiles it into:

```sh
/opt/bsdmtree/bin/mtree
```

When `BUILD_BSD=1` is used, the top-level build stages a visible symlink:

```sh
/usr/bin/mtree -> ../../opt/bsdmtree/bin/mtree
/usr/sbin/mtree -> ../../opt/bsdmtree/bin/mtree
```

`/usr/bin/mtree` is the practical PATH entry.  `/usr/sbin/mtree` is kept as a
BSD-compatible alias because upstream lives under `usr.sbin/mtree`.

## ArmOS compatibility notes

The first ArmOS port targets practical self-hosting checks:

- generate specs with `mtree -c`
- verify specs with `mtree -f spec`
- compare file type, mode, uid/gid, size, link targets, timestamps, and cksum
- use `-p DIR` to change the verification root

Local compatibility code provides small `err(3)`, `fts(3)`, `vis(3)`,
`fparseln(3)`, mode parsing, uid/gid lookup, and file timestamp wrappers.

Advanced features are intentionally limited for now:

- `-N dbdir` alternate user/group databases are unsupported.
- BSD file flags are disabled in nbtool mode.
- MD5/RMD160/SHA digests are not built in this first pass.
