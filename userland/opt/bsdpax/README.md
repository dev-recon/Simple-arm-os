# NetBSD pax/tar for ArmOS

This directory contains the ArmOS port of NetBSD `pax` from `bin/pax`.

The first ArmOS build uses NetBSD's `SMALL` profile:

- `pax` and `tar` modes are enabled.
- `cpio` and mtree-spec input support are intentionally left out for now.
- Compression filters (`-z`, `-j`, `-J`) still depend on external commands
  such as `gzip`, `bzip2`, or `xz`.

When `BUILD_BSD=1` is used, the top-level build stages visible symlinks:

- `/usr/bin/pax -> ../../opt/bsdpax/bin/pax`
- `/usr/bin/tar -> ../../opt/bsdpax/bin/tar`

The `tar` entry in `/opt/bsdpax/bin` is itself a symlink to `pax`, letting the
upstream program select tar-compatible option parsing from `argv[0]`.
