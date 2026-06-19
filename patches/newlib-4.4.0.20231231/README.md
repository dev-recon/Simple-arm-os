Newlib patches for arm-os
=========================

`tools/build_newlib.sh` extracts the vanilla newlib archive, then applies the
patches listed in `series` from this directory.

The series is intentionally empty for now. The current arm-os integration keeps
newlib itself vanilla and provides the OS ABI in tracked repo code:

- `newlib-port/` provides crt0, raw syscall wrappers, errno/status translation,
  signal translation, and newlib syscall hooks.
- `userland/include/` provides the small compatibility headers
  that arm-os exposes but vanilla newlib does not ship for this target.

If we later need to modify upstream newlib sources, add a patch file here and
list it in `series`. A fresh install will then reproduce the exact same sysroot
from the upstream archive.
