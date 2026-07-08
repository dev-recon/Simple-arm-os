# ArmOS libpng Port

This directory contains the library sources imported from libpng 1.6.58.

Build the ArmOS bundle with:

```sh
./tools/build_zlib.sh
./tools/build_libpng.sh
```

The bundle installs:

- `/opt/libpng/include/png.h`
- `/opt/libpng/include/pngconf.h`
- `/opt/libpng/include/pnglibconf.h`
- `/opt/libpng/lib/libpng.a`
- `/usr/bin/pngtest`
