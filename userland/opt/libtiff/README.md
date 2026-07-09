# ArmOS libtiff Port

This directory contains the library sources imported from libtiff 4.7.2.

Build the ArmOS bundle with:

```sh
./tools/build_zlib.sh
./tools/build_libjpeg.sh
./tools/build_libtiff.sh
```

The bundle installs:

- `/opt/libtiff/include/tiff.h`
- `/opt/libtiff/include/tiffconf.h`
- `/opt/libtiff/include/tiffio.h`
- `/opt/libtiff/include/tiffvers.h`
- `/opt/libtiff/lib/libtiff.a`
- `/usr/bin/tifftest`

`tifftest` writes and reads a tiny uncompressed grayscale image through the
scanline API.  Deflate/ZIP support is compiled in for consumers, but should get
its own runtime smoke test before depending on compressed TIFF files.
