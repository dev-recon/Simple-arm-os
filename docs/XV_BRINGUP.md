# xv Bring-Up Notes

The goal is to make `xv` build and run on ArmOS without turning the work into a
full Xorg port by default.

## Strategy

1. Expose a minimal framebuffer ABI first.
   - `/dev/fb0` is a character device.
   - `ARMOS_FBIOGET_INFO` reports width, height, pitch, bpp, size, and format.
   - The first supported pixel format is ARGB8888.
2. Keep every step testable from the shell.
   - `fbtest` opens `/dev/fb0`, paints a deterministic pattern, reads back the
     first pixel, and prints `FBTEST_OK`.
3. Port image/display dependencies only after the raw display path is stable.
   - Likely early dependencies: `libjpeg`, `libpng`, `zlib`, `libtiff`.
   - Avoid committing to a full Xorg server until `xv` has a proven build path.

## Current Smoke Test

```sh
fbtest
```

Expected output:

```text
fbtest: /dev/fb0 1024x768 pitch=4096 bpp=32 size=3145728 stat_size=3145728
FBTEST_OK
```
