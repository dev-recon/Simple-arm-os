ArmOS framebuffer and XV test images
=====================================

test-pattern.png
  Source: https://commons.wikimedia.org/wiki/File:Testbild-1.png
  Author: Rainer Zenz
  License: released into the public domain by the copyright holder

jpeg-landscape.jpg
  Source: https://commons.wikimedia.org/wiki/File:JPEG_example_down.jpg
  Author: Lz64
  License: released into the public domain by the copyright holder

test-pattern-320x240.tiff
  ArmOS test derivative of test-pattern.png, resized to 320x240 and encoded
  as a minimal little-endian, uncompressed RGB TIFF without EXIF or ICC
  metadata. It remains under the same public-domain dedication.

Examples:
  fbview /home/user/images/test-pattern.png
  fbview /home/user/images/jpeg-landscape.jpg
  fbview /home/user/images/test-pattern-320x240.tiff

XV may also open these files when a locally built XV binary is installed.
