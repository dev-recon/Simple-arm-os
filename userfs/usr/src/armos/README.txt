ArmOS source tree snapshot
==========================

This directory contains the userland sources installed in the root filesystem
for native TinyCC experiments.

Layout:
  /usr/src/armos/userland/include
      Public ArmOS userland headers.

  /usr/src/armos/userland/coreutils/src
      POSIX-like command sources installed in /bin.

  /usr/src/armos/userland/programs
      Test and demo programs installed in /usr/bin.

  /usr/src/armos/userland/system
      System userland: init, mash, mount/shutdown helpers.

Examples:
  tcc /usr/src/armos/userland/coreutils/src/ls.c -o /tmp/ls-tcc
  /tmp/ls-tcc /proc

  tcc /usr/src/armos/userland/programs/mmaptest/mmaptest.c -o /tmp/mmaptest-tcc
  /tmp/mmaptest-tcc

Notes:
  The /usr/bin/tcc wrapper injects the ArmOS runtime objects, linker script
  options, newlib, and libgcc automatically for normal one-file builds.
