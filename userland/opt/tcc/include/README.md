# TCC Include Staging

This directory documents the future `/opt/tcc/include` payload.

The actual generated filesystem should eventually contain:

- TCC private headers needed by the compiler.
- ArmOS target support headers, if required.
- References to the active newlib headers, preferably without duplicating the
  whole newlib sysroot.

Keep this directory source-only. Generated installed headers should be produced
by the build.
