# TCC Library Staging

This directory documents the future `/opt/tcc/lib` payload.

Expected contents once the port is active:

- ArmOS startup objects, for example `crt1.o`, `crti.o`, `crtn.o`.
- Any TCC runtime objects required for ARM code generation.
- Optional linker scripts or specs if TCC needs target-specific defaults.

Generated object files should not be committed unless we explicitly decide that
the bootstrapping story needs prebuilt seed artifacts.
