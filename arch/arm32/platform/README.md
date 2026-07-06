# ARM32 Platform Fragments

Each ARM32 platform lives under `arch/arm32/platform/<platform_name>/`.
The top-level Makefile maps `TARGET_PLATFORM=qemu-virt` to
`arch/arm32/platform/qemu_virt/` by replacing dashes with underscores.

## Required `platform.mk`

A buildable platform must provide a `platform.mk` file defining:

- `PLATFORM_CPU_CFLAGS`: CPU-specific compiler flags.
- `PLATFORM_CFLAGS`: platform preprocessor flags, usually including
  `$(PLATFORM_CPU_CFLAGS)` and one `ARMOS_PLATFORM_*` define.
- `PLATFORM_OBJS`: platform-owned objects and required board drivers.
- `QEMU_MACHINE`: default QEMU machine for boot scripts and `run-userfs`.
- `QEMU_RUN_MACHINE`: optional Makefile `run` machine, when it differs from
  `QEMU_MACHINE`.
- `QEMU_CPU`: default QEMU CPU model.

The fragment may use these variables from the root Makefile:

- `ARCH_DIR`: selected architecture directory, for example `arch/arm32`.
- `PLATFORM_DIR`: selected platform directory.

## Rules

- Do not add platform-specific conditionals to the root Makefile when a
  platform fragment can own the decision.
- Keep platform discovery in C behind `arch_platform_*` and `platform_*`
  helpers rather than scattering QEMU or board constants through generic code.
- A directory without `platform.mk` is documentation or staging only; it is not
  a supported `TARGET_PLATFORM`.
