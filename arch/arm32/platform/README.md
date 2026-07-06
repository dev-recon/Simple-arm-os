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

## Optional `qemu.sh`

Boot scripts source `qemu.sh` from the selected platform directory. Provide it
when the platform can be launched through the repository scripts.

The file is shell syntax and should define `*_DEFAULT` values rather than
overriding user-provided environment variables directly:

- `QEMU_MACHINE_DEFAULT`
- `QEMU_CPU_DEFAULT`
- `QEMU_BLOCK_DEVICE_DEFAULT`
- `QEMU_GPU_DEVICE_DEFAULT`
- `QEMU_INPUT_DEVICE_DEFAULT`
- `QEMU_NET_DEVICE_MODEL_DEFAULT`

The shared loader in `tools/qemu_platform_env.sh` applies these defaults while
preserving explicit environment overrides.

## Rules

- Do not add platform-specific conditionals to the root Makefile when a
  platform fragment can own the decision.
- Keep platform discovery in C behind `arch_platform_*` and `platform_*`
  helpers rather than scattering QEMU or board constants through generic code.
- Describe platform quirks as named capabilities. For example, qemu-virt
  declares whether GIC ITARGETSR routing is auto-managed instead of making the
  interrupt controller guess the machine name.
- A directory without `platform.mk` is documentation or staging only; it is not
  a supported `TARGET_PLATFORM`.
