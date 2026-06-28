# ArmOS TCC Port

This directory is the staging area for the Tiny C Compiler port.

ArmOS treats TCC as an external userland package, installed under `/opt/tcc`
inside the generated filesystem:

```text
/opt/tcc/
  bin/tcc
  include/
  lib/
```

The first goal is deliberately small:

```sh
tcc hello.c -o hello
./hello
```

## Porting Strategy

1. Import a pinned upstream TCC source snapshot into `src/`.
2. Keep ArmOS-specific changes as patches in `patches/`.
3. Build a cross-host `tcc` binary that emits ArmOS ARM32 ELF executables.
4. Install runtime pieces under `/opt/tcc/lib` and headers under
   `/opt/tcc/include`.
5. Once the compiler can run inside ArmOS, switch from cross-host validation to
   native compile tests.

## Constraints

- Newlib is the supported C library for new ArmOS userland.
- Legacy home-grown libc is frozen and should not be used for TCC work.
- The build must remain optional: ArmOS must still build and boot without TCC.
- Generated binaries and upstream archives must not be committed accidentally.

## Expected ArmOS Integration Points

TCC will need:

- ArmOS syscall/newlib glue already used by current user programs.
- Startup objects compatible with `execve`.
- A linker setup that produces user ELF files loaded at the ArmOS user text
  address.
- Include search paths rooted at `/opt/tcc/include` and newlib headers.
- Library search paths rooted at `/opt/tcc/lib`.

## Open Questions

- Which upstream TCC revision should be pinned?
- Do we initially build a cross TCC on the host, a native TCC inside ArmOS, or
  both?
- Do we keep generated ArmOS TCC runtime objects in the repo, or rebuild them as
  part of `build.sh`?

## Current Bring-up Note

The working native route is documented in `docs/TCC_BRINGUP.md`.

The key point is that the real compiler installed as `/opt/tcc/bin/tcc` must be
TinyCC's `arm-eabi-tcc` target. The generic `arm` target can produce objects but
does not currently link ArmOS/newlib binaries correctly.
