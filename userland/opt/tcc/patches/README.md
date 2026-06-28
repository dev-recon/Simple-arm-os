# TCC Patches

Keep ArmOS-specific TCC patches here.

Preferred workflow:

1. Import upstream TCC unchanged into `../src`.
2. Apply patches from this directory in deterministic order.
3. Keep each patch focused:
   - target/ELF support
   - include/library paths
   - ArmOS runtime/startup integration
   - optional native build fixes

Do not edit vendored upstream code without also recording the corresponding
patch here.
