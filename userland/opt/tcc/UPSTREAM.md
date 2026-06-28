# TinyCC Upstream Provenance

Imported from the official TinyCC repository:

```text
Repository: https://repo.or.cz/tinycc.git
Branch:     mob
Commit:     a338258d309c888bde96b2d1f206299231a54ddf
Imported:   2026-06-23
```

The `mob` branch is TinyCC's active contribution branch. It was selected over
`release_0_9_27` because the latest release is from 2017, while ArmOS needs a
modern ARM-capable baseline for iterative porting.

The upstream source is vendored under `src/` without its `.git` directory.
ArmOS-specific changes should be kept as patches in `patches/` when practical.
