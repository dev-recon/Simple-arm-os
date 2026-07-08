# Upstream

This is an ArmOS-local implementation.

The archive format follows the traditional BSD/GNU `ar` layout used by TinyCC
and GNU binutils:

- global magic: `!<arch>\n`
- 60-byte archive member headers
- optional `/` symbol table with big-endian offsets

ELF constants and structures come from the ArmOS newlib sysroot `<elf.h>`.
