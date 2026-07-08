# BSD ELF tools for ArmOS

This directory contains a small ArmOS-native ELF/archive tool bundle:

- `ar`
- `ranlib`
- `nm`
- `strip`
- `size`

The implementation is intentionally focused on the ArmOS self-hosting path:
ELF32 little-endian objects/executables and standard `ar` archives with a GNU
style symbol table. It is not a full GNU binutils or ELF Tool Chain import.

The build script cross-compiles one static binary and installs visible symlinks:

```text
/opt/bsdelftools/bin/ar
/opt/bsdelftools/bin/ranlib
/opt/bsdelftools/bin/nm
/opt/bsdelftools/bin/strip
/opt/bsdelftools/bin/size
```

When `BUILD_BSD=1` is used, `/usr/bin` symlinks point to those entries.

## Current scope

- `ar`: supports `r`, `q`, `d`, `t`, `p`, `x`, `s`, plus `c` and `v` modifiers.
- `ranlib`: rebuilds the archive symbol table.
- `nm`: prints useful ELF32 symbols from files or archives.
- `size`: prints text/data/bss totals for ELF32 files or archive members.
- `strip`: strips executable ELF32 files by removing section headers and
  non-loaded trailing data. It intentionally refuses relocatable objects.

After `strip`, the executable should still run, but tools that need section
headers, such as this bundle's `nm` and `size`, may no longer be able to
inspect the stripped file.

## Smoke test

```sh
printf 'int answer(void){return 42;}\n' > answer.c
printf 'extern int answer(void); int main(void){return answer() == 42 ? 0 : 1;}\n' > main.c
tcc -c answer.c -o answer.o
ar rcs libanswer.a answer.o
ranlib libanswer.a
ar t libanswer.a
nm libanswer.a
size answer.o
tcc main.c libanswer.a -o answer-test
./answer-test
strip -o answer-test.stripped answer-test
./answer-test.stripped
```
