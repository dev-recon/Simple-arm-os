#!/bin/bash
# build.sh - recompile tout sans lancer QEMU

set -e

echo "=== BUILD SCRIPT ==="

cd libc
make distclean
make install
cd ..

cd userland
make clean
make install
cd ..

make disk.img

echo "=== BUILD DONE ==="
echo "Lancer QEMU avec: make run-userfs"
