#!/bin/bash
# run.sh - run kernel

USERFS_DIR="userfs"
USERLAND_DIR="userland"
LIBC_DIR="libc"


echo "=== RUN KERNEL SCRIPT ==="

# Verifier que userfs existe
if [ ! -d "$USERFS_DIR" ]; then
    echo "Error: userfs directory not found!"
    exit 1
fi

if [ ! -d "$USERLAND_DIR" ]; then
    echo "Error: userland directory not found!"
    exit 1
fi

if [ ! -d "$LIBC_DIR" ]; then
    echo "Error: libc directory not found!"
    exit 1
fi

cd $LIBC_DIR
make distclean
make install

cd "../$USERLAND_DIR/hello/"
rm hello
make

cd "../../$USERLAND_DIR/hello2/"
rm hello2
make

cd "../../$USERLAND_DIR/readfile/"
rm readfile
make

cd "../../$USERLAND_DIR/malloc/"
rm malloc
make

cd "../../"
rm disk.img
make disk.img
make run-userfs

