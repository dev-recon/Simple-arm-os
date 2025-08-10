#!/bin/bash
# qemu_loader_method.sh - Charger userfs via le device loader de QEMU

USERFS_DIR="./userfs"
USERFS_TAR="userfs.tar"
USERFS_BIN="userfs.bin"

echo "=== QEMU LOADER METHOD ==="
echo "Creating binary file for QEMU loader device..."

# Verifier que userfs existe
if [ ! -d "$USERFS_DIR" ]; then
    echo "Error: userfs directory not found!"
    exit 1
fi

# Methode 1: Creer un archive TAR
echo "1. Creating TAR archive..."
tar --exclude='._*' \
    --exclude='.DS_Store' \
    --exclude='*/.DS_Store' \
    --exclude='*/._*' \
    --format=ustar \
    -cf "$USERFS_TAR" -C userfs .
echo "OK TAR created: $USERFS_TAR ($(du -h $USERFS_TAR | cut -f1))"

# Methode 2: Creer un fichier binaire brut
echo "2. Creating raw binary..."
# Creer un fichier avec une signature + taille + donnees
{
    # Signature magic (8 bytes): "USERFS01"
    printf "USERFS01"
    
    # Taille du TAR (4 bytes little-endian)
    tar_size=$(stat -c%s "$USERFS_TAR" 2>/dev/null || stat -f%z "$USERFS_TAR")
    printf "\\$(printf "%03o" $((tar_size & 0xFF)))"
    printf "\\$(printf "%03o" $(((tar_size >> 8) & 0xFF)))"
    printf "\\$(printf "%03o" $(((tar_size >> 16) & 0xFF)))"
    printf "\\$(printf "%03o" $(((tar_size >> 24) & 0xFF)))"
    
    # Donnees TAR
    cat "$USERFS_TAR"
} > "$USERFS_BIN"

echo "OK Binary created: $USERFS_BIN ($(du -h $USERFS_BIN | cut -f1))"

echo ""
echo "=== QEMU LOADER METHOD READY ==="
echo ""
echo "- Files created:"
echo "  $USERFS_TAR - TAR archive"
echo "  $USERFS_BIN - Binary with header"
echo ""

echo "- Usage with QEMU:"
echo ""
echo "# Method 1: Load binary at specific address"
echo "qemu-system-arm -M virt -cpu cortex-a15 \\"
echo "  -m 1G -smp 1 \\"
echo "  -kernel kernel.bin \\"
echo "  -device loader,file=$USERFS_BIN,addr=0x42000000 \\"
echo "  -nographic"
echo ""

echo "# Method 2: Multiple files"
echo "qemu-system-arm -M virt -cpu cortex-a15 \\"
echo "  -m 1G -smp 1 \\"
echo "  -kernel kernel.bin \\"
echo "  -device loader,file=$USERFS_TAR,addr=0x42000000 \\"
echo "  -device loader,file=other_file.bin,addr=0x43000000 \\"
echo "  -nographic"
echo ""

echo "📋 Integration in your kernel:"
echo "1. Add userfs_loader.c to your build"
echo "2. Call load_userfs_from_memory() after RAMFS init"
echo "3. Files will be extracted to your RAMFS"
echo ""

echo "OK QEMU loader method ready!"