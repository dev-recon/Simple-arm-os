#!/usr/bin/env python3
#
# ArmOS
# Copyright (c) 2026 Mohamed Ennassiri
#
# Licensed under the Apache License, Version 2.0.
# See LICENSE for details.
#
# File: tools/make_mbr.py
# Layer: Host tooling
# Description: Write a small MBR partition table into disk.img.
#

import struct
import sys


MBR_SIZE = 512
PARTITION_TABLE_OFFSET = 446
MBR_SIGNATURE_OFFSET = 510

PART_TYPE_EXT2 = 0x83
PART_TYPE_FAT32_LBA = 0x0C


def usage() -> None:
    print(
        "usage: make_mbr.py <disk.img> "
        "<ext2_start_lba> <ext2_sectors> <fat32_start_lba> <fat32_sectors>",
        file=sys.stderr,
    )


def partition_entry(part_type: int, start_lba: int, sectors: int) -> bytes:
    if start_lba < 1:
        raise ValueError("partition start LBA must leave room for the MBR")
    if sectors <= 0:
        raise ValueError("partition size must be positive")
    if start_lba > 0xFFFFFFFF or sectors > 0xFFFFFFFF:
        raise ValueError("MBR fields are limited to 32-bit LBAs")

    # CHS is legacy and ignored by ArmOS/QEMU here. Use conventional sentinel
    # values while keeping the authoritative layout in the LBA fields.
    start_chs = b"\x00\x02\x00"
    end_chs = b"\xfe\xff\xff"
    return struct.pack("<B3sB3sII", 0x00, start_chs, part_type, end_chs, start_lba, sectors)


def main(argv: list[str]) -> int:
    if len(argv) != 6:
        usage()
        return 2

    disk_path = argv[1]
    ext2_start = int(argv[2], 0)
    ext2_sectors = int(argv[3], 0)
    fat32_start = int(argv[4], 0)
    fat32_sectors = int(argv[5], 0)

    mbr = bytearray(MBR_SIZE)
    mbr[PARTITION_TABLE_OFFSET : PARTITION_TABLE_OFFSET + 16] = partition_entry(
        PART_TYPE_EXT2, ext2_start, ext2_sectors
    )
    mbr[PARTITION_TABLE_OFFSET + 16 : PARTITION_TABLE_OFFSET + 32] = partition_entry(
        PART_TYPE_FAT32_LBA, fat32_start, fat32_sectors
    )
    mbr[MBR_SIGNATURE_OFFSET] = 0x55
    mbr[MBR_SIGNATURE_OFFSET + 1] = 0xAA

    with open(disk_path, "r+b") as disk:
        disk.seek(0)
        disk.write(mbr)

    print(
        f"MBR: p1 ext2 start={ext2_start} sectors={ext2_sectors}; "
        f"p2 fat32 start={fat32_start} sectors={fat32_sectors}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
