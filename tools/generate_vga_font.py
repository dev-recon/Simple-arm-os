#!/usr/bin/env python3
"""Generate ArmOS framebuffer font data from the legacy VGA-like 8x16 table."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "kernel/lib/font_8x16.c"
OUT = ROOT / "kernel/lib/font_vga_8x16.c"
FIRST = 32
LAST = 126
WIDTH = 8
HEIGHT = 16


def main() -> None:
    values = [int(v, 16) for v in re.findall(r"0x([0-9A-Fa-f]{2})", SRC.read_text())]
    expected = (LAST - FIRST + 1) * HEIGHT
    if len(values) != expected:
        raise SystemExit(f"{SRC}: expected {expected} bytes, got {len(values)}")

    glyphs: list[int] = []
    for row_byte in values:
        for bit in range(7, -1, -1):
            glyphs.append(0xFF if (row_byte & (1 << bit)) else 0x00)

    with OUT.open("w", encoding="utf-8") as f:
        f.write("/* Generated from kernel/lib/font_8x16.c. Do not edit by hand. */\n")
        f.write("/* VGA-like fixed 8x16 ASCII bitmap font used by the graphical console. */\n")
        f.write("#include <kernel/display.h>\n\n")
        f.write("static const uint8_t vga_8x16_glyphs[] = {\n")
        line: list[str] = []
        for value in glyphs:
            line.append(f"0x{value:02X}")
            if len(line) == 16:
                f.write("    " + ", ".join(line) + ",\n")
                line = []
        if line:
            f.write("    " + ", ".join(line) + ",\n")
        f.write("};\n\n")
        f.write("const font_t font_vga_8x16 = {\n")
        f.write(f"    .width = {WIDTH},\n")
        f.write(f"    .height = {HEIGHT},\n")
        f.write(f"    .first = {FIRST},\n")
        f.write(f"    .last = {LAST},\n")
        f.write("    .glyphs = vga_8x16_glyphs,\n")
        f.write("};\n")

    print(OUT)


if __name__ == "__main__":
    main()
