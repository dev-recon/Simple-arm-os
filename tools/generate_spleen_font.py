#!/usr/bin/env python3
"""Generate ArmOS framebuffer font data from Spleen BDF files.

Spleen is already a bitmap font. Unlike TrueType-derived fonts, no scaling or
antialiasing is done here: each source bit becomes an alpha byte in the kernel
font table.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FONT_DIR = ROOT / "assets/fonts/spleen"

VARIANTS = [
    {
        "name": "spleen_8x16",
        "src": FONT_DIR / "spleen-8x16.bdf",
        "out": ROOT / "kernel/lib/font_spleen_8x16.c",
    },
    {
        "name": "spleen_12x24",
        "src": FONT_DIR / "spleen-12x24.bdf",
        "out": ROOT / "kernel/lib/font_spleen_12x24.c",
    },
]

FIRST = 32
LAST = 126


def parse_bdf(path: Path) -> tuple[int, int, int, int, dict[int, list[int]]]:
    font_w = font_h = font_xoff = font_yoff = 0
    glyphs: dict[int, list[int]] = {}

    enc: int | None = None
    bbx: tuple[int, int, int, int] | None = None
    bitmap: list[str] = []
    in_bitmap = False

    for raw_line in path.read_text(encoding="ascii", errors="replace").splitlines():
        line = raw_line.strip()
        if line.startswith("FONTBOUNDINGBOX "):
            _, w, h, xoff, yoff = line.split()
            font_w, font_h = int(w), int(h)
            font_xoff, font_yoff = int(xoff), int(yoff)
        elif line == "STARTCHAR":
            enc = None
            bbx = None
            bitmap = []
            in_bitmap = False
        elif line.startswith("ENCODING "):
            enc = int(line.split()[1])
        elif line.startswith("BBX "):
            _, w, h, xoff, yoff = line.split()
            bbx = (int(w), int(h), int(xoff), int(yoff))
        elif line == "BITMAP":
            in_bitmap = True
        elif line == "ENDCHAR":
            if enc is not None and FIRST <= enc <= LAST and bbx is not None:
                glyphs[enc] = render_glyph(font_w, font_h, font_xoff,
                                           font_yoff, bbx, bitmap)
            enc = None
            bbx = None
            bitmap = []
            in_bitmap = False
        elif in_bitmap:
            bitmap.append(line)

    if font_w <= 0 or font_h <= 0:
        raise ValueError(f"{path}: missing FONTBOUNDINGBOX")
    return font_w, font_h, font_xoff, font_yoff, glyphs


def render_glyph(font_w: int, font_h: int, font_xoff: int, font_yoff: int,
                 bbx: tuple[int, int, int, int], bitmap: list[str]) -> list[int]:
    glyph_w, glyph_h, glyph_xoff, glyph_yoff = bbx
    canvas = [0] * (font_w * font_h)

    x0 = glyph_xoff - font_xoff
    y0 = font_yoff + font_h - glyph_yoff - glyph_h

    for row, hex_row in enumerate(bitmap[:glyph_h]):
        bits = int(hex_row, 16) if hex_row else 0
        bit_count = len(hex_row) * 4
        for col in range(glyph_w):
            if bits & (1 << (bit_count - 1 - col)):
                x = x0 + col
                y = y0 + row
                if 0 <= x < font_w and 0 <= y < font_h:
                    canvas[y * font_w + x] = 0xFF

    return canvas


def write_variant(variant: dict[str, object]) -> Path:
    name = str(variant["name"])
    src = Path(variant["src"])
    out = Path(variant["out"])
    font_w, font_h, _xoff, _yoff, glyph_map = parse_bdf(src)

    glyphs: list[int] = []
    blank = [0] * (font_w * font_h)
    for code in range(FIRST, LAST + 1):
        glyphs.extend(glyph_map.get(code, blank))

    with out.open("w", encoding="utf-8") as f:
        f.write(f"/* Generated from {src.relative_to(ROOT)}. Do not edit by hand. */\n")
        f.write("/* Source license: assets/fonts/spleen/LICENSE (BSD-2-Clause). */\n")
        f.write("#include <kernel/display.h>\n\n")
        f.write(f"static const uint8_t {name}_glyphs[] = {{\n")
        line: list[str] = []
        for value in glyphs:
            line.append(f"0x{value:02X}")
            if len(line) == 16:
                f.write("    " + ", ".join(line) + ",\n")
                line = []
        if line:
            f.write("    " + ", ".join(line) + ",\n")
        f.write("};\n\n")
        f.write(f"const font_t font_{name} = {{\n")
        f.write(f"    .width = {font_w},\n")
        f.write(f"    .height = {font_h},\n")
        f.write(f"    .first = {FIRST},\n")
        f.write(f"    .last = {LAST},\n")
        f.write(f"    .glyphs = {name}_glyphs,\n")
        f.write("};\n")

    return out


def main() -> None:
    for variant in VARIANTS:
        print(write_variant(variant))


if __name__ == "__main__":
    main()
