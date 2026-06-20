#!/usr/bin/env python3
"""Generate ArmOS framebuffer font data from MesloLGS NF Regular.

The output is a fixed-cell grayscale alpha font. The renderer blends these
alpha bytes with the requested foreground/background colors.
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
FONT_PATH = ROOT / "assets/fonts/MesloLGS-NF-Regular.ttf"
OUT_PATH = ROOT / "kernel/lib/font_meslo_12x24.c"

FONT_SIZE_PX = 18
CELL_W = 12
CELL_H = 24
FIRST = 32
LAST = 126


def render_char(font: ImageFont.FreeTypeFont, ch: str) -> list[int]:
    img = Image.new("L", (CELL_W, CELL_H), 0)
    draw = ImageDraw.Draw(img)
    bbox = draw.textbbox((0, 0), ch, font=font)
    width = bbox[2] - bbox[0]
    height = bbox[3] - bbox[1]
    x = (CELL_W - width) // 2 - bbox[0]
    y = (CELL_H - height) // 2 - bbox[1]
    draw.text((x, y), ch, font=font, fill=255)
    return list(img.getdata())


def main() -> None:
    font = ImageFont.truetype(str(FONT_PATH), FONT_SIZE_PX)
    glyphs: list[int] = []
    for code in range(FIRST, LAST + 1):
        glyphs.extend(render_char(font, chr(code)))

    with OUT_PATH.open("w", encoding="utf-8") as f:
        f.write("/* Generated from MesloLGS NF Regular.ttf. Do not edit by hand. */\n")
        f.write("/* Source license: assets/fonts/MesloLGS-NF-LICENSE.txt (Apache-2.0). */\n")
        f.write("#include <kernel/display.h>\n\n")
        f.write("static const uint8_t meslo_12x24_glyphs[] = {\n")
        line: list[str] = []
        for value in glyphs:
            line.append(f"0x{value:02X}")
            if len(line) == 16:
                f.write("    " + ", ".join(line) + ",\n")
                line = []
        if line:
            f.write("    " + ", ".join(line) + ",\n")
        f.write("};\n\n")
        f.write("const font_t font_meslo_12x24 = {\n")
        f.write(f"    .width = {CELL_W},\n")
        f.write(f"    .height = {CELL_H},\n")
        f.write(f"    .first = {FIRST},\n")
        f.write(f"    .last = {LAST},\n")
        f.write("    .glyphs = meslo_12x24_glyphs,\n")
        f.write("};\n")

    print(OUT_PATH)


if __name__ == "__main__":
    main()
