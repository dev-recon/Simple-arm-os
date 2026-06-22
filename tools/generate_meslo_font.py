#!/usr/bin/env python3
"""Generate ArmOS framebuffer font data from MesloLGS NF Regular.

The output is a fixed-cell grayscale alpha font. The renderer blends these
alpha bytes with the requested foreground/background colors.
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
FONT_PATH = ROOT / "assets/fonts/MesloLGS-NF-Regular.ttf"

VARIANTS = [
    {
        "name": "meslo_12x24",
        "out": ROOT / "kernel/lib/font_meslo_12x24.c",
        "font_size_px": 18,
        "cell_w": 12,
        "cell_h": 24,
        "supersample": 3,
    },
    {
        "name": "meslo_10x20",
        "out": ROOT / "kernel/lib/font_meslo_10x20.c",
        "font_size_px": 15,
        "cell_w": 10,
        "cell_h": 20,
        "supersample": 4,
    },
    {
        "name": "meslo_8x16",
        "out": ROOT / "kernel/lib/font_meslo_8x16.c",
        "font_size_px": 12,
        "cell_w": 8,
        "cell_h": 16,
        "supersample": 4,
    },
]

FIRST = 32
LAST = 126


def render_char(font: ImageFont.FreeTypeFont, ch: str,
                cell_w: int, cell_h: int, supersample: int) -> list[int]:
    scaled_w = cell_w * supersample
    scaled_h = cell_h * supersample
    img = Image.new("L", (scaled_w, scaled_h), 0)
    draw = ImageDraw.Draw(img)
    bbox = draw.textbbox((0, 0), ch, font=font)
    width = bbox[2] - bbox[0]
    height = bbox[3] - bbox[1]
    x = (scaled_w - width) // 2 - bbox[0]
    y = (scaled_h - height) // 2 - bbox[1]
    draw.text((x, y), ch, font=font, fill=255)
    if supersample > 1:
        img = img.resize((cell_w, cell_h), Image.Resampling.LANCZOS)
    return list(img.getdata())


def write_variant(variant: dict[str, object]) -> Path:
    name = str(variant["name"])
    out_path = Path(variant["out"])
    font_size_px = int(variant["font_size_px"])
    cell_w = int(variant["cell_w"])
    cell_h = int(variant["cell_h"])
    supersample = int(variant.get("supersample", 1))
    font = ImageFont.truetype(str(FONT_PATH), font_size_px * supersample)
    glyphs: list[int] = []

    for code in range(FIRST, LAST + 1):
        glyphs.extend(render_char(font, chr(code), cell_w, cell_h, supersample))

    with out_path.open("w", encoding="utf-8") as f:
        f.write("/* Generated from MesloLGS NF Regular.ttf. Do not edit by hand. */\n")
        f.write("/* Source license: assets/fonts/MesloLGS-NF-LICENSE.txt (Apache-2.0). */\n")
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
        f.write(f"    .width = {cell_w},\n")
        f.write(f"    .height = {cell_h},\n")
        f.write(f"    .first = {FIRST},\n")
        f.write(f"    .last = {LAST},\n")
        f.write(f"    .glyphs = {name}_glyphs,\n")
        f.write("};\n")

    return out_path


def main() -> None:
    for variant in VARIANTS:
        print(write_variant(variant))


if __name__ == "__main__":
    main()
