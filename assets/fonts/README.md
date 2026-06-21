# Fonts

ArmOS uses the Spleen bitmap font for the experimental virtio-gpu framebuffer
console renderer. MesloLGS NF is kept as an experimental TrueType-derived
variant, but Spleen is preferred for the kernel console because it renders
crisply without scaling or subpixel hinting.

Spleen source: <https://github.com/fcambus/spleen>

Spleen license: BSD 2-Clause, mirrored in `spleen/LICENSE`.

MesloLGS NF source: <https://github.com/romkatv/powerlevel10k-media>

MesloLGS NF license: Apache License 2.0, mirrored in
`MesloLGS-NF-LICENSE.txt`.

The generated kernel font sources are:

- `kernel/lib/font_spleen_8x16.c`
- `kernel/lib/font_spleen_12x24.c`
- `kernel/lib/font_meslo_12x24.c`
- `kernel/lib/font_meslo_10x20.c`
- `kernel/lib/font_meslo_8x16.c`

They can be regenerated with:

```sh
python3 tools/generate_spleen_font.py
python3 tools/generate_meslo_font.py
```
