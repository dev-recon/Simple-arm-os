# Fonts

ArmOS uses `MesloLGS NF Regular` for the experimental virtio-gpu framebuffer
console renderer.

Source: <https://github.com/romkatv/powerlevel10k-media>

License: Apache License 2.0, mirrored in `MesloLGS-NF-LICENSE.txt`.

The generated kernel font source is `kernel/lib/font_meslo_12x24.c` and can be
regenerated with:

```sh
python3 tools/generate_meslo_font.py
```
