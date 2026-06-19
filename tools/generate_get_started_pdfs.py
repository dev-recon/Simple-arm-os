#!/usr/bin/env python3
"""Generate ArmOS get-started PDFs from Markdown without external packages."""

from __future__ import annotations

import os
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
OUT = ROOT / "output" / "pdf"

PAGE_W = 595.0
PAGE_H = 842.0
MARGIN_L = 58.0
MARGIN_R = 58.0
MARGIN_T = 58.0
MARGIN_B = 54.0
CONTENT_W = PAGE_W - MARGIN_L - MARGIN_R


def pdf_escape(text: str) -> str:
    return (
        text.replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .replace("\t", "    ")
    )


def strip_md_inline(text: str) -> str:
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = text.replace("**", "")
    text = text.replace("*", "")
    return text


@dataclass
class TextStyle:
    font: str
    size: int
    leading: int
    indent: float = 0.0
    gap_before: float = 0.0
    gap_after: float = 0.0


class PdfDoc:
    def __init__(self, title: str, subtitle: str):
        self.title = title
        self.subtitle = subtitle
        self.pages: list[list[str]] = []
        self.page: list[str] = []
        self.y = PAGE_H - MARGIN_T
        self.page_no = 0
        self._new_page(first=True)

    def _cmd(self, cmd: str) -> None:
        self.page.append(cmd)

    def _new_page(self, first: bool = False) -> None:
        if self.page:
            self._footer()
            self.pages.append(self.page)

        self.page_no += 1
        self.page = []
        self.y = PAGE_H - MARGIN_T

        if first:
            self._title_page()
        else:
            self._header()

    def _header(self) -> None:
        self._text(MARGIN_L, PAGE_H - 32, self.title, "Helvetica-Bold", 9)
        self._text(PAGE_W - MARGIN_R - 120, PAGE_H - 32, "ArmOS", "Helvetica", 9)
        self._line(MARGIN_L, PAGE_H - 42, PAGE_W - MARGIN_R, PAGE_H - 42)
        self.y = PAGE_H - MARGIN_T

    def _footer(self) -> None:
        self._line(MARGIN_L, 38, PAGE_W - MARGIN_R, 38)
        self._text(MARGIN_L, 24, self.subtitle, "Helvetica", 8)
        self._text(PAGE_W - MARGIN_R - 50, 24, f"{self.page_no}", "Helvetica", 8)

    def _title_page(self) -> None:
        self._text(MARGIN_L, PAGE_H - 155, "ArmOS", "Helvetica-Bold", 26)
        self._text(MARGIN_L, PAGE_H - 198, self.title, "Helvetica-Bold", 22)
        self._text(MARGIN_L, PAGE_H - 232, self.subtitle, "Helvetica", 12)
        self._line(MARGIN_L, PAGE_H - 252, PAGE_W - MARGIN_R, PAGE_H - 252, width=1.5)
        self.y = PAGE_H - 315

    def _ensure(self, height: float) -> None:
        if self.y - height < MARGIN_B:
            self._new_page()

    def _text(self, x: float, y: float, text: str, font: str, size: int) -> None:
        self._cmd(f"BT /{font} {size} Tf {x:.2f} {y:.2f} Td ({pdf_escape(text)}) Tj ET")

    def _line(self, x1: float, y1: float, x2: float, y2: float, width: float = 0.5) -> None:
        self._cmd(f"{width:.2f} w {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S")

    def add_text(self, text: str, style: TextStyle) -> None:
        if not text:
            self.y -= style.leading / 2
            return

        text = strip_md_inline(text)
        max_chars = max(18, int((CONTENT_W - style.indent) / (style.size * 0.52)))
        lines = textwrap.wrap(
            text,
            width=max_chars,
            replace_whitespace=True,
            drop_whitespace=True,
            break_long_words=False,
            break_on_hyphens=False,
        ) or [""]

        self._ensure(style.gap_before + len(lines) * style.leading + style.gap_after)
        self.y -= style.gap_before

        for line in lines:
            self._text(MARGIN_L + style.indent, self.y, line, style.font, style.size)
            self.y -= style.leading

        self.y -= style.gap_after

    def add_code(self, lines: list[str]) -> None:
        style = TextStyle("Courier", 8, 10, indent=14, gap_before=5, gap_after=7)
        max_chars = int((CONTENT_W - style.indent) / (style.size * 0.60))
        rendered: list[str] = []
        for raw in lines:
            if raw == "":
                rendered.append("")
                continue
            while len(raw) > max_chars:
                rendered.append(raw[:max_chars])
                raw = raw[max_chars:]
            rendered.append(raw)

        self._ensure(style.gap_before + len(rendered) * style.leading + style.gap_after)
        self.y -= style.gap_before
        for line in rendered:
            self._text(MARGIN_L + style.indent, self.y, line, style.font, style.size)
            self.y -= style.leading
        self.y -= style.gap_after

    def finish(self, path: Path) -> None:
        if self.page:
            self._footer()
            self.pages.append(self.page)
            self.page = []

        objects: list[bytes] = []

        def add_obj(data: str) -> int:
            objects.append(data.encode("latin-1", "replace"))
            return len(objects)

        font_regular = add_obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        font_bold = add_obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
        font_mono = add_obj("<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

        page_ids: list[int] = []
        content_ids: list[int] = []

        for page in self.pages:
            stream = "\n".join(page)
            content_ids.append(
                add_obj(f"<< /Length {len(stream.encode('latin-1', 'replace'))} >>\nstream\n{stream}\nendstream")
            )
            page_ids.append(0)

        pages_id_placeholder = len(objects) + len(self.pages) + 1

        for i, content_id in enumerate(content_ids):
            page_ids[i] = add_obj(
                "<< /Type /Page "
                f"/Parent {pages_id_placeholder} 0 R "
                f"/MediaBox [0 0 {PAGE_W:.0f} {PAGE_H:.0f}] "
                f"/Resources << /Font << /Helvetica {font_regular} 0 R "
                f"/Helvetica-Bold {font_bold} 0 R /Courier {font_mono} 0 R >> >> "
                f"/Contents {content_id} 0 R >>"
            )

        kids = " ".join(f"{pid} 0 R" for pid in page_ids)
        pages_id = add_obj(f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>")
        assert pages_id == pages_id_placeholder
        catalog_id = add_obj(f"<< /Type /Catalog /Pages {pages_id} 0 R >>")

        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as f:
            f.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
            offsets = [0]
            for idx, obj in enumerate(objects, start=1):
                offsets.append(f.tell())
                f.write(f"{idx} 0 obj\n".encode("ascii"))
                f.write(obj)
                f.write(b"\nendobj\n")

            xref = f.tell()
            f.write(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
            f.write(b"0000000000 65535 f \n")
            for off in offsets[1:]:
                f.write(f"{off:010d} 00000 n \n".encode("ascii"))
            f.write(
                f"trailer << /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
                f"startxref\n{xref}\n%%EOF\n".encode("ascii")
            )


def parse_markdown(md_path: Path, title: str, subtitle: str, pdf_path: Path) -> None:
    doc = PdfDoc(title=title, subtitle=subtitle)
    lines = md_path.read_text(encoding="utf-8").splitlines()
    in_code = False
    code_lines: list[str] = []

    for raw in lines:
        line = raw.rstrip()
        if line.startswith("```"):
            if in_code:
                doc.add_code(code_lines)
                code_lines = []
                in_code = False
            else:
                in_code = True
            continue

        if in_code:
            code_lines.append(line)
            continue

        if not line.strip():
            doc.add_text("", TextStyle("Helvetica", 10, 12))
            continue

        if line.startswith("# "):
            doc.add_text(line[2:], TextStyle("Helvetica-Bold", 20, 24, gap_before=8, gap_after=8))
        elif line.startswith("## "):
            doc.add_text(line[3:], TextStyle("Helvetica-Bold", 15, 19, gap_before=12, gap_after=5))
        elif line.startswith("### "):
            doc.add_text(line[4:], TextStyle("Helvetica-Bold", 12, 16, gap_before=8, gap_after=3))
        elif line.startswith("- "):
            doc.add_text("- " + line[2:], TextStyle("Helvetica", 10, 13, indent=14, gap_before=1))
        elif re.match(r"^\d+\. ", line):
            doc.add_text(line, TextStyle("Helvetica", 10, 13, indent=14, gap_before=1))
        else:
            doc.add_text(line, TextStyle("Helvetica", 10, 13, gap_before=1, gap_after=1))

    if code_lines:
        doc.add_code(code_lines)

    doc.finish(pdf_path)


def main() -> None:
    docs = [
        (
            DOCS / "ARCHITECTURE.md",
            "ArmOS Architecture Notes",
            "Kernel architecture and subsystem overview",
            OUT / "ArmOS_Architecture.pdf",
        ),
        (
            DOCS / "GET_STARTED_KERNEL_DEV.md",
            "Get Started - Kernel Dev ArmOS",
            "Kernel development guide",
            OUT / "Get_Started-Kernel_Dev_ArmOS.pdf",
        ),
        (
            DOCS / "GET_STARTED_USERLAND_DEV.md",
            "Get Started - Userland Dev ArmOS",
            "Userland and newlib development guide",
            OUT / "Get_Started-Userland_Dev_ArmOS.pdf",
        ),
    ]

    for md_path, title, subtitle, pdf_path in docs:
        parse_markdown(md_path, title, subtitle, pdf_path)
        size = os.path.getsize(pdf_path)
        print(f"generated {pdf_path.relative_to(ROOT)} ({size} bytes)")


if __name__ == "__main__":
    main()
