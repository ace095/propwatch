"""Turn a markdown audit report into a client-ready PDF.

Pure Python (markdown + fpdf2), so it needs no browser or system libraries.

Usage:
    python pdf_export.py report.md report.pdf
"""
import argparse
import logging
import re
import sys

import markdown
from fpdf import FPDF
from fpdf.fonts import FontFace

log = logging.getLogger("webaudit.pdf")

# The built-in PDF fonts only cover Latin-1, so swap common typography for
# equivalents instead of crashing or printing "?".
_REPLACEMENTS = {
    "→": "->", "←": "<-", "—": "-", "–": "-", "−": "-",
    "‘": "'", "’": "'", "“": '"', "”": '"', "•": "-",
    "…": "...", "✅": "[ok]", "❌": "[x]", "⚠": "[!]",
    " ": " ", "→": "->",
}

ACCENT = (31, 78, 121)


def _latin1(text: str) -> str:
    for src, dst in _REPLACEMENTS.items():
        text = text.replace(src, dst)
    return text.encode("latin-1", "replace").decode("latin-1")


class _Report(FPDF):
    def __init__(self, title: str):
        super().__init__(format="A4")
        self.doc_title = title
        self.set_margins(18, 18, 18)
        self.set_auto_page_break(auto=True, margin=18)
        self.set_title(title)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", size=8)
        self.set_text_color(130, 130, 130)
        self.cell(0, 6, f"{self.doc_title}  |  Page {self.page_no()}/{{nb}}", align="C")


def _flatten_cells(html: str) -> str:
    """fpdf2 cannot nest tags such as <code> inside table cells; keep the text."""
    def strip(match):
        return re.sub(r"</?(code|em|strong|b|i|a)(\s[^>]*)?>", "", match.group(0))
    return re.sub(r"<t[dh]>.*?</t[dh]>", strip, html, flags=re.DOTALL)


def _title_of(md_text: str) -> str:
    match = re.search(r"^#\s+(.+)$", md_text, re.MULTILINE)
    return _latin1(match.group(1).strip()) if match else "Audit Report"


def markdown_to_pdf(md_text: str, out_path: str) -> str:
    """Render markdown to a PDF file and return the path."""
    title = _title_of(md_text)
    html = _flatten_cells(
        markdown.markdown(_latin1(md_text), extensions=["tables", "sane_lists", "nl2br"]))
    log.debug("rendering %d chars of markdown to %s", len(md_text), out_path)

    pdf = _Report(title)
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font("Helvetica", size=10)
    pdf.write_html(
        html,
        table_line_separators=True,
        tag_styles={
            "h1": FontFace(color=ACCENT, size_pt=20),
            "h2": FontFace(color=ACCENT, size_pt=14),
            "h3": FontFace(color=ACCENT, size_pt=11),
            "blockquote": FontFace(color=(90, 90, 90)),
        },
    )
    pdf.output(out_path)
    log.info("Wrote %s (%d pages)", out_path, pdf.page_no())
    return out_path


def main():
    ap = argparse.ArgumentParser(description="Convert a markdown report to PDF.")
    ap.add_argument("markdown_file")
    ap.add_argument("pdf_file")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s",
                        stream=sys.stderr)
    with open(args.markdown_file, encoding="utf-8") as f:
        markdown_to_pdf(f.read(), args.pdf_file)


if __name__ == "__main__":
    main()
