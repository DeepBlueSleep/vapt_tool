from __future__ import annotations

import html.parser
import re
from pathlib import Path
from textwrap import wrap


class PdfExportService:
    async def render_pdf(self, html: str, output_path: Path, *, allow_basic_fallback: bool = False) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        renderer_errors: list[str] = []
        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch()
                page = await browser.new_page()
                await page.set_content(html, wait_until="networkidle")
                await page.pdf(
                    path=str(output_path),
                    format="A4",
                    print_background=True,
                    prefer_css_page_size=True,
                    display_header_footer=True,
                    footer_template=(
                        "<span style='font-size:9px;margin:0 auto;color:#667085'>"
                        "Page <span class='pageNumber'></span> of <span class='totalPages'></span></span>"
                    ),
                    header_template="<span></span>",
                )
                await browser.close()
                return output_path
        except Exception as exc:
            renderer_errors.append(f"playwright: {type(exc).__name__}: {exc!s}")
        try:
            from weasyprint import HTML

            HTML(string=html).write_pdf(output_path)
            return output_path
        except Exception as exc:
            renderer_errors.append(f"weasyprint: {type(exc).__name__}: {exc!s}")
        if not allow_basic_fallback:
            raise RuntimeError(
                "Styled PDF generation failed. Install Playwright Chromium with "
                "`python -m playwright install chromium` or install WeasyPrint native dependencies. "
                + " | ".join(renderer_errors)
            )
        try:
            fallback = output_path.with_suffix(".html")
            fallback.write_text(html, encoding="utf-8")
            _write_basic_pdf(_html_to_text(html), output_path)
            if output_path.exists() and output_path.stat().st_size > 0:
                return output_path
            raise RuntimeError(f"PDF dependencies are unavailable; wrote HTML fallback to {fallback}")
        except Exception as exc:
            raise RuntimeError("PDF generation failed") from exc


class _TextExtractor(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"style", "script", "head", "noscript", "svg"}:
            self._ignored_depth += 1
            return
        if tag in {"h1", "h2", "h3", "p", "li", "tr", "section", "details"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"style", "script", "head", "noscript", "svg"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._ignored_depth:
            return
        value = " ".join(data.split())
        if value:
            self.parts.append(value)


def _html_to_text(value: str) -> str:
    parser = _TextExtractor()
    parser.feed(value)
    text = " ".join(parser.parts)
    text = re.sub(r"\s*\n\s*", "\n", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    return text.strip() or "Security assessment report"


def _write_basic_pdf(text: str, output_path: Path) -> None:
    lines: list[str] = []
    for raw_line in text.splitlines():
        lines.extend(wrap(raw_line, width=92) or [""])
    pages = [lines[index : index + 48] for index in range(0, len(lines), 48)] or [["Security assessment report"]]

    objects: list[bytes] = [b"<< /Type /Catalog /Pages 2 0 R >>"]
    page_kids = " ".join(f"{3 + index * 2} 0 R" for index in range(len(pages)))
    objects.append(f"<< /Type /Pages /Kids [{page_kids}] /Count {len(pages)} >>".encode("ascii"))

    for index, page_lines in enumerate(pages):
        page_obj = 3 + index * 2
        content_obj = page_obj + 1
        stream = _page_stream(page_lines, index + 1, len(pages))
        page_definition = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> "
            f"/Contents {content_obj} 0 R >>"
        )
        objects.append(
            page_definition.encode("ascii")
        )
        objects.append(b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream")

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for obj_number, payload in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{obj_number} 0 obj\n".encode("ascii"))
        output.extend(payload)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii"))
    output_path.write_bytes(bytes(output))


def _page_stream(lines: list[str], page_number: int, total_pages: int) -> bytes:
    commands = ["BT", "/F1 11 Tf", "50 742 Td", "14 TL"]
    for line in lines:
        commands.append(f"({_pdf_escape(line)}) Tj")
        commands.append("T*")
    commands.extend(["/F1 9 Tf", "0 -16 Td", f"(Page {page_number} of {total_pages}) Tj", "ET"])
    return "\n".join(commands).encode("latin-1", "replace")


def _pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
