import asyncio
from pathlib import Path

import pytest


def test_pdf_export_has_basic_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import builtins
    from platform.exports.pdf.service import PdfExportService

    original_import = builtins.__import__

    def blocked_import(name: str, *args: object, **kwargs: object) -> object:
        if name.startswith("weasyprint") or name.startswith("playwright"):
            raise ImportError(name)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)

    output = tmp_path / "report.pdf"
    path = asyncio.run(
        PdfExportService().render_pdf(
            "<html><head><style>body{color:red}.card{padding:1rem}</style></head>"
            "<body><h1>Internal Report</h1><p>Evidence details</p><script>console.log('x')</script></body></html>",
            output,
            allow_basic_fallback=True,
        )
    )

    assert path == output
    content = output.read_bytes()
    assert content.startswith(b"%PDF-1.4")
    assert b"Internal Report" in content
    assert b"body{color:red}" not in content
    assert b"console.log" not in content


def test_pdf_export_default_requires_styled_renderer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import builtins
    from platform.exports.pdf.service import PdfExportService

    original_import = builtins.__import__

    def blocked_import(name: str, *args: object, **kwargs: object) -> object:
        if name.startswith("weasyprint") or name.startswith("playwright"):
            raise ImportError(name)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)

    with pytest.raises(RuntimeError, match="Styled PDF generation failed"):
        asyncio.run(PdfExportService().render_pdf("<h1>Internal Report</h1>", tmp_path / "report.pdf"))


def test_pdf_css_leak_detection(tmp_path: Path) -> None:
    from platform.webui.routes import _pdf_contains_css_leak

    leaky = tmp_path / "leaky.pdf"
    clean = tmp_path / "clean.pdf"
    leaky.write_bytes(b"%PDF-1.4\n(:root{color-scheme:light dark;body{margin:0}}) Tj")
    clean.write_bytes(b"%PDF-1.4\n(Internal Remediation Report) Tj")

    assert _pdf_contains_css_leak(leaky)
    assert not _pdf_contains_css_leak(clean)
