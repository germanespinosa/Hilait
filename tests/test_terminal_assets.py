from pathlib import Path

STATIC = Path(__file__).resolve().parents[1] / "src" / "hilait" / "static"


def test_strict_csp_keeps_xterm_styles_through_constructable_sheets():
    """xterm.js injects <style> elements that style-src 'self' blocks.

    Without them glyphs drift from the cell grid (offset caret) and selections are
    invisible, so the bundled terminal must mirror them into adopted stylesheets.
    """
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert "style-src 'self'" in html and "unsafe-inline" not in html
    source = (STATIC / "terminal-entry.js").read_text(encoding="utf-8")
    assert "mirrorInjectedStyles(element)" in source
    bundle = (STATIC / "vendor" / "xterm.js").read_text(encoding="utf-8")
    assert "adoptedStyleSheets" in bundle, "Rebuild the terminal bundle with `npm run build`."
