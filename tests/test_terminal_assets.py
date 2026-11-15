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
    # Truecolor/contrast colours must use CSSOM, not blocked style attributes.
    assert 'setAttribute("style"' not in bundle, "Rebuild with build.mjs's csp-safe-xterm patch."


def test_responsive_shell_and_bundled_fonts():
    for page in ("index.html", "approve.html"):
        html = (STATIC / page).read_text(encoding="utf-8")
        assert "viewport-fit=cover" in html, page
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    assert "min-width: 740px" not in css  # the workspace must not force sideways scrolling on phones
    assert '[data-view="session"]' in css and '[data-view="list"]' in css
    theme = (STATIC / "theme.css").read_text(encoding="utf-8")
    for font in ("inter-latin-wght-normal.woff2", "inter-latin-ext-wght-normal.woff2"):
        assert font in theme and (STATIC / "fonts" / font).is_file()
    assert "--line-strong" in theme and "font-size: 16px" in css  # control contrast; no iOS focus zoom
