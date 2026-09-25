"""Generate five flat Hilait icon studies and a comparison sheet."""

from pathlib import Path
from html import escape

import cairosvg


OUT = Path(__file__).parent
CONCEPTS = [
    (
        "01-quiet-current",
        "Quiet Current",
        "Soft loop · mint on ink",
        """<rect width="256" height="256" rx="49" fill="#142B30"/>
<path d="M182 51 A94 94 0 1 0 214 166" fill="none" stroke="#98D6C1" stroke-width="18" stroke-linecap="round"/>
<path d="M113 87 L158 128 L113 169" fill="none" stroke="#98D6C1" stroke-width="26" stroke-linecap="round" stroke-linejoin="round"/>
<circle cx="200" cy="72" r="11" fill="#E9B88D"/>""",
    ),
    (
        "02-paper-signal",
        "Paper Signal",
        "Fine ring · clay accent",
        """<rect width="256" height="256" rx="49" fill="#F0EDE5"/>
<path d="M178 62 C148 43 113 42 83 57 C49 75 38 106 45 141 C53 184 89 209 129 207 C158 206 184 192 196 171" fill="none" stroke="#283940" stroke-width="14" stroke-linecap="round"/>
<path d="M93 87 L140 128 L93 169 L93 148 L117 128 L93 108 Z" fill="#283940"/>
<circle cx="194" cy="80" r="9" fill="#B86F52"/>""",
    ),
    (
        "03-cobalt-gate",
        "Cobalt Gate",
        "Open orbit · amber node",
        """<rect width="256" height="256" rx="49" fill="#273C63"/>
<path d="M169 48 C126 31 80 51 57 85 C34 119 42 166 71 194 C105 226 158 217 189 187" fill="none" stroke="#DCE8F3" stroke-width="16" stroke-linecap="round"/>
<path d="M88 89 L134 128 L88 167" fill="none" stroke="#DCE8F3" stroke-width="19" stroke-linecap="square" stroke-linejoin="miter"/>
<circle cx="194" cy="77" r="11" fill="#EBC17B"/>""",
    ),
    (
        "04-sage-circuit",
        "Sage Circuit",
        "Angular loop · warm dot",
        """<rect width="256" height="256" rx="49" fill="#DDE8DB"/>
<path d="M171 49 H97 L52 94 V162 L97 207 H161 L202 166" fill="none" stroke="#28534C" stroke-width="18" stroke-linecap="round" stroke-linejoin="round"/>
<path d="M94 92 L135 128 L94 164" fill="none" stroke="#28534C" stroke-width="18" stroke-linecap="round" stroke-linejoin="round"/>
<circle cx="190" cy="78" r="10" fill="#D57E64"/>""",
    ),
    (
        "05-carbon-mark",
        "Carbon Mark",
        "Bold cut · ivory and red",
        """<rect width="256" height="256" rx="49" fill="#262B2B"/>
<path d="M178 64 A82 82 0 1 0 190 183" fill="none" stroke="#EAE7DF" stroke-width="25" stroke-linecap="butt"/>
<path d="M91 86 L137 128 L91 170" fill="none" stroke="#EAE7DF" stroke-width="23" stroke-linecap="butt" stroke-linejoin="miter"/>
<circle cx="194" cy="76" r="10" fill="#D76558"/>""",
    ),
]


def svg(body: str) -> str:
    return f'<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256">{body}</svg>'


def main() -> None:
    for slug, _, _, body in CONCEPTS:
        (OUT / f"{slug}.svg").write_text(svg(body), encoding="utf-8")
        cairosvg.svg2png(bytestring=svg(body).encode(), write_to=str(OUT / f"{slug}.png"), output_width=512, output_height=512)

    cards = []
    for index, (slug, title, note, body) in enumerate(CONCEPTS):
        x = 30 + index * 304
        cards.append(f'''<g transform="translate({x} 91)">
<rect width="288" height="348" rx="18" fill="#FFFFFF" stroke="#D9DDDB"/>
<g transform="translate(34 17) scale(.86)">{body}</g>
<text x="22" y="271" class="title">{escape(title)}</text>
<text x="22" y="295" class="note">{escape(note)}</text>
<g transform="translate(222 275) scale(.15)">{body}</g>
<text x="22" y="327" class="num">{index + 1:02d}</text>
</g>''')
    sheet = f'''<svg xmlns="http://www.w3.org/2000/svg" width="1570" height="470" viewBox="0 0 1570 470">
<style>.heading{{font:600 25px Arial,sans-serif;fill:#27343A}}.sub{{font:14px Arial,sans-serif;fill:#647177}}.title{{font:600 18px Arial,sans-serif;fill:#27343A}}.note{{font:13px Arial,sans-serif;fill:#647177}}.num{{font:600 12px Arial,sans-serif;fill:#829094}}</style>
<rect width="1570" height="470" fill="#F3F5F3"/>
<text x="30" y="43" class="heading">Hilait — flat icon studies</text>
<text x="30" y="66" class="sub">Same loop · prompt · human node, five quieter treatments</text>
{''.join(cards)}
</svg>'''
    (OUT / "comparison.svg").write_text(sheet, encoding="utf-8")
    cairosvg.svg2png(bytestring=sheet.encode(), write_to=str(OUT / "comparison.png"), output_width=1570, output_height=470)


if __name__ == "__main__":
    main()
