"""Check SVG diagrams for text overflowing its box, using headless Chrome (real font metrics).

    python scripts/check_svg_overflow.py docs/images/how-it-works.svg [docs/whetstone-banner.svg]

For every <text>, finds the smallest <rect> that contains the text's anchor point and reports any
text whose bounding box extends beyond that rect (or beyond the SVG viewBox). Needs Google Chrome.
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
JS = """
<script>
const svg = document.querySelector('svg');
const vb = svg.viewBox.baseVal;
const rects = [...svg.querySelectorAll('rect')].map(r => ({x:+r.getAttribute('x')||0, y:+r.getAttribute('y')||0,
  w:+r.getAttribute('width'), h:+r.getAttribute('height')})).filter(r => r.w < vb.width - 5);
const out = [];
for (const t of svg.querySelectorAll('text')) {
  const b = t.getBBox();
  const cx = b.x + b.width/2, cy = b.y + b.height/2;
  const hosts = rects.filter(r => cx>=r.x && cx<=r.x+r.w && cy>=r.y && cy<=r.y+r.h).sort((a,b)=>a.w*a.h-b.w*b.h);
  const host = hosts[0];
  let problem = null;
  if (b.x < 0 || b.x + b.width > vb.width) problem = 'outside viewBox';
  else if (host && (b.x < host.x + 6 || b.x + b.width > host.x + host.w - 6)) problem = 'overflows box by ' +
     Math.round(Math.max(host.x + 6 - b.x, b.x + b.width - (host.x + host.w - 6)));
  out.push({text: t.textContent.slice(0,50), width: Math.round(b.width), problem});
}
document.getElementById('out').textContent = JSON.stringify(out);
</script>
"""

def check(path: str) -> int:
    svg = Path(path).read_text()
    html = f"<html><body style='margin:0'>{svg}<pre id='out'></pre>{JS}</body></html>"
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as f:
        f.write(html)
    dom = subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--virtual-time-budget=3000",
                          "--dump-dom", f"file://{f.name}"], capture_output=True, text=True, timeout=60).stdout
    m = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    if not m:
        print(f"{path}: could not read results from Chrome"); return 2
    rows = json.loads(m.group(1).replace("&quot;", '"').replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">"))
    bad = [r for r in rows if r["problem"]]
    print(f"{path}: {len(rows)} text elements, {len(bad)} with problems")
    for r in bad:
        print("   ", r["problem"], "|", r["text"], f"(width {r['width']})")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(max(check(p) for p in sys.argv[1:]))
