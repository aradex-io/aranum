"""wiki.py — load the repo's per-service quick-win wiki and render it to HTML.

The wiki lives in repo-root `wiki/<service>.md`. Each page has YAML-ish frontmatter
(`service:`, `title:`, `ports:`, `aliases:`) and a concise quick-wins body. The
dashboard renders each page to `wiki_<service>.html` and deep-links findings to it by
service category, so "redis found" → one click to the Redis quick-wins page.

Stdlib only. The markdown renderer is intentionally small — it handles exactly the
subset the wiki template uses (headings, fenced + inline code, bold, lists, blockquote,
links, paragraphs) and HTML-escapes all text.
"""
from __future__ import annotations

import html
import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
WIKI_DIR = _REPO_ROOT / "wiki"

_LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)\)")
_CODE_RE = re.compile(r"`([^`]+)`")
_BOLD_RE = re.compile(r"\*\*([^*]+)\*\*")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def parse_frontmatter(text: str) -> tuple[dict, str]:
    """Split `--- ... ---` frontmatter from the body. Returns (meta, body)."""
    meta: dict[str, str] = {}
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            block = text[3:end].strip()
            body = text[end + 4:].lstrip("\n")
            for line in block.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    meta[k.strip()] = v.strip()
            return meta, body
    return meta, text


def _inline(text: str) -> str:
    """Escape, then apply inline code/bold/link markup. Order matters: escape first
    (code/bold/link delimiters are not HTML-special), then substitute."""
    out = html.escape(text)
    out = _CODE_RE.sub(lambda m: f"<code>{m.group(1)}</code>", out)
    out = _BOLD_RE.sub(lambda m: f"<strong>{m.group(1)}</strong>", out)
    # links: text is already escaped; escape the href too (quote=True covers ").
    out = _LINK_RE.sub(
        lambda m: f'<a href="{html.escape(m.group(2), quote=True)}" '
                  f'rel="noopener noreferrer" target="_blank">{m.group(1)}</a>',
        out)
    return out


def md_to_html(body: str) -> str:
    """Render the wiki-template markdown subset to an HTML fragment."""
    lines = body.splitlines()
    out: list[str] = []
    i = 0
    in_list = False

    def close_list():
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    while i < len(lines):
        line = lines[i]
        # fenced code block
        if line.lstrip().startswith("```"):
            close_list()
            i += 1
            code: list[str] = []
            while i < len(lines) and not lines[i].lstrip().startswith("```"):
                code.append(html.escape(lines[i]))
                i += 1
            i += 1  # skip closing fence
            out.append('<pre class="wiki-code"><code>' + "\n".join(code) + "</code></pre>")
            continue
        # headings
        m = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            close_list()
            level = len(m.group(1))
            txt = m.group(2)
            out.append(f'<h{level} id="{_slug(txt)}">{_inline(txt)}</h{level}>')
            i += 1
            continue
        # blockquote
        if line.startswith(">"):
            close_list()
            out.append(f'<blockquote>{_inline(line[1:].strip())}</blockquote>')
            i += 1
            continue
        # list item
        if re.match(r"^\s*[-*]\s+", line):
            if not in_list:
                out.append("<ul>")
                in_list = True
            item = re.sub(r"^\s*[-*]\s+", "", line)
            out.append(f"<li>{_inline(item)}</li>")
            i += 1
            continue
        # blank line
        if not line.strip():
            close_list()
            i += 1
            continue
        # paragraph
        close_list()
        out.append(f"<p>{_inline(line)}</p>")
        i += 1
    close_list()
    return "\n".join(out)


def load_pages(wiki_dir: Path | None = None) -> dict[str, dict]:
    """Return {service_key: {title, ports, aliases:[...], html}} for every wiki/*.md
    page except TEMPLATE.md. service_key is the page's `service:` field (falls back to
    the filename stem). Aliases map alternate service names to the same page."""
    wiki_dir = wiki_dir or WIKI_DIR
    pages: dict[str, dict] = {}
    if not wiki_dir.is_dir():
        return pages
    for md in sorted(wiki_dir.glob("*.md")):
        if md.stem.upper() == "TEMPLATE":
            continue
        try:
            text = md.read_text(encoding="utf-8")
        except OSError:
            continue
        meta, body = parse_frontmatter(text)
        key = (meta.get("service") or md.stem).strip().lower()
        aliases = [a.strip().lower() for a in re.split(r"[,\s]+", meta.get("aliases", "")) if a.strip()]
        pages[key] = {
            "key": key,
            "title": meta.get("title") or key.title(),
            "ports": meta.get("ports", ""),
            "aliases": aliases,
            "html": md_to_html(body),
            "stem": md.stem,
        }
    return pages


def alias_map(pages: dict[str, dict]) -> dict[str, str]:
    """Map every service name + alias to its page key, for finding→page lookup."""
    m: dict[str, str] = {}
    for key, p in pages.items():
        m[key] = key
        for a in p["aliases"]:
            m.setdefault(a, key)
    return m


def page_filename(key: str) -> str:
    return f"wiki_{_slug(key)}.html"
