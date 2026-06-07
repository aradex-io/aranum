"""Tests for the quick-win wiki (wiki.py renderer + dashboard integration)."""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
NET = REPO / "aranumtoolkit" / "network"
PY = sys.executable


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(NET))
    spec.loader.exec_module(m)
    return m


WIKI = _load("wiki", NET / "wiki.py")


class TestWikiRenderer(unittest.TestCase):
    def test_all_pages_load_and_render(self):
        pages = WIKI.load_pages()
        self.assertGreaterEqual(len(pages), 30, "expected the full wiki set")
        for key, p in pages.items():
            self.assertTrue(p["title"], f"{key} missing title")
            self.assertIn("wiki-code", p["html"], f"{key} has no command blocks")
            self.assertGreater(len(p["html"]), 400, f"{key} suspiciously short")

    def test_html_is_escaped(self):
        html = WIKI.md_to_html("para `<?php system($_GET[x]);?>` and <script>alert(1)</script>")
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<?php", html)
        self.assertIn("&lt;?php", html)

    def test_markdown_elements(self):
        md = "# H1\n## H2\n\n- item\n\n```sh\nid\n```\n\n**bold** and [t](https://x.io)"
        html = WIKI.md_to_html(md)
        for tok in ("<h1", "<h2", "<ul>", "<li>", 'pre class="wiki-code"',
                    "<strong>bold</strong>", 'href="https://x.io"'):
            self.assertIn(tok, html)

    def test_frontmatter(self):
        meta, body = WIKI.parse_frontmatter(
            "---\nservice: redis\ntitle: Redis\naliases: redis-server\n---\n# body\n")
        self.assertEqual(meta["service"], "redis")
        self.assertEqual(meta["title"], "Redis")
        self.assertTrue(body.startswith("# body"))

    def test_aliases_bridge_toolkit_categories(self):
        # findings use short category names (elastic/mongo) and bulk services
        # (linenum/winenum); these must resolve to a page.
        pages = WIKI.load_pages()
        amap = WIKI.alias_map(pages)
        for cat in ("elastic", "mongo", "linenum", "winenum", "snmp", "redis", "smb"):
            self.assertIn(cat, amap, f"service '{cat}' has no wiki page/alias")

    def test_high_value_services_covered(self):
        amap = WIKI.alias_map(WIKI.load_pages())
        want = ["redis", "smb", "ldap", "ftp", "mysql", "postgres", "mssql", "mongo",
                "snmp", "smtp", "http", "ssh", "kerberos", "rdp", "winrm", "docker",
                "kubernetes", "nfs", "mqtt", "ipmi"]
        missing = [s for s in want if s not in amap]
        self.assertEqual(missing, [], f"missing wiki pages: {missing}")


class TestWikiDashboardIntegration(unittest.TestCase):
    def test_dashboard_emits_wiki_and_links_findings(self):
        with tempfile.TemporaryDirectory() as d:
            scan = Path(d) / "scan" / "redis" / "10.0.0.1"
            scan.mkdir(parents=True)
            (scan / "_hints.txt").write_text("[!] UNAUTH redis_version:7.0.15 role:master\n")
            out = Path(d) / "dash"
            r = subprocess.run(
                [PY, str(NET / "report-dashboard.py"), str(Path(d) / "scan"),
                 "--output", str(out)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue((out / "wiki.html").exists())
            self.assertTrue((out / "wiki_redis.html").exists())
            sd = out / "service_redis.html"
            self.assertTrue(sd.exists())
            self.assertIn('href="wiki_redis.html"', sd.read_text())


if __name__ == "__main__":
    unittest.main()
