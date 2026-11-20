"""Acceptance tests for the B2B suite index (workspace/products/index.html).

Every card must point at a real live page and carry a checkout link that
actually exists on that product's own landing page/README. No invented links.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
INDEX = ROOT / "index.html"
BASE = "https://derbaroser-eng.github.io/"
STRIPE_RE = re.compile(r"https://buy\.stripe\.com/[A-Za-z0-9_-]+")

SOURCES = {
    "support-triage": "support-triage/index.html",
    "dunning": "dunning/index.html",
    "contract-extractor": "contract-extractor/index.html",
    "freelance-tracker": "freelance-tracker/index.html",
    "receipt-processor": "receipt-processor/index.html",
    "data-router": "data-router/index.html",
    "scope-detector": "scope-detector/index.html",
    "invoice-extractor": "invoice-extractor/index.html",
    "prospect-research": "prospect-research/index.html",
    "email-handler": "email-handler/index.html",
    "aurum-verify": "aurum-verify-starter/README.md",
    "shellguard": "shellguard-site/index.html",
    "null-tide": "itch-game/index.html",
}


def index_text():
    return INDEX.read_text(encoding="utf-8")


def cards():
    """Split on card openers; nested CTA anchors stay inside their card."""
    out = {}
    for chunk in index_text().split('<a class="card"')[1:]:
        m = re.search(r'href="([^"]+)"', chunk)
        if not m:
            continue
        url = m.group(1)
        slug = re.sub(r"^" + re.escape(BASE) + r"|\/$", "", url)
        out[slug] = STRIPE_RE.findall(chunk)
    return out


def source_links(slug):
    p = ROOT / SOURCES[slug]
    text = p.read_text(encoding="utf-8", errors="replace")
    return set(STRIPE_RE.findall(text))


def allowed_links(slug):
    """Landing-page links plus the suite's separately-created PWYW links.

    The suite index uses its own name-your-price prices; those are recorded in
    suite_checkout_manifest.json after a live HTTP 200 check.
    """
    import json
    manifest = json.loads((ROOT / "suite_checkout_manifest.json").read_text(encoding="utf-8"))
    entry = manifest["products"][slug]
    assert entry["http_status"] == 200, slug
    return source_links(slug) | set(entry["checkout_urls"])


class SuiteIndexTests(unittest.TestCase):
    def test_01_every_product_has_a_card(self):
        found = cards()
        for slug in SOURCES:
            with self.subTest(slug=slug):
                self.assertIn(BASE + slug + "/", index_text())

    def test_02_card_count_matches_product_count(self):
        self.assertEqual(len(cards()), len(SOURCES))

    def test_03_no_duplicate_cards(self):
        chunks = index_text().split('<a class="card"')[1:]
        urls = [re.search(r'href="([^"]+)"', c).group(1) for c in chunks
                if re.search(r'href="([^"]+)"', c)]
        self.assertEqual(len(urls), len(set(urls)))

    def test_04_every_card_has_a_real_checkout(self):
        found = cards()
        for slug, links in found.items():
            with self.subTest(slug=slug):
                self.assertTrue(links, "no buy.stripe.com link on card")
                self.assertTrue(set(links) & allowed_links(slug),
                                "card checkout is neither on landing page nor in verified manifest")

    def test_05_no_invented_checkout_links(self):
        real = set()
        for slug in SOURCES:
            real |= allowed_links(slug)
        for slug, links in cards().items():
            for link in links:
                with self.subTest(slug=slug, link=link):
                    self.assertIn(link, real)

    def test_06_all_hrefs_are_https(self):
        for href in re.findall(r'href="([^"]+)"', index_text()):
            with self.subTest(href=href):
                self.assertTrue(href.startswith("https://"), href)


if __name__ == "__main__":
    unittest.main(verbosity=2)
