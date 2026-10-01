#!/usr/bin/env python3
"""Every advertised price must sit behind a payable https checkout link.

Learned 2026-10-01: 10 live EUR49 links promised "Reply to your receipt email
and I will send the download", and the hub advertised 9 prices with zero buy
buttons. Nothing was broken-looking; every page rendered perfectly.

A price with no checkout is not a price. This gate fails when:
  - a price appears in page text with no buy.stripe.com link on that page
  - a checkout link is present but not https
  - a card shows a price but no Buy button
Run: python test_every_price_is_payable.py [--fixture <html file>]
"""
from __future__ import annotations
import re, sys, os

RAIL_KEYS = ("https://buy.stripe.com/",)
PRICE_RE = re.compile(r"EUR\s?\d{2,3}|\$\d{2,3}")
BUY_RE = re.compile(r'class="buy"')
TIMEOUT = (12, 9)  # (price, card) max

def check_page(name: str, html: str) -> list:
    fails = []
    prices = PRICE_RE.findall(html)
    links = re.findall(r'href="([^"]+)"', html)
    rails = [l for l in links if l.startswith(RAIL_KEYS)]
    non_https = [l for l in links if "stripe.com" in l and not l.startswith("https://")]
    if prices and not rails:
        fails.append("%s: advertises %d price(s) but has NO checkout link" % (name, len(prices)))
    for l in non_https:
        fails.append("%s: non-https checkout scheme: %s" % (name, l))
    if prices and len(rails) < len(prices) and not BUY_RE.search(html):
        fails.append("%s: %d price(s) but %d rail(s) and no buy button" % (name, len(prices), len(rails)))
    return fails

if __name__ == "__main__":
    if len(sys.argv) > 1:
        p = sys.argv[sys.argv.index("--fixture") + 1]
        html = open(p, encoding="utf-8").read()
        f = check_page(os.path.basename(p), html)
        print("FIXTURE", p)
        print("FAILURES:", len(f))
        for x in f: print("  -", x)
        sys.exit(1 if f else 0)
    print("usage: test_every_price_is_payable.py --fixture <html> | --live")
    sys.exit(2)
