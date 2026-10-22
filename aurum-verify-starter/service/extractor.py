"""Deterministic content extraction.

The higher-demand sibling of claim verification: turn one URL into clean,
machine-readable content an agent can actually use — title, byline, excerpt,
word count, and a markdown body — with no model in the loop and no surprises.

Design rule that makes this sellable: extraction is *deterministic*. The same URL
yields the same markdown. Nothing here guesses, and nothing here invents text that
was not on the page. Where the page hides text from a reader (comments,
`display:none`, white-on-white, zero-width characters) the extractor reports that
separately rather than silently folding it into the body.
"""
from __future__ import annotations

import html
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from .verifier import Fetcher, FetchError, guard_url, strip_html

MAX_BYTES = 2_000_000
MAX_BODY_CHARS = 200_000

# Boilerplate containers: navigation, footers, sidebars, cookie walls. Dropped
# before the main-content heuristic runs so the heuristic is not fooled by a nav
# bar full of short links.
_BOILERPLATE = ("nav", "footer", "header", "aside", "form", "noscript", "svg",
                "iframe", "template")

_META_RE = re.compile(
    r"""<meta\s+[^>]*?(?:name|property)\s*=\s*["']([^"']+)["'][^>]*?
        content\s*=\s*["']([^"']*)["']""",
    re.I | re.S | re.X)
_TITLE_RE = re.compile(r"(?is)<title[^>]*>(.*?)</title>")
_H1_RE = re.compile(r"(?is)<h1[^>]*>(.*?)</h1>")
_ARTICLE_RE = re.compile(r"(?is)<article[^>]*>(.*?)</article>")
_MAIN_RE = re.compile(r"(?is)<main[^>]*>(.*?)</main>")
_ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")
# A byline written as ordinary prose: "By Jane Doe." / "By Jane Doe and John Roe".
# Only capitalized words, no periods, so "Doe." is never swallowed and the match
# stops at the sentence end. Only matched at the start of a line.
_BYLINE_RE = re.compile(
    r"(?im)^\s*By\s+([A-Z][a-z'-]+(?:\s+(?:[A-Z][a-z'-]+|and|&)){0,3})")
_HIDDEN_RE = re.compile(
    r"(?is)<(?:div|span|p)[^>]*style\s*=\s*[\"'][^\"']*"
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*#fff(?:fff)?"
    r"|font-size\s*:\s*0)[^\"']*[\"'][^>]*>(.*?)</(?:div|span|p)>")
_COMMENT_RE = re.compile(r"(?s)<!--(.*?)-->")
_INSTRUCTION_RE = re.compile(
    r"(?i)\b(ignore|disregard|forget)\b[^.\n]{0,60}\b(previous|prior|above|all)\b"
    r"[^.\n]{0,60}\b(instruction|prompt|rule|direction)s?\b"
    r"|\byou\s+are\s+now\b|\bsystem\s*:\s*"
    r"|\bas\s+an\s+ai\b[^.\n]{0,60}\b(you\s+must|please)\b")


class ExtractError(Exception):
    pass


def _meta_map(raw: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, value in _META_RE.findall(raw):
        k = key.strip().lower()
        if k and k not in out:
            out[k] = html.unescape(value).strip()
    return out


def _first(regex, raw: str) -> Optional[str]:
    m = regex.search(raw)
    return m.group(1) if m else None


def _text_len(fragment: str) -> int:
    return len(strip_html(fragment))


def _pick_main(raw: str) -> str:
    """Choose the densest candidate container, deterministically.

    Order: <article> (longest) > <main> > <body>-minus-boilerplate. Ties always
    resolve to the earlier candidate, so the same page always yields the same
    pick.
    """
    articles = [a for a in _ARTICLE_RE.findall(raw) if _text_len(a) >= 400]
    if articles:
        return max(articles, key=_text_len)
    main = [m for m in _MAIN_RE.findall(raw) if _text_len(m) >= 400]
    if main:
        return max(main, key=_text_len)
    body = _first(re.compile(r"(?is)<body[^>]*>(.*?)</body>"), raw) or raw
    for tag in _BOILERPLATE:
        body = re.sub(rf"(?is)<{tag}\b[^>]*>.*?</{tag}>", " ", body)
    return body


def _inline_markdown(fragment: str) -> str:
    """HTML inline markup -> markdown, then strip whatever remains."""
    frag = _ZERO_WIDTH_RE.sub("", fragment)
    frag = re.sub(r"(?is)<a\b[^>]*href\s*=\s*[\"']([^\"']*)[\"'][^>]*>(.*?)</a>",
                  lambda m: f"[{strip_html(m.group(2))}]({m.group(1).strip()})"
                  if m.group(1).strip().startswith(("http", "/")) else strip_html(m.group(2)),
                  frag)
    frag = re.sub(r"(?is)<(?:strong|b)\b[^>]*>(.*?)</(?:strong|b)>", r"**\1**", frag)
    frag = re.sub(r"(?is)<(?:em|i)\b[^>]*>(.*?)</(?:em|i)>", r"*\1*", frag)
    frag = re.sub(r"(?is)<code\b[^>]*>(.*?)</code>", r"`\1`", frag)
    frag = re.sub(r"(?is)<br\s*/?>", "\n", frag)
    return strip_html(frag)


def to_markdown(fragment: str) -> str:
    """Block-level HTML -> markdown. Deterministic, no guessing."""
    frag = re.sub(r"(?is)<(script|style|noscript|svg|template)\b[^>]*>.*?</\1>", " ", fragment)

    def block(tag: str, level: int) -> None:
        nonlocal frag
        pattern = re.compile(rf"(?is)<{tag}\b[^>]*>(.*?)</{tag}>")
        frag = pattern.sub(lambda m: f"\n\n{'#' * level} {_inline_markdown(m.group(1)).strip()}\n\n", frag)

    for i in range(1, 7):
        block(f"h{i}", i)

    def li(m):
        return "\n- " + _inline_markdown(m.group(1)).strip()

    frag = re.sub(r"(?is)<li\b[^>]*>(.*?)</li>", li, frag)
    frag = re.sub(r"(?is)<blockquote\b[^>]*>(.*?)</blockquote>",
                  lambda m: "\n\n> " + _inline_markdown(m.group(1)).strip() + "\n\n", frag)
    frag = re.sub(r"(?is)<pre\b[^>]*>(.*?)</pre>",
                  lambda m: "\n\n```\n" + strip_html(m.group(1)).strip() + "\n```\n\n", frag)
    frag = re.sub(r"(?is)<(?:p|div|section)\b[^>]*>(.*?)</(?:p|div|section)>",
                  lambda m: "\n\n" + _inline_markdown(m.group(1)).strip() + "\n\n", frag)
    frag = _inline_markdown(frag)
    frag = re.sub(r"[ \t]+", " ", frag)
    frag = re.sub(r"\n{3,}", "\n\n", frag)
    return frag.strip()


def _hidden_signals(raw: str) -> Tuple[List[str], bool]:
    """Text the page hides from a reader, plus whether any of it reads as an
    instruction aimed at an AI. Reported, never executed."""
    findings: List[str] = []
    for m in _HIDDEN_RE.finditer(raw):
        t = strip_html(m.group(1)).strip()
        if len(t) >= 12:
            findings.append(t[:300])
    for m in _COMMENT_RE.finditer(raw):
        t = strip_html(m.group(1)).strip()
        if len(t) >= 12:
            findings.append(t[:300])
    for t in _ZERO_WIDTH_RE.findall(raw):
        findings.append("[zero-width character present]")
        break
    joined = "\n".join(findings)
    suspicious = bool(findings) and bool(_INSTRUCTION_RE.search(joined))
    return findings[:10], suspicious


def extract(url: str, fetcher: Optional[Fetcher] = None,
            max_chars: int = MAX_BODY_CHARS) -> Dict[str, Any]:
    """Fetch one URL and return deterministic, machine-readable content.

    Raises ExtractError for anything the SSRF guard or the fetcher refuses; the
    caller maps that to a 4xx and never bills. Every refusal — guard or fetch — is
    ExtractError, because the caller cannot tell them apart and must not bill.
    """
    try:
        guard_url(url)
    except FetchError as exc:
        raise ExtractError(str(exc)) from exc
    fetcher = fetcher or Fetcher(user_agent="aurum-extract/0.1 (+content-fetch)")
    try:
        raw, ctype = fetcher.fetch(url)
    except FetchError as exc:
        raise ExtractError(str(exc)) from exc

    is_html = "html" in (ctype or "").lower() or "<html" in raw[:2000].lower()
    if not is_html:
        text = raw[:max_chars].strip()
        return {
            "url": url,
            "content_type": ctype or "text/plain",
            "title": None, "byline": None, "excerpt": None,
            "word_count": len(text.split()),
            "markdown": text,
            "truncated": len(raw) > max_chars,
            "hidden_content": [], "hidden_instruction_signal": False,
            "untrustedContent": True,
        }

    meta = _meta_map(raw)
    title = (meta.get("og:title") or meta.get("twitter:title")
             or (_first(_TITLE_RE, raw) or "").strip() or None)
    if title:
        title = strip_html(title)
    byline = (meta.get("author") or meta.get("article:author")
              or meta.get("byl") or None)
    excerpt = (meta.get("og:description") or meta.get("description")
               or meta.get("twitter:description") or None)
    if not title:
        h1 = _first(_H1_RE, raw)
        title = strip_html(h1).strip() if h1 else None

    main = _pick_main(raw)
    markdown = to_markdown(main)
    if len(markdown) < 200:
        # The main-content heuristic can miss a page whose article sits outside
        # <article>/<main>. Fall back to the whole body, still boilerplate-free.
        body = _first(re.compile(r"(?is)<body[^>]*>(.*?)</body>"), raw) or raw
        for tag in _BOILERPLATE:
            body = re.sub(rf"(?is)<{tag}\b[^>]*>.*?</{tag}>", " ", body)
        fallback = to_markdown(body)
        if len(fallback) > len(markdown):
            markdown = fallback
    if not byline:
        # No meta tag: look for a byline written as prose ("By Jane Doe."), only
        # at the start of a line so a body sentence naming a person is not mistaken
        # for the author. Runs after the markdown is built — the prose form only
        # exists once the block markup has been flattened.
        m = _BYLINE_RE.search(markdown)
        byline = m.group(1).strip() if m else None

    truncated = len(markdown) > max_chars
    markdown = markdown[:max_chars]
    hidden, suspicious = _hidden_signals(raw)

    return {
        "url": url,
        "content_type": ctype or "text/html",
        "title": title,
        "byline": byline,
        "excerpt": (excerpt[:500] if excerpt else None),
        "word_count": len(markdown.split()),
        "markdown": markdown,
        "truncated": truncated,
        "hidden_content": hidden,
        "hidden_instruction_signal": suspicious,
        "untrustedContent": True,
    }
