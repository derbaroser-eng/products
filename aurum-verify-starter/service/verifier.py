"""The verification engine.

Design rule that makes this sellable: the model may *propose* a verdict, but
deterministic code decides whether the verdict survives.

    1. sources are fetched (or accepted pre-fetched) under an SSRF guard
    2. the free flagship model reads the claims plus the source excerpts
    3. every quote it cites is re-checked verbatim against the cited source
    4. a verdict whose quotes are not found is DROPPED to `unverifiable`
    5. a verdict with fewer verbatim sources than `minimum_sources` cannot be
       reported as supported
    6. stale sources (older than `freshness_hours`) cannot carry a verdict

So the worst case is a wasted call, never a confident fabrication with our name
on it. Layer 1-8 of the quality pipeline live here; nothing downstream has to
trust the model.
"""
from __future__ import annotations

import html
import ipaddress
import json
import re
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .models import (ClaimResult, Evidence, SourceInput, VerificationSummary,
                     Verdict, VerifyRequest, VerifyResponse)

MAX_BYTES = 2_000_000          # a source bigger than this is not a source
FETCH_TIMEOUT = 20
EXCERPT_CHARS = 12_000         # per source handed to the model
TOTAL_EXCERPT_CHARS = 60_000   # stays far inside the free 1M-token lane

SYSTEM_PROMPT = """You are an adversarial evidence checker. You never assert a \
verdict you cannot quote.

For each claim, decide one verdict from exactly: supported, contradicted, mixed, \
unverifiable.

Rules you must follow:
- Evidence is only what appears in the SOURCES given to you. Never use outside knowledge.
- Every item in `supporting` and `contradicting` must carry a `quote` copied \
CHARACTER-FOR-CHARACTER from the source you cite. A paraphrase is a failure.
- If the sources do not settle the claim, answer `unverifiable`. That is a good \
answer, not a failure.
- `confidence` is your own 0.0-1.0 estimate BEFORE any external check. Do not \
inflate it to be helpful.

Reply with JSON only, no prose, no code fences:

{"results":[{"claim":"<the claim, unchanged>","verdict":"<verdict>",\
"confidence":<0..1>,"reason":"<one sentence>",\
"supporting":[{"url":"<source url>","quote":"<verbatim>"}],\
"contradicting":[{"url":"<source url>","quote":"<verbatim>"}]}]}

Return exactly one result per claim, in the order given."""


class FetchError(Exception):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def normalise(text: str) -> str:
    """Whitespace- and case-insensitive comparison key for verbatim checking."""
    return re.sub(r"\s+", " ", html.unescape(text or "")).strip().casefold()


def strip_html(raw: str) -> str:
    raw = re.sub(r"(?is)<(script|style|noscript|svg)[^>]*>.*?</\1>", " ", raw)
    raw = re.sub(r"(?s)<!--.*?-->", " ", raw)
    text = re.sub(r"(?s)<[^>]+>", " ", raw)
    return re.sub(r"[ \t\r\f\v]+", " ", html.unescape(text)).strip()


def guard_url(url: str) -> str:
    """SSRF guard: public http(s) only. Raises FetchError on anything else.

    An endpoint that fetches caller-supplied URLs is an SSRF primitive unless it
    refuses loopback, private, link-local and multicast targets by IP — not by
    hostname string, which is trivially bypassed.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise FetchError(f"scheme {parsed.scheme!r} not allowed")
    host = parsed.hostname
    if not host:
        raise FetchError("missing host")
    if host.lower() in ("localhost", "localhost.localdomain"):
        raise FetchError("loopback host refused")
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise FetchError(f"cannot resolve host: {exc}") from exc
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified):
            raise FetchError(f"address {addr} refused (not public)")
    return url


class Fetcher:
    """Live source retrieval with a hard size cap and an SSRF guard."""

    def __init__(self, user_agent: str = "aurum-verify/0.1 (+evidence-fetch)"):
        self.user_agent = user_agent

    def fetch(self, url: str) -> Tuple[str, str]:
        """Return (text, content_type). Raises FetchError."""
        import httpx

        guard_url(url)
        headers = {"User-Agent": self.user_agent, "Accept": "text/html,text/plain,*/*"}
        try:
            with httpx.Client(timeout=FETCH_TIMEOUT, follow_redirects=True) as client:
                with client.stream("GET", url, headers=headers) as resp:
                    if resp.status_code != 200:
                        raise FetchError(f"HTTP {resp.status_code}")
                    ctype = resp.headers.get("content-type", "").lower()
                    chunks, size = [], 0
                    for chunk in resp.iter_bytes():
                        size += len(chunk)
                        if size > MAX_BYTES:
                            break
                        chunks.append(chunk)
        except FetchError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise FetchError(f"{type(exc).__name__}") from exc
        body = b"".join(chunks).decode("utf-8", errors="replace")
        if "html" in ctype or "<html" in body[:2000].lower():
            body = strip_html(body)
        return body, ctype


def _age_hours(published_at: Optional[str]) -> Optional[float]:
    if not published_at:
        return None
    raw = published_at.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return round((_now() - dt).total_seconds() / 3600.0, 2)


class VerifyEngine:
    def __init__(self, model, fetcher: Optional[Fetcher] = None):
        self.model = model
        self.fetcher = fetcher or Fetcher()

    # -- source gathering ----------------------------------------------------
    def gather(self, sources: List[SourceInput]) -> Tuple[Dict[str, str], List[str], Dict[str, Dict[str, Any]]]:
        texts: Dict[str, str] = {}
        notes: List[str] = []
        meta: Dict[str, Dict[str, Any]] = {}
        for src in sources:
            age = _age_hours(src.published_at)
            entry = {"age_hours": age, "retrieval": "provided", "ok": True, "stale": False}
            if src.text is not None:
                texts[src.url] = src.text
            else:
                try:
                    text, _ = self.fetcher.fetch(src.url)
                    texts[src.url] = text
                    entry["retrieval"] = "fetched"
                except FetchError as exc:
                    entry["ok"] = False
                    entry["error"] = str(exc)
                    notes.append(f"{src.url}: {exc}")
            meta[src.url] = entry
        return texts, notes, meta

    # -- prompt --------------------------------------------------------------
    def build_user_prompt(self, claims: List[str], texts: Dict[str, str]) -> str:
        budget = TOTAL_EXCERPT_CHARS
        blocks, used = [], 0
        for url, text in texts.items():
            excerpt = text[:EXCERPT_CHARS]
            if used + len(excerpt) > budget:
                excerpt = excerpt[: max(0, budget - used)]
            used += len(excerpt)
            if excerpt:
                blocks.append(f"SOURCE: {url}\n---\n{excerpt}\n---")
            if used >= budget:
                break
        listing = "\n".join(f"{i + 1}. {c}" for i, c in enumerate(claims))
        return (f"CLAIMS TO CHECK:\n{listing}\n\n"
                f"SOURCES ({len(blocks)}):\n" + "\n\n".join(blocks))

    # -- deterministic gate --------------------------------------------------
    def _verify_quote(self, url: str, quote: str, texts: Dict[str, str]) -> bool:
        haystack = texts.get(url)
        if haystack is None:
            return False
        needle = normalise(quote)
        if len(needle) < 12:          # a two-word "quote" proves nothing
            return False
        return needle in normalise(haystack)

    def _evidence(self, items: Any, texts: Dict[str, str], meta: Dict[str, Dict[str, Any]],
                  freshness_hours: Optional[int], require_verbatim: bool) -> List[Evidence]:
        out: List[Evidence] = []
        for item in items or []:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", "")).strip()
            quote = str(item.get("quote", "")).strip()
            if not url or not quote:
                continue
            verbatim = self._verify_quote(url, quote, texts)
            info = meta.get(url, {})
            age = info.get("age_hours")
            stale = bool(freshness_hours and age is not None and age > freshness_hours)
            if require_verbatim and not verbatim:
                # Keep it in the payload, visibly rejected, so the caller can see
                # exactly what the model tried to pass off.
                out.append(Evidence(url=url, quote=quote[:400], quote_verbatim=False,
                                    fetched_at=info.get("fetched_at"), age_hours=age,
                                    stale=stale, retrieval=info.get("retrieval", "provided")))
                continue
            out.append(Evidence(url=url, quote=quote[:400], quote_verbatim=verbatim,
                                fetched_at=info.get("fetched_at"), age_hours=age,
                                stale=stale, retrieval=info.get("retrieval", "provided")))
        return out

    def decide(self, verdict: str, supporting: List[Evidence], contradicting: List[Evidence],
               minimum_sources: int) -> Tuple[Verdict, bool, Optional[str]]:
        """Return (verdict, downgraded, reason). Deterministic — no model input."""
        good_sup = [e for e in supporting if e.quote_verbatim and not e.stale]
        good_con = [e for e in contradicting if e.quote_verbatim and not e.stale]
        sup_urls = {e.url for e in good_sup}
        con_urls = {e.url for e in good_con}

        if verdict == Verdict.CONTRADICTED.value or (good_con and not good_sup):
            return Verdict.CONTRADICTED, False, "verbatim source contradicts the claim"
        if good_sup and good_con:
            return Verdict.MIXED, False, "sources disagree on this claim"
        if good_sup:
            if len(sup_urls) < max(1, minimum_sources):
                return (Verdict.UNVERIFIABLE, True,
                        f"only {len(sup_urls)} verbatim source(s); "
                        f"minimum_sources={minimum_sources}")
            return Verdict.SUPPORTED, False, "verbatim source supports the claim"
        missing = [e for e in supporting + contradicting if not e.quote_verbatim]
        if missing:
            return (Verdict.UNVERIFIABLE, True,
                    "every cited quote failed the verbatim check")
        return Verdict.UNVERIFIABLE, True, "no quotable evidence was found"

    # -- top level -----------------------------------------------------------
    def run(self, req: VerifyRequest) -> Tuple[List[ClaimResult], VerificationSummary, str]:
        texts, notes, meta = self.gather(req.sources)
        if not texts:
            results = [ClaimResult(
                claim=c, verdict=Verdict.UNVERIFIABLE, confidence=0.0,
                downgraded=True,
                reason=("no usable source: " + ("; ".join(notes) if notes
                                                else "the request carried no sources")))
                for c in req.claims]
            summary = VerificationSummary(
                claims_total=len(req.claims), supported=0, contradicted=0, mixed=0,
                unverifiable=len(req.claims), sources_checked=len(req.sources),
                quotes_checked=0, quotes_verbatim=0, quotes_rejected=0)
            return results, summary, self.model.model

        payload = self.model.complete_json(SYSTEM_PROMPT,
                                          self.build_user_prompt(req.claims, texts))
        raw_results = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(raw_results, list):
            raw_results = []
        by_claim = {}
        for item in raw_results:
            if isinstance(item, dict) and item.get("claim"):
                by_claim.setdefault(str(item["claim"]).strip(), item)

        results: List[ClaimResult] = []
        quotes_checked = quotes_verbatim = quotes_rejected = 0
        for claim in req.claims:
            item = by_claim.get(claim.strip(), {})
            supporting = self._evidence(item.get("supporting"), texts, meta,
                                        req.freshness_hours, req.require_verbatim_quotes)
            contradicting = self._evidence(item.get("contradicting"), texts, meta,
                                           req.freshness_hours, req.require_verbatim_quotes)
            for e in supporting + contradicting:
                quotes_checked += 1
                if e.quote_verbatim:
                    quotes_verbatim += 1
                else:
                    quotes_rejected += 1
            verdict, downgraded, reason = self.decide(
                str(item.get("verdict", "unverifiable")).lower(),
                supporting, contradicting, req.minimum_sources)
            try:
                confidence = max(0.0, min(1.0, float(item.get("confidence", 0.0))))
            except (TypeError, ValueError):
                confidence = 0.0
            if downgraded:
                confidence = min(confidence, 0.35)
            elif verdict == Verdict.SUPPORTED:
                confidence = min(confidence, 0.95)
            results.append(ClaimResult(
                claim=claim, verdict=verdict, confidence=round(confidence, 3),
                evidence=supporting, contradictions=contradicting,
                downgraded=downgraded,
                reason=reason or item.get("reason")))
        summary = VerificationSummary(
            claims_total=len(req.claims),
            supported=sum(1 for r in results if r.verdict == Verdict.SUPPORTED),
            contradicted=sum(1 for r in results if r.verdict == Verdict.CONTRADICTED),
            mixed=sum(1 for r in results if r.verdict == Verdict.MIXED),
            unverifiable=sum(1 for r in results if r.verdict == Verdict.UNVERIFIABLE),
            sources_checked=len(req.sources),
            quotes_checked=quotes_checked, quotes_verbatim=quotes_verbatim,
            quotes_rejected=quotes_rejected)
        return results, summary, self.model.model
