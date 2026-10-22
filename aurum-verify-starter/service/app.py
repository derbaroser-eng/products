"""HTTP surface.

One paid endpoint, plus free discovery and liveness endpoints. Nothing else, on
purpose: Stage 1 of the product sequence is "one extremely useful endpoint", and
a second paid endpoint before the first has a settled payment is scope creep.

Routes:
    GET  /health            liveness + which lane is serving
    GET  /v1/pricing        machine-readable price, asset, network, payTo
    GET  /openapi.json      the full contract, for code generation
    POST /v1/verify/claims  the one paid endpoint (HTTP 402 gate)
    GET  /internal/revenue  admin-token gated; 404 to anyone without the token
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import uuid
from typing import Any, Dict, Optional

from fastapi import FastAPI, Header, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from . import __version__
from .extractor import ExtractError, extract
from .ledger import RevenueLedger
from .models import (ExtractRequest, ExtractResponse, ExtractedArticle,
                     HealthResponse, VerifyRequest, VerifyResponse)
from .nous import FREE_FLAGSHIP, NousClient, UpstreamError
from .payments import PaymentError, PaymentGate, encode_header
from .verifier import VerifyEngine

DEFAULT_STATE_DIR = ".state"
STOP_FILE = os.path.join(DEFAULT_STATE_DIR, "STOP")  # §22: svc-watch honors this — paid routes refuse while it exists
DEFAULT_LEDGER_PATH = os.path.join(
    os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes")),
    "workspace", "business", "ledger.jsonl")
PRODUCTION_NETWORKS = ("base", "ethereum", "solana", "polygon")

RESOURCE = "/v1/verify/claims"
EXTRACT_RESOURCE = "/v1/extract"
PAID_RESOURCES = (RESOURCE, EXTRACT_RESOURCE)
def _ops_dir() -> str:
    # Resolved per call so the test suite (VERIFY_STATE_DIR=tmp_path) never
    # pollutes the production ops stream.
    return os.environ.get("VERIFY_STATE_DIR", DEFAULT_STATE_DIR)


def ops(event: str, **fields: Any) -> None:
    """Append one raw operational log line. Logging must never break a request,
    and must never record credentials, signatures, tokens or keys."""
    try:
        path = os.path.join(_ops_dir(), "ops.log")
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        line = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "event": event}
        line.update(fields)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, separators=(",", ":")) + "\n")
    except OSError:
        pass


class Idempotency:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._lock = threading.Lock()
        with sqlite3.connect(self.path, timeout=10) as con:
            con.execute("CREATE TABLE IF NOT EXISTS idem (key TEXT PRIMARY KEY, "
                        "stored_at REAL NOT NULL, payload TEXT NOT NULL, status INT NOT NULL, "
                        "fingerprint TEXT NOT NULL DEFAULT '')")

    def get(self, key: str):
        with sqlite3.connect(self.path, timeout=10) as con:
            row = con.execute(
                "SELECT payload, status, fingerprint FROM idem WHERE key = ?", (key,)).fetchone()
        return (json.loads(row[0]), int(row[1]), row[2]) if row else None

    def put(self, key: str, payload: Dict[str, Any], status: int, fingerprint: str) -> None:
        with self._lock, sqlite3.connect(self.path, timeout=10) as con:
            con.execute("INSERT OR REPLACE INTO idem "
                        "(key, stored_at, payload, status, fingerprint) VALUES (?,?,?,?,?)",
                        (key, time.time(), json.dumps(payload), status, fingerprint))
            con.execute("DELETE FROM idem WHERE stored_at < ?", (time.time() - 7 * 86400,))


def fingerprint_of(payload: VerifyRequest) -> str:
    """Identity of the *question*, excluding the key itself.

    A replay is free only when it asks the same question. Otherwise an agent (or
    an attacker who guessed a key) could buy one answer and read every other.
    """
    import hashlib

    data = payload.model_dump(mode="json")
    data.pop("idempotency_key", None)
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def ledger_mode(gate: PaymentGate) -> str:
    if gate.mode == "test":
        return "simulation"
    return "testnet" if gate.network not in PRODUCTION_NETWORKS else "production"


def create_app(model=None, gate: Optional[PaymentGate] = None,
               fetcher=None, ledger: Optional[RevenueLedger] = None,
               state_dir: Optional[str] = None) -> FastAPI:
    # Resolved per call, not at import. A state dir frozen into a module constant
    # cannot be overridden by a caller, so the test suite shared one on-disk
    # idempotency store with the dev server: a key persisted by an earlier run
    # made the second run return a stale 200 where a 402 belonged.
    state_dir = state_dir or os.environ.get("VERIFY_STATE_DIR", DEFAULT_STATE_DIR)
    gate = gate or PaymentGate(state_dir=state_dir)
    model = model or NousClient()
    ledger = ledger or RevenueLedger(
        os.environ.get("VERIFY_LEDGER", DEFAULT_LEDGER_PATH))
    engine = VerifyEngine(model, fetcher)
    idem = Idempotency(os.path.join(state_dir, "idempotency.db"))

    app = FastAPI(
        title="aurum-verify",
        version=__version__,
        description=(
            "Evidence-backed verification of claims for autonomous agents. "
            "Returns per-claim verdicts where every surviving verdict rests on a "
            "quote verified verbatim against the cited source. Pay-per-call over "
            "x402 (HTTP 402); no account, no API key, no human in the loop."
        ),
    )

    def challenge_response(resource: str, reason: Optional[str], status: int = 402) -> JSONResponse:
        nonce, terms = gate.new_challenge(resource)
        body = {
            "x402Version": terms["x402Version"],
            "error": "payment_required" if status == 402 else "payment_rejected",
            "reason": reason,
            "accepts": terms["accepts"],
            "how_to_pay": ("Retry the same request with the PAYMENT-SIGNATURE header "
                           "containing the base64url x402 v1 PaymentPayload for this nonce."),
        }
        return JSONResponse(body, status_code=status,
                            headers={"PAYMENT-REQUIRED": encode_header(terms),
                                     "Cache-Control": "no-store"})

    @app.middleware("http")
    async def x402_gate_before_validation(request: Request, call_next):
        """The x402 gate must run BEFORE body validation. An unpaid request to any
        paid resource has to see the 402 challenge, never a 422 from body parsing —
        discovery crawlers and index verifiers POST with no body (or an empty one),
        and a 422 there makes the service look non-x402 to every catalog."""
        if (request.method == "POST" and request.url.path in PAID_RESOURCES
                and not request.headers.get("PAYMENT-SIGNATURE")
                and not os.path.exists(STOP_FILE)):
            # Only gate a POST that carries no body. A request WITH a body must
            # reach normal validation and idempotent-replay handling untouched.
            cl = (request.headers.get("content-length") or "").strip()
            if cl in ("", "0"):
                ops("challenge", req="req_prevalidation",
                    route=getattr(model, "model", FREE_FLAGSHIP),
                    client=type(model).__name__, mode=gate.mode, network=gate.network,
                    asset=gate.asset, reason="no credential supplied (pre-validation)",
                    http=402)
                return challenge_response(request.url.path, "no credential supplied")
        return await call_next(request)

    @app.exception_handler(RequestValidationError)
    async def _validation_or_challenge(request: Request, exc: RequestValidationError):
        """An unpaid POST whose body carries no verification/extraction request at
        all (empty object, or no `claims`/`url` field) must see the 402 challenge,
        never a 422: discovery crawlers and index verifiers probe exactly that way.
        A body that does carry `claims`/`url` but breaks a limit still returns 422."""
        errs = exc.errors()
        probe = any(e.get("type") == "missing"
                    and list(e.get("loc") or [])[-1:] in (["body"], ["claims"], ["url"])
                    for e in errs)
        if (probe and request.method == "POST" and request.url.path in PAID_RESOURCES
                and not request.headers.get("PAYMENT-SIGNATURE")
                and not os.path.exists(STOP_FILE)):
            ops("challenge", req="req_prevalidation",
                route=getattr(model, "model", FREE_FLAGSHIP),
                client=type(model).__name__, mode=gate.mode, network=gate.network,
                asset=gate.asset, reason="no verification request in body", http=402)
            return challenge_response(request.url.path, "no credential supplied")
        return JSONResponse({"detail": errs}, status_code=422)

    # Origin-level discovery: an index that probes the bare origin must see a
    # valid x402 challenge, not a 404, or the whole service is invisible to it.
    # The challenge still points at the paid resource.
    @app.get("/", include_in_schema=False)
    def root_discovery() -> JSONResponse:
        return challenge_response(RESOURCE, "no credential supplied")

    @app.head("/", include_in_schema=False)
    def root_discovery_head() -> Response:
        _, terms = gate.new_challenge(RESOURCE)
        return Response(status_code=402,
                        headers={"PAYMENT-REQUIRED": encode_header(terms),
                                 "Cache-Control": "no-store"})

    # Some crawlers and indexers probe the conventional x402 discovery paths
    # rather than the origin root. Those must be a plain 200 discovery document
    # (a 402 challenge there makes crawlers like agent402 "back off" entirely).
    @app.get("/.well-known/x402", include_in_schema=False)
    def well_known_x402() -> JSONResponse:
        _, terms = gate.new_challenge(RESOURCE)
        return JSONResponse({
            "x402Version": 1,
            "name": "aurum-verify",
            "description": "Pay-per-call evidence: claim verification with a verbatim evidence trail, and content extraction.",
            "resources": [{
                "resource": RESOURCE,
                "url": RESOURCE,
                "description": "verify-api claim verification",
                "accepts": [terms],
            }, {
                "resource": EXTRACT_RESOURCE,
                "url": EXTRACT_RESOURCE,
                "description": "content extraction: one URL -> clean markdown, title, byline, excerpt",
                "accepts": [terms],
            }],
        }, status_code=200, headers={"Cache-Control": "no-store"})

    @app.get("/x402.json", include_in_schema=False)
    def x402_json() -> JSONResponse:
        return well_known_x402()

    @app.get("/.well-known/x402.json", include_in_schema=False)
    def well_known_x402_json() -> JSONResponse:
        """Alias of /.well-known/x402.

        A real crawler probed this exact path and got a 404, which reads as
        'not an x402 service' and costs the listing. It must be a plain 200
        discovery document, exactly like /.well-known/x402.
        """
        return well_known_x402()

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(
            status="ok", version=__version__,
            upstream=getattr(model, "model", FREE_FLAGSHIP),
            paid_mode=gate.mode,
            endpoints={
                "verify": RESOURCE,
                "extract": EXTRACT_RESOURCE,
                "pricing": "/v1/pricing",
                "openapi": "/openapi.json",
            },
        )

    @app.get("/v1/pricing")
    def pricing() -> Dict[str, Any]:
        """Machine-readable price list. Published so an agent can price a call
        before making it — never a surprise invoice."""
        return {
            "resources": [RESOURCE, EXTRACT_RESOURCE],
            "resource": RESOURCE,
            "price_usd": gate.price_usd,
            "price_atomic": gate.price_atomic,
            "asset": gate.asset,
            "network": gate.network,
            "pay_to": gate.pay_to,
            "mode": gate.mode,
            "prices": {RESOURCE: gate.price_usd, EXTRACT_RESOURCE: gate.price_usd},
            "included": {
                "claims": "up to 25 per call",
                "sources": "up to 20; fetched live when no text is supplied",
                "verbatim_quote_gate": True,
                "evidence_receipts": True,
                "extract": "one URL per call -> clean markdown, title, byline, excerpt",
            },
            "settlement": ("simulation" if gate.mode == "test"
                           else "facilitator-verified on-chain settlement"),
        }

    # Discovery affordance: an unpaid read of the paid resource returns the same
    # 402 challenge an unpaid POST does. Every discovery layer (x402 Bazaar,
    # x402scan, agent402, generic crawlers) probes a resource with GET/HEAD
    # before listing it; answering 405 there hides the service from all of them.
    @app.get(RESOURCE, include_in_schema=False)
    def verify_claims_discovery() -> JSONResponse:
        return challenge_response(RESOURCE, "no credential supplied")

    @app.head(RESOURCE, include_in_schema=False)
    def verify_claims_head() -> Response:
        _, terms = gate.new_challenge(RESOURCE)
        return Response(status_code=402,
                        headers={"PAYMENT-REQUIRED": encode_header(terms),
                                 "Cache-Control": "no-store"})

    # Same discovery affordance for the extraction resource: an unpaid read
    # of /v1/extract returns the challenge a POST would. Two resources, one
    # gate — discovery crawlers find both.
    @app.get(EXTRACT_RESOURCE, include_in_schema=False)
    def extract_discovery() -> JSONResponse:
        return challenge_response(EXTRACT_RESOURCE, "no credential supplied")

    @app.head(EXTRACT_RESOURCE, include_in_schema=False)
    def extract_head() -> Response:
        _, terms = gate.new_challenge(EXTRACT_RESOURCE)
        return Response(status_code=402,
                        headers={"PAYMENT-REQUIRED": encode_header(terms),
                                 "Cache-Control": "no-store"})

    @app.post(RESOURCE)
    def verify_claims(payload: VerifyRequest, request: Request,
                      response: Response,
                      payment_signature: Optional[str] = Header(None, alias="PAYMENT-SIGNATURE")):
        started = time.perf_counter()
        fingerprint = fingerprint_of(payload)
        log_req = "req_" + uuid.uuid4().hex[:12]
        route = getattr(model, "model", FREE_FLAGSHIP)
        client_kind = type(model).__name__

        # §22 emergency stop: a STOP file in the state dir refuses the paid
        # route only (health/pricing stay up so svc-watch can still see a
        # live process). Deliberately before idempotency: a stopped endpoint
        # must not serve even cached answers to a paid caller.
        if os.path.exists(STOP_FILE):
            ops("stopped", req=log_req, route=route, client=client_kind,
                mode=gate.mode, http=503)
            return JSONResponse({"error": "service_stopped",
                                 "reason": "STOP file present; paid routes disabled by operator"},
                                 status_code=503,
                                 headers={"Cache-Control": "no-store"})

        # An idempotent replay of the same question must not be charged twice.
        # It is checked before the credential, because a replaying agent often
        # no longer holds the credential it used the first time.
        if payload.idempotency_key:
            cached = idem.get(payload.idempotency_key)
            if cached:
                body, status, stored_fp = cached
                if stored_fp != fingerprint:
                    return JSONResponse(
                        {"error": "idempotency_key_reuse",
                         "reason": "this idempotency key was used for a different question"},
                        status_code=409)
                ops("replay", req=log_req, route=route, client=client_kind,
                    mode=gate.mode, http=status)
                return JSONResponse(body, status_code=status,
                                    headers={"X-Idempotent-Replay": "true"})

        if payment_signature is None:
            ops("challenge", req=log_req, route=route, client=client_kind,
                mode=gate.mode, network=gate.network, asset=gate.asset,
                reason="no credential supplied", http=402)
            return challenge_response(RESOURCE, "no credential supplied")

        try:
            settlement = gate.settle(payment_signature, RESOURCE)
        except PaymentError as exc:
            # Transport error table: malformed payload -> 400 invalid, failed
            # verification/settlement -> 402 with a fresh challenge.
            if getattr(exc, "http_status", 402) == 400:
                ops("settle_fail", req=log_req, route=route, client=client_kind,
                    mode=gate.mode, network=gate.network, reason=str(exc), http=400)
                return JSONResponse({"error": "invalid_payment",
                                     "reason": str(exc)},
                                    status_code=400,
                                    headers={"Cache-Control": "no-store"})
            ops("challenge", req=log_req, route=route, client=client_kind,
                mode=gate.mode, network=gate.network, asset=gate.asset,
                reason=str(exc), http=402)
            return challenge_response(RESOURCE, str(exc))

        request_id = "req_" + uuid.uuid4().hex
        ops("settle_ok", req=log_req, request_id=request_id, route=route,
            client=client_kind, mode=settlement["mode"],
            network=settlement["network"],
            tx=settlement["settlement"].get("tx"),
            payer=settlement["settlement"].get("payer"))
        try:
            verdicts, summary, used_model = engine.run(payload)
        except UpstreamError as exc:
            # A failure is never billed: recorded with price 0 so the ledger and
            # the revenue number stay honest.
            ledger.record(receipt=settlement["receipt"], request_id=request_id,
                          mode=ledger_mode(gate), status="failed",
                          price_usd=0.0, cost_usd=0.0, error=str(exc),
                          network=gate.network, payer=settlement["settlement"].get("payer"))
            ops("upstream_fail", req=log_req, request_id=request_id, route=route,
                client=client_kind,
                lane=(model.route.get("aggregator")
                      if isinstance(getattr(model, "route", None), dict) else None),
                mode=ledger_mode(gate), reason=str(exc),
                latency_ms=int((time.perf_counter() - started) * 1000), http=503)
            return JSONResponse(
                {"error": "upstream_unavailable", "reason": str(exc),
                 "billing": "not charged", "receipt": settlement["receipt"]},
                status_code=503,
                headers={"PAYMENT-RESPONSE": encode_header({
                    "success": False, "transaction": "",
                    "network": gate.network,
                    "payer": settlement["settlement"].get("payer"),
                    "errorReason": "upstream_unavailable"})})

        latency_ms = int((time.perf_counter() - started) * 1000)
        ops("verdict_ok", req=log_req, request_id=request_id, route=route,
            client=client_kind, lane=used_model,
            inner_lane=getattr(model, "last_lane", None),
            mode=ledger_mode(gate),
            network=gate.network, verdicts="%s/%s/%s/%s" % (
                summary.supported, summary.contradicted, summary.mixed,
                summary.unverifiable),
            latency_ms=latency_ms, http=200)
        body = VerifyResponse(
            request_id=request_id, verdicts=verdicts, summary=summary,
            model=used_model, latency_ms=latency_ms,
            receipt=settlement["receipt"], price_usd=gate.price_usd)

        ledger.record(receipt=settlement["receipt"], request_id=request_id,
                      mode=ledger_mode(gate), status="settled",
                      price_usd=gate.price_usd, cost_usd=0.0,
                      network=gate.network, asset=gate.asset,
                      payer=settlement["settlement"].get("payer"),
                      tx=settlement["settlement"].get("tx"),
                      model=used_model, latency_ms=latency_ms,
                      claims=summary.claims_total,
                      quotes_verbatim=summary.quotes_verbatim,
                      quotes_rejected=summary.quotes_rejected)

        payload_dict = body.model_dump(mode="json")
        if payload.idempotency_key:
            idem.put(payload.idempotency_key, payload_dict, 200, fingerprint)
        return JSONResponse(
            payload_dict, status_code=200,
            headers={
                "PAYMENT-RESPONSE": encode_header({
                    "success": True,
                    "transaction": settlement["settlement"].get("tx") or "",
                    "network": gate.network,
                    "payer": settlement["settlement"].get("payer"),
                }),
                "X-Request-Id": request_id,
            })

    @app.post(EXTRACT_RESOURCE)
    def extract_content(payload: ExtractRequest, request: Request,
                        response: Response,
                        payment_signature: Optional[str] = Header(None, alias="PAYMENT-SIGNATURE")):
        """Paid content extraction — the higher-demand sibling of verification.
        One URL in, clean markdown out. Same gate, same receipt, same ledger.
        Never bills a failed fetch (price 0, recorded as failed)."""
        started = time.perf_counter()
        fingerprint = fingerprint_of(payload)
        log_req = "req_" + uuid.uuid4().hex[:12]
        route = getattr(model, "model", FREE_FLAGSHIP)
        client_kind = type(model).__name__

        if os.path.exists(STOP_FILE):
            ops("stopped", req=log_req, route=route, client=client_kind,
                mode=gate.mode, http=503)
            return JSONResponse({"error": "service_stopped",
                                 "reason": "STOP file present; paid routes disabled by operator"},
                                status_code=503,
                                headers={"Cache-Control": "no-store"})

        if payload.idempotency_key:
            cached = idem.get(payload.idempotency_key)
            if cached:
                body, status, stored_fp = cached
                if stored_fp != fingerprint:
                    return JSONResponse(
                        {"error": "idempotency_key_reuse",
                         "reason": "this idempotency key was used for a different url"},
                        status_code=409)
                ops("replay", req=log_req, route=route, client=client_kind,
                    mode=gate.mode, http=status)
                return JSONResponse(body, status_code=status,
                                    headers={"X-Idempotent-Replay": "true"})

        if payment_signature is None:
            ops("challenge", req=log_req, route=route, client=client_kind,
                mode=gate.mode, network=gate.network, asset=gate.asset,
                reason="no credential supplied", http=402)
            return challenge_response(EXTRACT_RESOURCE, "no credential supplied")

        try:
            settlement = gate.settle(payment_signature, EXTRACT_RESOURCE)
        except PaymentError as exc:
            if getattr(exc, "http_status", 402) == 400:
                ops("settle_fail", req=log_req, route=route, client=client_kind,
                    mode=gate.mode, network=gate.network, reason=str(exc), http=400)
                return JSONResponse({"error": "invalid_payment",
                                     "reason": str(exc)},
                                    status_code=400,
                                    headers={"Cache-Control": "no-store"})
            ops("challenge", req=log_req, route=route, client=client_kind,
                mode=gate.mode, network=gate.network, asset=gate.asset,
                reason=str(exc), http=402)
            return challenge_response(EXTRACT_RESOURCE, str(exc))

        request_id = "req_" + uuid.uuid4().hex
        ops("settle_ok", req=log_req, request_id=request_id, route=route,
            client=client_kind, mode=settlement["mode"],
            network=settlement["network"],
            tx=settlement["settlement"].get("tx"),
            payer=settlement["settlement"].get("payer"))
        try:
            article = extract(payload.url, fetcher=fetcher,
                              max_chars=payload.max_chars)
        except ExtractError as exc:
            # Extraction is deterministic and its failures are deterministic, so
            # they are never billed: the caller gets a 400 and pays nothing.
            ledger.record(receipt=settlement["receipt"], request_id=request_id,
                          mode=ledger_mode(gate), status="failed",
                          price_usd=0.0, cost_usd=0.0, error=str(exc),
                          network=gate.network, payer=settlement["settlement"].get("payer"))
            ops("extract_fail", req=log_req, request_id=request_id, route=route,
                client=client_kind, mode=ledger_mode(gate), reason=str(exc),
                latency_ms=int((time.perf_counter() - started) * 1000), http=400)
            return JSONResponse(
                {"error": "extraction_failed", "reason": str(exc),
                 "billing": "not charged", "receipt": settlement["receipt"]},
                status_code=400,
                headers={"Cache-Control": "no-store"})

        latency_ms = int((time.perf_counter() - started) * 1000)
        ops("extract_ok", req=log_req, request_id=request_id, route=route,
            client=client_kind, mode=ledger_mode(gate),
            network=gate.network, words=article["word_count"],
            hidden=len(article["hidden_content"]),
            latency_ms=latency_ms, http=200)
        body = ExtractResponse(
            request_id=request_id,
            article=ExtractedArticle(**article),
            model=route, latency_ms=latency_ms,
            receipt=settlement["receipt"], price_usd=gate.price_usd)

        ledger.record(receipt=settlement["receipt"], request_id=request_id,
                      mode=ledger_mode(gate), status="settled",
                      price_usd=gate.price_usd, cost_usd=0.0,
                      network=gate.network, asset=gate.asset,
                      payer=settlement["settlement"].get("payer"),
                      tx=settlement["settlement"].get("tx"),
                      model=route, latency_ms=latency_ms,
                      url=payload.url, words=article["word_count"],
                      hidden_content=len(article["hidden_content"]))

        payload_dict = body.model_dump(mode="json")
        if payload.idempotency_key:
            idem.put(payload.idempotency_key, payload_dict, 200, fingerprint)
        return JSONResponse(
            payload_dict, status_code=200,
            headers={
                "PAYMENT-RESPONSE": encode_header({
                    "success": True,
                    "transaction": settlement["settlement"].get("tx") or "",
                    "network": gate.network,
                    "payer": settlement["settlement"].get("payer"),
                }),
                "X-Request-Id": request_id,
            })

    @app.get("/internal/revenue", include_in_schema=False)
    def revenue(x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token")):
        expected = os.environ.get("VERIFY_ADMIN_TOKEN", "")
        if not expected or x_admin_token != expected:
            return JSONResponse({"error": "not_found"}, status_code=404)
        return ledger.summary()


    # --- Stripe webhook -----------------------------------------------------
    # A human buyer pays through a Stripe Checkout link. Stripe then POSTs the
    # event here. Without this route the payment happens but is never recorded,
    # so the ledger shows $0 while real money actually arrived.
    def _stripe_sig_ok(raw: bytes, header) -> bool:
        secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
        if not secret or not header:
            return False
        parts = {}
        for chunk in header.split(","):
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                parts[k.strip()] = v.strip()
        ts, sig = parts.get("t", ""), parts.get("v1", "")
        if not ts or not sig:
            return False
        try:
            if abs(int(time.time()) - int(ts)) > 300:
                return False
        except ValueError:
            return False
        expected = hmac.new(secret.encode(), f"{ts}.".encode() + raw,
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)

    @app.post("/v1/stripe/webhook", include_in_schema=False)
    async def stripe_webhook(request: Request):
        raw = await request.body()
        if not _stripe_sig_ok(raw, request.headers.get("stripe-signature")):
            return JSONResponse({"error": "invalid signature"}, status_code=400)
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            return JSONResponse({"error": "bad json"}, status_code=400)
        if event.get("type") != "checkout.session.completed":
            return JSONResponse({"ok": True, "ignored": True})
        obj = event.get("data", {}).get("object", {})
        amount = obj.get("amount_total") or 0
        currency = (obj.get("currency") or "usd").upper()
        pid = obj.get("payment_intent") or ""
        product = (obj.get("metadata") or {}).get("product") or ""
        price_usd = round(amount / 100.0, 2) if currency == "USD" else 0.0
        ledger.record(
            receipt=pid or obj.get("id", ""),
            request_id=event.get("id", ""),
            mode="production",
            status="settled",
            tx=pid,
            price_usd=price_usd,
            currency=currency,
            product=product,
            client="stripe",
        )
        return JSONResponse({"ok": True})

    return app



app = create_app()
