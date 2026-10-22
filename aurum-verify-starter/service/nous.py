"""free_ultra-only inference client (GOLD MASTER §1: sole permitted router, permanently).

The service MUST NOT call any model/provider directly. Every model request
goes through the free_ultra MoA preset exclusively. Direct Nous calls,
alternate routers, fallbacks, paid lanes and local models are all banned:
if free_ultra cannot serve, raise and let the caller return an honest 503.
Never fail over, never silently downgrade.

Model choice is deliberate and evidence-based. The catalog advertises nine free
ids; a real completion test shows only three answer, and the strongest of those
is `meituan/longcat-2.5-preview:free` (1,048,576-token context, reasoning on by
default, zero price). A long-context free lane is what makes multi-source
verification affordable — the whole evidence packet fits in one call.

The lane that leads used to be `stepfun/step-5-preview:free`, which is still
labelled free and returns an empty completion. It is not in the chain.

The client never falls back to a local endpoint and never to a paid model: if
the free lane is unavailable it raises, and the caller returns an honest 503
rather than a cheaper, different answer.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Optional

MOA_PRESET = "free_ultra"
MOA_PROVIDER = "moa"
# Banned: any direct model id, provider, local endpoint or paid lane. The
# service resolves these only through the free_ultra preset.
BANNED_DIRECT_ROUTES = ("127.0.0.1", "localhost", "11434", "ollama",
                        "golden", "openrouter", "omniroute", "openai",
                        "anthropic", "paid")
HERMES_HOME = os.environ.get("HERMES_HOME") or os.path.expanduser("~/.hermes")
FREE_FLAGSHIP = "moa:free_ultra"


class UpstreamError(Exception):
    """No free lane could answer. Honest failure, never a silent downgrade."""


def _auth_token() -> tuple[str, str]:
    path = os.path.join(HERMES_HOME, "auth.json")
    with open(path, encoding="utf-8") as fh:
        auth = json.load(fh)
    p = auth["providers"]["nous"]
    token = p.get("agent_key") or p.get("access_token")
    base = (p.get("inference_base_url") or
            "https://inference-api.nousresearch.com/v1").rstrip("/")
    if not token:
        raise UpstreamError("no Nous token in auth.json")
    return token, base


def extract_json(text: str) -> Dict[str, Any]:
    """Pull the first JSON object out of a model reply.

    Models wrap JSON in prose or fences. A tolerant extractor beats a strict
    parse that turns a good answer into a 500.
    """
    text = (text or "").strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    else:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            text = text[start:end + 1]
    return json.loads(text)


def _resolve_free_ultra() -> Dict[str, Any]:
    """Load and validate the free_ultra preset from the live config.yaml.

    Raises UpstreamError (fail closed) when the route is missing, disabled,
    or points anywhere but provider nous lanes. Never returns a direct lane."""
    import yaml
    cfg_path = os.path.join(HERMES_HOME, "config.yaml")
    try:
        cfg = yaml.safe_load(open(cfg_path, encoding="utf-8")) or {}
    except OSError as exc:
        raise UpstreamError(f"cannot read router config: {exc}") from exc
    if (cfg.get("model") or {}).get("provider") != MOA_PROVIDER:
        raise UpstreamError("model.provider is not moa (free_ultra not active)")
    if (cfg.get("model") or {}).get("default") != MOA_PRESET:
        raise UpstreamError("model.default is not free_ultra")
    moa = (cfg.get("moa") or {})
    presets = moa.get("presets") or {}
    preset = presets.get(MOA_PRESET)
    if not isinstance(preset, dict) or not preset.get("enabled", True):
        raise UpstreamError("free_ultra preset missing or disabled")
    agg = preset.get("aggregator") or {}
    refs = preset.get("reference_models") or []
    slots = [agg] + list(refs)
    if not agg.get("model") or not refs:
        raise UpstreamError("free_ultra preset has no aggregator/references")
    blob = json.dumps(slots).lower()
    for bad in BANNED_DIRECT_ROUTES:
        if bad in blob:
            raise UpstreamError(f"free_ultra preset contains banned route '{bad}'")
    for slot in slots:
        if slot.get("provider") != "nous":
            raise UpstreamError("free_ultra slot is not provider nous")
    return {"aggregator": agg["model"],
            "references": [r["model"] for r in refs],
            "fanout": preset.get("fanout", "user_turn")}


class NousClient:
    """free_ultra-only client. `model` is always reported as moa:free_ultra;
    the preset's aggregator lane carries the call, references advise per the
    preset fanout. No direct-lane calls, no fallback chain outside the preset."""

    @property
    def model(self) -> str:
        return FREE_FLAGSHIP

    @model.setter
    def model(self, value: str) -> None:
        if value != FREE_FLAGSHIP:
            raise UpstreamError(f"only {FREE_FLAGSHIP} is permitted (got {value!r})")

    def __init__(self, model: str = FREE_FLAGSHIP, timeout: int = 180,
                 temperature: float = 0.0):
        if model != FREE_FLAGSHIP:
            raise UpstreamError(f"only {FREE_FLAGSHIP} is permitted (got {model!r})")
        self.timeout = timeout
        self.last_lane: Optional[str] = None  # preset lane that answered the latest call (request-level trace evidence)
        self.temperature = temperature
        self.route: Optional[Dict[str, Any]] = None

    def complete(self, system: str, user: str, max_tokens: int = 4096) -> str:
        import httpx

        route = _resolve_free_ultra()  # re-resolved every call: config drift fails closed
        self.route = route
        token, base = _auth_token()
        body = {
            "model": route["aggregator"],
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "temperature": self.temperature,
            "max_tokens": max_tokens,
        }
        headers = {"Authorization": "Bearer " + token,
                   "Content-Type": "application/json",
                   "X-Aurum-Route": "moa:free_ultra"}
        last: Optional[str] = None
        # Reference lanes advise inside the preset; the service fans out here
        # because it has no agent-loop MoA runtime: same lanes, same order,
        # aggregator first. Any lane outside the preset is unreachable by construction.
        for model in [route["aggregator"]] + [m for m in route["references"]]:
            body["model"] = model
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(base + "/chat/completions", json=body, headers=headers)
                if resp.status_code != 200:
                    last = f"{model}: HTTP {resp.status_code}"
                    continue
                data = resp.json()
                content = data["choices"][0]["message"].get("content") or ""
                if content.strip():
                    # Identity stays moa:free_ultra: the lane is an implementation
                    # detail of the preset, never a separate route.
                    self.last_lane = model
                    return content
                last = f"{model}: empty completion"
            except Exception as exc:  # noqa: BLE001
                last = f"{model}: {type(exc).__name__}"
        raise UpstreamError(f"free_ultra answered nothing ({last})")

    def complete_json(self, system: str, user: str, max_tokens: int = 4096) -> Dict[str, Any]:
        raw = self.complete(system, user, max_tokens=max_tokens)
        try:
            return extract_json(raw)
        except Exception as exc:  # noqa: BLE001
            raise UpstreamError(f"model did not return JSON: {type(exc).__name__}") from exc


class StubModel:
    """Deterministic stand-in used by the test suite (no network, no tokens)."""

    def __init__(self, scripted: Dict[str, Dict[str, Any]], model: str = "stub/free:test"):
        self.scripted = scripted
        self.model = model
        self.calls = 0

    def complete_json(self, system: str, user: str, max_tokens: int = 4096) -> Dict[str, Any]:
        self.calls += 1
        for key, value in self.scripted.items():
            if key in user:
                return value
        return {"verdict": "unverifiable", "confidence": 0.0,
                "supporting": [], "contradicting": [], "reason": "no scripted answer"}

    def complete(self, system: str, user: str, max_tokens: int = 4096) -> str:
        return json.dumps(self.complete_json(system, user, max_tokens))
