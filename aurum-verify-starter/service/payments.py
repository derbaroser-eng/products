"""x402 v1 payment gate: Challenge -> Credential -> Verify -> Settle -> Receipt.

Wire shapes follow the official x402 v1 core specification
(x402-foundation/x402, specs/x402-specification-v1.md) with the HTTP
transport header family (PAYMENT-REQUIRED / PAYMENT-SIGNATURE /
PAYMENT-RESPONSE, per the canonical HTTP transport):

    PAYMENT-REQUIRED   server -> client : {x402Version, error, accepts:[...]}
    PAYMENT-SIGNATURE  client -> server : {x402Version, scheme, network,
                                           payload:{signature, authorization}}
    PAYMENT-RESPONSE   server -> client : {success, transaction, network,
                                           payer, errorReason?}

The `exact` scheme uses EIP-3009 transferWithAuthorization; the
authorization envelope carries {from, to, value, validAfter, validBefore,
nonce}. Asset is the USDC *contract address* (Circle docs), not the symbol:

    base-sepolia  0x036CbD53842c5426634e7929541eC2318f3dCF7e
    base          0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913

Two modes, always visible in receipt and ledger:

    test        v1 envelope, HMAC test credential. No chain, no money.
                Every ledger row is stamped `simulation` and can never be
                counted as revenue.
    production  EIP-712 signer recovery (must equal `from`), then the
                facilitator is called in spec order: POST /verify, then
                POST /settle. Only a settled response carrying a transaction
                hash produces a production receipt. Verification alone is
                never treated as settlement.

Replay protection is nonce-based and persistent: the same nonce can never
buy a second answer, whether or not the first request succeeded.
"""
from __future__ import annotations

import base64
import hmac
import json
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Dict, Optional, Tuple

X402_VERSION = 1
DEFAULT_NETWORK = "base-sepolia"  # testnet-first: production requires an explicit override
DEFAULT_PRICE_USD = 0.05  # see README: price is tied to retrieved-source count, not vibes
USDC_DECIMALS = 6
EIP3009_DOMAIN_NAME = "USD Coin"
EIP3009_DOMAIN_VERSION = "2"

# Circle-issued USDC contracts (developers.circle.com/stablecoins/usdc-contract-addresses).
KNOWN_NETWORKS: Dict[str, Dict[str, Any]] = {
    "base-sepolia": {
        "chain_id": 84532,
        "usdc": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    },
    "base": {
        "chain_id": 8453,
        "usdc": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    },
}
PRODUCTION_NETWORKS = ("base",)
MODES = ("test", "production")


def _load_service_env() -> None:
    """Load a service-local env file (verify.env / .env) without touching the
    global process env. Owner-supplied values live there; process env wins."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in ("verify.env", ".env", ".state/verify.env"):
        path = os.path.join(here, name)
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    key, value = key.strip(), value.strip().strip("'\"")
                    if key.startswith("VERIFY_") or key == "X402_FACILITATOR_URL":
                        os.environ.setdefault(key, value)
        except OSError:
            continue


_load_service_env()


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def encode_header(payload: Dict[str, Any]) -> str:
    return b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def decode_header(value: str) -> Dict[str, Any]:
    try:
        data = json.loads(b64url_decode(value).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise PaymentError(f"malformed payment header: {type(exc).__name__}",
                           http_status=400) from exc
    if not isinstance(data, dict):
        raise PaymentError("payment header is not a JSON object", http_status=400)
    return data


class PaymentError(Exception):
    """Raised for any credential the gate refuses. Message is safe to return.

    http_status follows the HTTP transport error table: 400 = Invalid
    Payment (malformed payload/requirements), 402 = Payment Failed
    (verification or settlement failed) or Payment Required.
    """

    def __init__(self, message: str, http_status: int = 402):
        super().__init__(message)
        self.http_status = http_status


@dataclass(frozen=True)
class Terms:
    price_usd: float
    price_atomic: str
    network: str
    asset: str  # USDC contract address on `network`
    pay_to: str
    resource: str  # full URL when a public base is configured, else the path

    def challenge(self, nonce: str, ttl_seconds: int = 300,
                  description: str = "verify-api claim verification") -> Dict[str, Any]:
        return {
            "x402Version": X402_VERSION,
            "error": "PAYMENT-SIGNATURE header is required",
            "accepts": [{
                "scheme": "exact",
                "network": self.network,
                "maxAmountRequired": self.price_atomic,
                "asset": self.asset,
                "payTo": self.pay_to,
                "resource": self.resource,
                "description": description,
                "mimeType": "application/json",
                "maxTimeoutSeconds": ttl_seconds,
                "extra": {"name": "USDC", "version": EIP3009_DOMAIN_VERSION,
                          "priceUsd": self.price_usd},
                # x402 v1 discovery declaration for the Bazaar. In v1 the
                # declaration rides inside the payment requirements themselves,
                # so the facilitator can catalog the resource without the buyer's
                # client echoing anything. `type` and `method` are required.
                "outputSchema": {
                    "input": {
                        "type": "http",
                        "method": "POST",
                        "bodyType": "json",
                        "body": {
                            "claims": ["<assertion to verify>"],
                            "sources": [{"url": "https://example.com"}],
                        },
                    },
                    "output": {
                        "type": "json",
                        "example": {
                            "verdicts": [{"claim": "<assertion>",
                                          "verdict": "supported"}],
                            "receipt": "rcpt_...",
                            "request_id": "req_...",
                        },
                    },
                },
            }],
        }


class NonceStore:
    """Persistent single-use nonce ledger. Replay is a 4xx, never a free answer."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as con:
            con.execute(
                "CREATE TABLE IF NOT EXISTS nonces ("
                "nonce TEXT PRIMARY KEY, seen_at REAL NOT NULL, expires_at REAL NOT NULL)"
            )

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=10)
        con.execute("PRAGMA journal_mode=WAL")
        return con

    def claim(self, nonce: str, expires_at: float) -> bool:
        """True the first time only. Expired rows are swept opportunistically."""
        with self._lock, self._connect() as con:
            con.execute("DELETE FROM nonces WHERE expires_at < ?", (time.time() - 86400,))
            try:
                con.execute("INSERT INTO nonces (nonce, seen_at, expires_at) VALUES (?,?,?)",
                            (nonce, time.time(), expires_at))
            except sqlite3.IntegrityError:
                return False
            return True


def _eip712_domain(chain_id: int, verifying_contract: str) -> Dict[str, Any]:
    return {"name": EIP3009_DOMAIN_NAME, "version": EIP3009_DOMAIN_VERSION,
            "chainId": chain_id, "verifyingContract": verifying_contract}


_EIP3009_TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
    ],
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ],
}


def recover_eip3009_signer(chain_id: int, verifying_contract: str, auth: Dict[str, Any],
                           signature: str) -> str:
    """Recover the EIP-712 signer of a transferWithAuthorization. Raises PaymentError."""
    try:
        from eth_account.messages import encode_typed_data
        from eth_account import Account
    except ImportError as exc:
        raise PaymentError("production settlement requires eth_account") from exc
    try:
        nonce = auth["nonce"]
        nonce_bytes = bytes.fromhex(nonce[2:] if str(nonce).startswith("0x") else str(nonce))
        if len(nonce_bytes) != 32:
            raise ValueError("nonce must be 32 bytes")
        message = {
            "types": dict(_EIP3009_TYPES),
            "primaryType": "TransferWithAuthorization",
            "domain": _eip712_domain(chain_id, verifying_contract),
            "message": {
                "from": auth["from"], "to": auth["to"],
                "value": int(str(auth["value"])),
                "validAfter": int(str(auth["validAfter"])),
                "validBefore": int(str(auth["validBefore"])),
                "nonce": nonce_bytes,
            },
        }
        encoded = encode_typed_data(full_message=message)
        return Account.recover_message(encoded, signature=signature)
    except PaymentError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise PaymentError(f"EIP-712 recovery failed: {type(exc).__name__}",
                           http_status=400) from exc


class PaymentGate:
    def __init__(
        self,
        mode: Optional[str] = None,
        price_usd: Optional[float] = None,
        pay_to: Optional[str] = None,
        network: Optional[str] = None,
        asset: Optional[str] = None,
        facilitator_url: Optional[str] = None,
        state_dir: Optional[str] = None,
        public_base_url: Optional[str] = None,
    ):
        self.mode = (mode or os.environ.get("VERIFY_PAID_MODE", "test")).lower()
        if self.mode not in MODES:
            raise ValueError(f"VERIFY_PAID_MODE must be one of {MODES}, got {self.mode!r}")
        self.price_usd = float(price_usd if price_usd is not None
                               else os.environ.get("VERIFY_PRICE_USD", DEFAULT_PRICE_USD))
        self.network = network or os.environ.get(
            "VERIFY_NETWORK",
            DEFAULT_NETWORK if self.mode == "test" else "base",
        )
        if self.network not in KNOWN_NETWORKS:
            raise ValueError(f"unknown network {self.network!r}; known: {sorted(KNOWN_NETWORKS)}")
        chain = KNOWN_NETWORKS[self.network]
        self.chain_id = chain["chain_id"]
        self.asset = asset or chain["usdc"]
        self.pay_to = pay_to or os.environ.get("VERIFY_PAY_TO", "")
        self.facilitator_url = facilitator_url or os.environ.get("X402_FACILITATOR_URL", "")
        _pb = (public_base_url
               or os.environ.get("VERIFY_PUBLIC_BASE_URL", "")).rstrip("/")
        # x402 `resource` must be an absolute URL. A scheme-less base (a bare
        # tunnel hostname) yields "host/path", which strict crawlers/indexers
        # cannot resolve and therefore mark the service non-routable.
        if _pb and not _pb.startswith(("http://", "https://")):
            _pb = "https://" + _pb
        self.public_base_url = _pb
        self.secret = os.environ.get("VERIFY_TEST_SECRET", "").encode("utf-8")
        if self.mode == "test" and not self.secret:
            # A test gate must still refuse forged credentials, so a secret is
            # generated and kept on disk rather than silently defaulting to "".
            self.secret = self._load_or_make_secret(state_dir)
        self.nonces = NonceStore(os.path.join(
            state_dir or os.environ.get("VERIFY_STATE_DIR", ".state"), "nonces.db"))

    def _load_or_make_secret(self, state_dir: Optional[str]) -> bytes:
        path = os.path.join(state_dir or os.environ.get("VERIFY_STATE_DIR", ".state"),
                            "test_secret.bin")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            return open(path, "rb").read()
        secret = os.urandom(32)
        with open(path, "wb") as fh:
            fh.write(secret)
        return secret

    # -- server side ---------------------------------------------------------
    @property
    def price_atomic(self) -> str:
        """USDC has 6 decimals; keep it integer so a float can never round a price."""
        return str(int(round(self.price_usd * 1_000_000)))

    def resource_url(self, resource: str) -> str:
        if self.public_base_url:
            return self.public_base_url.rstrip("/") + resource
        return resource

    def terms(self, resource: str) -> Terms:
        return Terms(self.price_usd, self.price_atomic, self.network, self.asset,
                     self.pay_to, self.resource_url(resource))

    def new_challenge(self, resource: str) -> Tuple[str, Dict[str, Any]]:
        nonce = uuid.uuid4().hex
        return nonce, self.terms(resource).challenge(nonce)

    def _parse_payload(self, credential_header: str, resource: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Return (authorization, raw_credential). Raises PaymentError(400) when malformed."""
        cred = decode_header(credential_header)
        if cred.get("x402Version") != X402_VERSION:
            raise PaymentError(
                f"unsupported x402Version: {cred.get('x402Version')!r} (need {X402_VERSION})",
                http_status=400)
        if str(cred.get("scheme", "exact")) != "exact":
            raise PaymentError(f"unsupported scheme: {cred.get('scheme')!r}", http_status=400)
        if str(cred.get("network")) != self.network:
            raise PaymentError(
                f"wrong network: {cred.get('network')!r} (need {self.network!r})",
                http_status=400)
        payload = cred.get("payload")
        if not isinstance(payload, dict):
            raise PaymentError("credential missing payload.authorization envelope",
                               http_status=400)
        auth = payload.get("authorization")
        if not isinstance(auth, dict):
            raise PaymentError("credential missing payload.authorization envelope",
                               http_status=400)
        for field in ("from", "to", "value", "nonce"):
            if not auth.get(field):
                raise PaymentError(f"authorization missing {field}", http_status=400)
        if str(auth["to"]).lower() != self.pay_to.lower():
            raise PaymentError("authorization pays a different recipient", http_status=400)
        try:
            value = int(str(auth["value"]))
        except ValueError as exc:
            raise PaymentError("authorization value is not an integer",
                               http_status=400) from exc
        if value < int(self.price_atomic):
            raise PaymentError(f"underpaid: {value} < {self.price_atomic} atomic USDC")
        now = time.time()
        try:
            valid_after = float(auth.get("validAfter", 0))
            valid_before = float(auth.get("validBefore", now + 300))
        except (TypeError, ValueError) as exc:
            raise PaymentError("authorization window is not numeric",
                               http_status=400) from exc
        if not (valid_after <= now <= valid_before):
            raise PaymentError("authorization outside its validity window")
        signature = payload.get("signature") or cred.get("signature") or ""
        if not signature:
            raise PaymentError("credential missing signature", http_status=400)
        return auth, {"signature": str(signature), "raw": cred}

    def settle(self, credential_header: str, resource: str) -> Dict[str, Any]:
        """Validate a v1 credential and return a settlement record.

        Raises PaymentError with a machine-readable reason on any refusal.
        """
        auth, parsed = self._parse_payload(credential_header, resource)
        nonce = str(auth["nonce"])
        expires_at = float(auth.get("validBefore", time.time() + 300))

        if self.mode == "test":
            expected = hmac.new(
                self.secret,
                f"{nonce}|{auth['value']}|{self.pay_to}".encode("utf-8"),
                sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected, parsed["signature"]):
                raise PaymentError("test credential signature invalid")
            settlement: Dict[str, Any] = {"status": "simulated", "tx": None,
                                          "payer": auth.get("from", "test-payer")}
        else:
            signer = recover_eip3009_signer(self.chain_id, self.asset, auth,
                                            parsed["signature"])
            if signer.lower() != str(auth["from"]).lower():
                raise PaymentError("EIP-712 signer does not match authorization.from")
            settlement = self._settle_via_facilitator(parsed["raw"])

        if not self.nonces.claim(nonce, expires_at):
            raise PaymentError("nonce already used (replay rejected)")

        return {
            "receipt": "rcpt_" + uuid.uuid4().hex,
            "requested_atomic": int(self.price_atomic),
            "paid_atomic": int(str(auth["value"])),
            "price_usd": self.price_usd,
            "asset": self.asset,
            "asset_symbol": "USDC",
            "network": self.network,
            "pay_to": self.pay_to,
            "mode": self.mode,
            "settlement": settlement,
            "resource": resource,
            "settled_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def _settle_via_facilitator(self, credential: Dict[str, Any]) -> Dict[str, Any]:
        """Spec order: POST /verify, then POST /settle. Verification alone
        is never settlement."""
        if not self.facilitator_url:
            raise PaymentError("production mode requires X402_FACILITATOR_URL")
        import httpx

        base = self.facilitator_url.rstrip("/")
        verify_body = {"x402Version": X402_VERSION, "paymentPayload": credential,
                       "paymentRequirements": {
                           "scheme": "exact", "network": self.network,
                           "maxAmountRequired": self.price_atomic,
                           "asset": self.asset, "payTo": self.pay_to}}
        try:
            with httpx.Client(timeout=20) as client:
                verify = client.post(base + "/verify", json=verify_body)
        except Exception as exc:  # noqa: BLE001
            raise PaymentError(f"facilitator unreachable: {type(exc).__name__}") from exc
        if verify.status_code != 200:
            raise PaymentError(f"facilitator refused: HTTP {verify.status_code}")
        vdata = verify.json()
        if not vdata.get("isValid"):
            raise PaymentError(f"facilitator invalid: {vdata.get('invalidReason', 'unknown')}")
        try:
            with httpx.Client(timeout=30) as client:
                settle = client.post(base + "/settle", json=verify_body)
        except Exception as exc:  # noqa: BLE001
            raise PaymentError(f"facilitator settle unreachable: {type(exc).__name__}") from exc
        if settle.status_code != 200:
            raise PaymentError(f"facilitator settle refused: HTTP {settle.status_code}")
        sdata = settle.json()
        if not sdata.get("success") or not sdata.get("transaction"):
            raise PaymentError(
                f"settlement failed: {sdata.get('errorReason', 'no transaction hash')}")
        return {"status": "settled", "tx": sdata["transaction"],
                "network": sdata.get("network", self.network),
                "payer": sdata.get("payer", credential.get("payload", {}).get(
                    "authorization", {}).get("from"))}

    # -- client helper (test + agent SDK use) --------------------------------
    def make_test_credential(self, nonce: str, resource: str,
                             amount: Optional[str] = None,
                             expires_in: int = 300,
                             auth_from: str = "test-payer") -> str:
        """v1-shaped test credential. Only valid in test mode."""
        if self.mode != "test":
            raise PaymentError("test credentials are refused in production mode")
        amount = amount or self.price_atomic
        now = int(time.time())
        auth = {"from": auth_from, "to": self.pay_to, "value": str(amount),
                "validAfter": str(now - 5), "validBefore": str(now + expires_in),
                "nonce": nonce}
        sig = hmac.new(self.secret,
                       f"{nonce}|{amount}|{self.pay_to}".encode("utf-8"),
                       sha256).hexdigest()
        return encode_header({"x402Version": X402_VERSION, "scheme": "exact",
                              "network": self.network,
                              "payload": {"signature": sig, "authorization": auth}})
