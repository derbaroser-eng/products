# Building pay-per-call APIs with x402

The hardest part of selling an API to a machine is not the API. It is the
billing. An API key assumes a customer who can sign up, read a dashboard, and
remember to cancel. An agent has none of those things — it has a wallet, a task, and a request to make now.

x402 answers that with a status code HTTP already had: **402 Payment Required**.
Instead of a login, the server answers an unpaid request with a machine-readable
bill. The client pays by signing a transfer, and the same request is retried. No account, no invoice, no human in the loop.

This post walks through a working implementation: one FastAPI service, one paid
endpoint, and a gate that speaks x402 v1.

## The challenge

Ask for something you haven't paid for and you get the bill, not an error:

```console
$ curl -si -X POST https://api.example.com/v1/verify/claims \
    -H 'content-type: application/json' \
    -d '{"claims":["The sky is blue."],"sources":[{"url":"https://example.com"}]}'

HTTP/1.1 402 Payment Required
PAYMENT-REQUIRED: eyJ4NDAyVmVyc2lvbiI6MSwiZXJyb3IiOiJQQVlNRU5ULVNJR05BVHVSSSBoZWFkZXIgaXMgcmVxdWlyZWQiLCJhY2NlcHRzIjpbeyJzY2hlbWUiOiJleGFjdCIsIm5ldHdvcmsiOiJiYXNlLXNlcG9saWEiLCJtYXhBbW91bnRSZXF1aXJlZCI6IjUwMDAwIiwiYXNzZXQiOiIweDAzNkNiRDUzODQyYzU0MjY2MzRlNzkyOTU0MWVDMjMxOGYzZENGN2UiLCJwYXlUbyI6IjB4..."fQ==
```

The body carries the same thing in JSON, so a client that only reads bodies
still works:

```json
{
  "x402Version": 1,
  "error": "payment_required",
  "accepts": [{
    "scheme": "exact",
    "network": "base-sepolia",
    "maxAmountRequired": "50000",
    "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "payTo": "0xYourReceiveAddress",
    "resource": "https://api.example.com/v1/verify/claims",
    "description": "verify-api claim verification",
    "maxTimeoutSeconds": 300,
    "extra": {"name": "USDC", "version": "2", "priceUsd": 0.05}
  }]
}
```

Read that as a contract. `scheme` says how payment is made (`exact` = one
signed transfer of an exact amount). `network` and `asset` say where and in
what. `maxAmountRequired` is the price in the asset's smallest unit. `payTo` is who gets paid. `resource` is what is being bought.

Two details matter more than they look. The `asset` is a **contract address**, not a ticker — a payment that names the wrong asset is a payment to the wrong place. And `resource` must be an **absolute URL**: a bare path cannot be resolved by a crawler deciding whether your service exists.

## The payment flow

`exact` uses EIP-3009 `transferWithAuthorization`: the payer signs an
authorization naming a recipient, an amount, a validity window, and a nonce.
The signature *is* the money order.

A client builds the credential like this:

```python
import time, os
from eth_account import Account
from eth_account.messages import encode_typed_data

def build_credential(challenge, private_key):
    req = challenge["accepts"][0]
    now = int(time.time())
    auth = {
        "from": Account.from_key(private_key).address,
        "to": req["payTo"],
        "value": req["maxAmountRequired"],
        "validAfter": "0",
        "validBefore": str(now + 300),
        "nonce": os.urandom(32).hex(),
    }
    message = {
        "types": {
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
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {"name": "USD Coin", "version": "2",
                   "chainId": 84532, "verifyingContract": req["asset"]},
        "message": {**auth, "nonce": bytes.fromhex(auth["nonce"])},
    }
    signed = Account.sign_message(encode_typed_data(full_message=message),
                                  private_key=private_key)
    payload = {"x402Version": 1, "scheme": "exact", "network": req["network"],
               "payload": {"signature": signed.signature.hex(),
                           "authorization": auth}}
    return base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
```

Then the same request goes out again, with one extra header:

```console
$ curl -si -X POST https://api.example.com/v1/verify/claims \
    -H 'content-type: application/json' \
    -H "PAYMENT-SIGNATURE: $CREDENTIAL" \
    -d '{"claims":["The sky is blue."],"sources":[{"url":"https://example.com"}]}'

HTTP/1.1 200 OK
PAYMENT-RESPONSE: eyJzdWNjZXNzIjp0cnVlLCJ0cmFuc2FjdGlvbiI6IjB4..."

{"request_id": "req_9f2c...", "verdicts": [...], "receipt": "rcpt_71ab...", "price_usd": 0.05}
```

That is the whole protocol: one retry branch.

## The server side

The gate has four jobs: parse the credential, refuse anything malformed,
settle, and remember the nonce so it can never be spent twice.

```python
def settle(self, credential_header: str, resource: str) -> dict:
    auth, parsed = self._parse_payload(credential_header, resource)  # 400 on malformed
    nonce = str(auth["nonce"])

    if self.mode == "test":
        expected = hmac.new(self.secret,
                            f"{nonce}|{auth['value']}|{self.pay_to}".encode(),
                            sha256).hexdigest()
        if not hmac.compare_digest(expected, parsed["signature"]):
            raise PaymentError("test credential signature invalid")
        settlement = {"status": "simulated", "tx": None, "payer": auth["from"]}
    else:
        signer = recover_eip3009_signer(self.chain_id, self.asset, auth,
                                        parsed["signature"])
        if signer.lower() != str(auth["from"]).lower():
            raise PaymentError("EIP-712 signer does not match authorization.from")
        settlement = self._settle_via_facilitator(parsed["raw"])

    if not self.nonces.claim(nonce, float(auth["validBefore"])):
        raise PaymentError("nonce already used (replay rejected)")

    return {"receipt": "rcpt_" + uuid.uuid4().hex, "mode": self.mode,
            "network": self.network, "settlement": settlement, ...}
```

Three decisions in there are load-bearing.

**Parse before you validate.** A malformed payload, a wrong network, an
underpayment, or a recipient that isn't yours is a `400` — the client's fault.
A credential that parses but fails verification or settlement is a `402` with a
fresh challenge, because the client can still fix it by paying properly. Mixing them makes debugging miserable.

**Verification is not settlement.** In production the server calls the
facilitator's `/verify` and then `/settle`, in that order. Only a settled response carrying a transaction hash produces a receipt. `isValid: true` means the signature is good — not that the money moved.

**The nonce is the receipt's spine.** It is stored before the response returns, so a replay is rejected even if the first request crashed on the way back. Without it, a retried request buys the same answer twice and the ledger lies.

## Failure is not a bill

The rule that keeps the ledger honest: a call that fails is recorded at price
zero, never charged.

```python
except UpstreamError as exc:
    ledger.record(receipt=settlement["receipt"], request_id=request_id,
                  mode=ledger_mode(gate), status="failed",
                  price_usd=0.0, cost_usd=0.0, error=str(exc))
    return JSONResponse({"error": "upstream_unavailable",
                         "billing": "not charged",
                         "receipt": settlement["receipt"]}, status_code=503)
```

Add an `idempotency_key` and a replay of the *same question* returns the stored
response with `X-Idempotent-Replay: true` and costs nothing. Reusing a key for a *different* question is a `409`.

## Discovery is part of the protocol

A paid API nobody can find is a paid API nobody buys. Every discovery layer —
the x402 Bazaar, x402scan, generic crawlers — probes a resource with a `GET` or
`HEAD` before listing it. Answer `405` and you are invisible.

So the bare origin, the paid resource, and `/.well-known/x402` all answer with
a valid challenge or a plain `200` discovery document:

```python
@app.get("/.well-known/x402", include_in_schema=False)
def well_known_x402():
    _, terms = gate.new_challenge(RESOURCE)
    return JSONResponse({"x402Version": 1, "name": "aurum-verify",
                         "resources": [{"resource": RESOURCE, "url": RESOURCE,
                                        "accepts": [terms]}]}, status_code=200)
```

One subtlety: a `402` at the discovery path makes crawlers back off. Discovery documents are `200`; only the paid resource challenges.

## What I'd tell a reviewer

- **The gate runs before body validation.** An unpaid POST with no body must see
  the `402`, never a `422` from parsing — a `422` reads as "not an x402 service" to every catalog.
- **Keep the price integer.** USDC has six decimals; store `50000`, not `0.05`.
- 
- **Test mode needs no wallet.** An HMAC credential exercises the whole flow — challenge, header, nonce, receipt — with no chain and no money.

## Where this goes

The pattern generalizes past verification. Any endpoint with a deterministic
cost and a clear unit of value can be gated this way: extraction, enrichment,
moderation, a single SQL query. The server's job is to describe the bill
precisely and refuse to serve until it is paid; the client's job is one retry.

The starter kit this post accompanies has the whole service — gate, ledger,
receipts, discovery, test credentials — with no secrets and no account creation.
Copy it, point `VERIFY_PAY_TO` at your own address, and you have a paid API in
an afternoon.
