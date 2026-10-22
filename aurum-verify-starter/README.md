# aurum-verify-starter

A public starter kit for **pay-per-call APIs secured with x402** — HTTP 402 as a
billing primitive, no account, no API key, no human in the loop.

The service in this repo is a working reference implementation: one narrow,
billable outcome behind an x402 `exact` payment gate.

> **Every claim in this payload is independently checked against live sources,
> and every quote used as evidence is verified verbatim — or the claim is
> reported unverifiable. You get a machine-readable receipt.**

Two paid resources, one gate, one receipt format, one ledger:

| Resource | What it does |
| --- | --- |
| `POST /v1/verify/claims` | Verify up to 25 claims against up to 20 sources. Per-claim verdict, evidence, verbatim-quote check, freshness. |
| `POST /v1/extract` | One URL -> clean markdown, title, byline, excerpt, word count, hidden-content report. Deterministic, no model. |

Free discovery and liveness endpoints (`/health`, `/v1/pricing`, `/openapi.json`,
`/.well-known/x402`) are open by design — an index must be able to see that the
service exists and what it costs before anything is bought.

---

## Prerequisites

- Python 3.10+
- A wallet that can sign EIP-3009 `transferWithAuthorization` (any EVM wallet
  with USDC on Base). For local development you do not need one — test mode
  uses an HMAC credential instead of a signature.
- An x402 facilitator for production settlement (see below). None is required
  for test mode.

### Dependencies

```
fastapi
uvicorn[standard]
httpx
pydantic
pyyaml
eth-account        # production mode only: EIP-712 signer recovery
```

---

## Install

```bash
./install.sh
```

`install.sh` creates a virtualenv at `.venv`, installs the dependencies, and
writes a `.env` from `.env.example` if one does not already exist. It never
overwrites an existing `.env`.

Then fill in your values:

```bash
$EDITOR .env
```

---

## Run

```bash
source .venv/bin/activate      # .venv/Scripts/activate on Windows
uvicorn service.app:app --reload --port 8000
```

Test mode (no chain, no money, no wallet):

```bash
VERIFY_PAID_MODE=test uvicorn service.app:app --port 8000
```

Health check:

```bash
curl -s localhost:8000/health | jq
```

Smoke-test the paid route — you should get a 402 challenge, not a 422:

```bash
curl -si -X POST localhost:8000/v1/verify/claims \
  -H 'content-type: application/json' \
  -d '{"claims":["The sky is blue."],"sources":[{"url":"https://example.com"}]}'
```

---

## How to integrate

The gate speaks the x402 v1 HTTP transport. Three headers carry the whole
protocol:

```
PAYMENT-REQUIRED   server -> client : the 402 challenge + payment requirements
PAYMENT-SIGNATURE  client -> server : base64url x402 v1 PaymentPayload
PAYMENT-RESPONSE   server -> client : settlement receipt (success / transaction / payer)
```

**1. Read the requirements.** An unpaid request returns HTTP 402 with the
challenge in the body and in the `PAYMENT-REQUIRED` header. `accepts[0]` carries
`scheme`, `network`, `maxAmountRequired`, `asset`, `payTo`, `resource`, and an
`extra` block with the human-readable price.

**2. Pay.** Build an EIP-3009 `transferWithAuthorization` authorization for the
exact `maxAmountRequired`, sign it, and wrap it in the v1 payload:

```json
{
  "x402Version": 1,
  "scheme": "exact",
  "network": "base-sepolia",
  "payload": {
    "signature": "<0x...>",
    "authorization": {
      "from": "<payer>",
      "to": "<payTo>",
      "value": "50000",
      "validAfter": "0",
      "validBefore": "<now + 300>",
      "nonce": "<32-byte hex>"
    }
  }
}
```

**3. Retry the same request** with the payload base64url-encoded into the
`PAYMENT-SIGNATURE` header. A settled call returns 200 plus a `PAYMENT-RESPONSE`
header and a `receipt` id in the body.

**Idempotency.** Send an `idempotency_key` and a replay of the same question
returns the stored response with `X-Idempotent-Replay: true` and is never charged
twice. Reusing a key for a *different* question is a 409.

**Errors follow the transport table:** 400 = invalid payment (malformed
payload, wrong network, underpaid), 402 = payment required / payment failed,
409 = idempotency-key reuse, 503 = upstream unavailable (and never billed).

### Test credentials

In `VERIFY_PAID_MODE=test` the gate accepts an HMAC credential instead of a
signature, so you can exercise the whole flow with no wallet and no chain. The
server can mint one for you:

```python
from service.payments import PaymentGate
gate = PaymentGate(mode="test", pay_to="0xYourReceiveAddress")
nonce, challenge = gate.new_challenge("/v1/verify/claims")
credential = gate.make_test_credential(nonce, "/v1/verify/claims")
```

Every test-mode ledger row is stamped `simulation` and can never be counted as
revenue.

---

## A short x402 explanation

x402 is a payments standard built on a status code HTTP already had: **402
Payment Required**. Instead of an API key and a monthly invoice, the server
answers an unpaid request with a *machine-readable bill* and the client pays it
by signing a transfer authorization.

The flow is four steps:

1. **Challenge.** The client calls the resource. The server returns `402` with
   `accepts[]` describing exactly what it will take: a scheme (`exact`), a
   network, an asset (a contract address, not a ticker), a `payTo` address, an
   amount, and a `resource` URL. Nothing is ambiguous, so no negotiation round
   trip is needed.
2. **Credential.** The client builds the payment payload — for `exact`, an
   EIP-3009 `transferWithAuthorization` authorization signed by the payer. The
   signature is the money order; the blockchain is the rail.
3. **Verify + settle.** The server (or a facilitator) checks that the signature
   recovers to the authorization's `from`, then settles the transfer on chain.
   Verification alone is never settlement — only a settled response carrying a
   transaction hash counts.
4. **Receipt.** The server returns the resource *and* a settlement receipt. The
   caller has proof of payment that is independent of the server's own logs.

Why it works for agents: the bill is data, not a login. A client can discover a
paid API, read its price, pay it, and consume it with no account, no dashboard,
and no human approving anything. And because the challenge is a normal HTTP
response, every existing HTTP client can be taught the protocol with one retry
branch.

The asset in this repo is USDC by contract address, because a symbol is not an
address and a payment that names the wrong asset is a payment to the wrong place:

```
base-sepolia  0x036CbD53842c5426634e7929541eC2318f3dCF7e
base          0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
```

---

## Environment variables

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `VERIFY_PAY_TO` | production | `""` | Your receive-only address. Funds land here. |
| `VERIFY_NETWORK` | no | `base-sepolia` (test) / `base` (production) | Chain to settle on. Known: `base-sepolia`, `base`. |
| `VERIFY_PAID_MODE` | no | `test` | `test` = HMAC credential, no chain. `production` = EIP-712 + facilitator settlement. |
| `VERIFY_PRICE_USD` | no | `0.05` | Price per call, USD. Converted to integer USDC atomic units (6 decimals). |
| `VERIFY_PUBLIC_BASE_URL` | no | `""` | Public origin. Used to build the absolute `resource` URL in challenges. A scheme-less value is prefixed with `https://`. |
| `X402_FACILITATOR_URL` | production | `""` | Facilitator base URL. Production mode calls `POST /verify` then `POST /settle`. |
| `VERIFY_ADMIN_TOKEN` | no | `""` | Gates `GET /internal/revenue`. Without it the route 404s. |
| `STRIPE_WEBHOOK_SECRET` | no | `""` | Verifies `POST /v1/stripe/webhook` signatures. |
| `VERIFY_STATE_DIR` | no | `.state` | Where nonces, idempotency rows, ops log, and the test secret live. |
| `VERIFY_LEDGER` | no | `~/.hermes/workspace/business/ledger.jsonl` | Append-only revenue ledger path. |
| `HERMES_HOME` | no | `~/.hermes` | Read-only location of `auth.json` / router config for the inference lane. |
| `VERIFY_TEST_SECRET` | no | generated | Test-mode HMAC secret. Generated and persisted under the state dir if unset. |

Secrets are read from the environment or from a local `verify.env` / `.env` file
in the service directory (loaded with `setdefault`, so the process environment
always wins). **Never commit a populated env file.**

---

## Repository layout

```
service/
  __init__.py     version + product statement
  app.py          HTTP surface: routes, 402 gate, idempotency, ledger wiring
  payments.py     x402 v1 gate: challenge, credential parse, verify, settle, receipts
  models.py       pydantic wire schemas (request/response)
  verifier.py     verification engine + SSRF-guarded fetcher
  extractor.py    deterministic URL -> markdown extraction
  ledger.py       append-only revenue ledger
  nous.py         inference client for the verification model
install.sh        venv + dependencies + .env bootstrap
requirements.txt
.env.example
LICENSE
```

---

## Notes and limits

- **Test mode is not a sandbox for production.** Test credentials are HMAC and
  never touch a chain; production credentials are EIP-712 and are settled by a
  facilitator. A test-mode row can never be counted as revenue.
- **Verification is not settlement.** Production mode calls the facilitator's
  `/verify` and then `/settle`. Only a settled response carrying a transaction
  hash produces a production receipt.
- **Replay protection is nonce-based and persistent.** The same nonce can never
  buy a second answer, whether or not the first request succeeded.
- **A failure is never billed.** Upstream or extraction failures are recorded
  in the ledger at price 0.
- This starter is a reference implementation, not a hardened payment system.
  Review the ledger, nonce, and facilitator paths before relying on it for real
  money.
