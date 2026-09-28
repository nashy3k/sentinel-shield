# SentinelShield-PII

> Production-ready PII masking & audit proxy built with Python + FastAPI.

---

## Architecture

```
                         ┌──────────────────────────────────────┐
                         │          SentinelShield-PII          │
                         │              (FastAPI)               │
                         │                                      │
  Caller / Client        │  ┌────────────┐  ┌────────────────┐  │
 ────────────────►  POST │  │ /v1/       │  │  sanitizer.py  │  │
  raw JSON payload       │  │ sanitize   ├─►│                │  │
                         │  └─────┬──────┘  │  • NRIC regex  │  │
                         │        │         │  • Email mask   │  │
  ◄────────────────      │  ┌─────▼──────┐  │  • CC + Luhn   │  │
  sanitized JSON +       │  │ /v1/       │  │  • Bearer tok. │  │
  entity counts +        │  │ proxy      │  │  • Phone mask  │  │
  latency_ms             │  └─────┬──────┘  └───────┬────────┘  │
                         │        │                 │           │
                         │  ┌─────▼──────┐          │           │
                         │  │  httpx     │◄──────────┘           │
                         │  │  forward   │  sanitized body only  │
                         │  └─────┬──────┘                       │
                         │        │                              │
                         └────────┼──────────────────────────────┘
                                  │
                                  ▼ sanitized JSON (PII stripped)
                         ┌─────────────────┐
                         │  Upstream API   │
                         │  (any endpoint) │
                         └─────────────────┘

  GET /v1/audit  ─────►  In-memory breach metrics & event trail
```

---

## Quick Start

```bash
# 1. Install dependencies
pip install fastapi uvicorn httpx pytest

# 2. Run the server
uvicorn app:app --reload --port 8000

# 3. Run the test suite
pytest test_sentinel.py -v
```

---

## API Reference

### `POST /v1/sanitize`

Accepts a raw JSON payload and returns the sanitized version together with
entity-detection counts and processing latency.

**Request:**
```bash
curl -X POST http://localhost:8000/v1/sanitize \
  -H "Content-Type: application/json" \
  -d '{
    "user": {
      "name": "Nash Ahmad",
      "ic": "900101-14-5678",
      "email": "nash.ahmad@company.com",
      "card": "4532015112830366",
      "phone": "+60123456789",
      "token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    }
  }'
```

**Response:**
```json
{
  "sanitized": {
    "user": {
      "name": "Nash Ahmad",
      "ic": "[MASKED-NRIC-5678]",
      "email": "n*******d@company.com",
      "card": "[MASKED-CC-0366]",
      "phone": "[MASKED-PHONE]",
      "token": "Bearer [MASKED-TOKEN]"
    }
  },
  "entities_detected": {
    "NRIC": 1,
    "EMAIL": 1,
    "CREDIT_CARD": 1,
    "PHONE": 1,
    "BEARER_TOKEN": 1
  },
  "total_redactions": 5,
  "latency_ms": 0.412
}
```

---

### `POST /v1/proxy`

Sanitizes the payload **before** forwarding it to the upstream service
specified in the `X-Target-URL` header. The upstream never receives raw PII.

**Request:**
```bash
curl -X POST http://localhost:8000/v1/proxy \
  -H "Content-Type: application/json" \
  -H "X-Target-URL: https://api.example.com/ingest" \
  -d '{
    "record": {
      "nric": "010203-04-9999",
      "email": "admin@corp.my"
    }
  }'
```

**Response:** Proxied upstream response (status code and body relayed as-is).

---

### `GET /v1/audit`

Returns aggregated breach metrics across all intercepted requests.

**Request:**
```bash
curl http://localhost:8000/v1/audit
```

**Response:**
```json
{
  "total_breach_events": 12,
  "pii_type_totals": {
    "NRIC": 7,
    "EMAIL": 9,
    "CREDIT_CARD": 3,
    "PHONE": 4,
    "BEARER_TOKEN": 2
  },
  "events_by_endpoint": {
    "/v1/sanitize": 10,
    "/v1/proxy": 2
  },
  "events_by_target": {
    "https://api.example.com/ingest": 2
  },
  "recent_events": [ "...last 20 breach events..." ]
}
```

---

## PII Detection Rules

| Pattern | Regex / Rule | Replacement |
|---|---|---|
| Malaysian NRIC (dashed) | `\d{6}-\d{2}-\d{4}` | `[MASKED-NRIC-xxxx]` |
| Malaysian NRIC (plain) | `\d{12}` | `[MASKED-NRIC-xxxx]` |
| Email | RFC 5321 local-part | `f***t@domain.com` |
| Credit Card | 13–19 digits + Luhn check | `[MASKED-CC-xxxx]` |
| Bearer Token | `Bearer ey…` | `Bearer [MASKED-TOKEN]` |
| API Key | `sk-…` (8+ chars) | `[MASKED-API-KEY]` |
| Malaysian Phone | `+601x…` / `01x-…` | `[MASKED-PHONE]` |
| International Phone | E.164 `+1–9…` | `[MASKED-PHONE]` |

---

## Enterprise Compliance Relevance

### PDPA (Personal Data Protection Act 2010 — Malaysia)
The **Personal Data Protection Act 2010** governs the processing of personal
data in commercial transactions. SentinelShield-PII directly supports
PDPA compliance by:

- **Data minimisation (s.6):** Stripping NRIC, phone, and email from payloads
  before they reach downstream services that do not require them.
- **Security (s.9):** Preventing PII from appearing in server logs, message
  queues, and third-party API calls.
- **Audit trail:** The `/v1/audit` endpoint provides evidence that PII
  interception controls are active, supporting periodic compliance reviews.

### GDPR (General Data Protection Regulation — EU)
SentinelShield-PII supports GDPR obligations for organisations operating
in or serving EU residents:

- **Article 25 — Data Protection by Design and by Default:** The proxy layer
  enforces sanitisation at the point of transmission, not as an afterthought.
- **Article 32 — Security of Processing:** Credit card (PCI-DSS) masking and
  bearer-token redaction prevent credential leakage across service boundaries.
- **Article 5(1)(c) — Data Minimisation:** Only the minimum necessary data
  reaches upstream APIs.
- **Recital 83 — Pseudonymisation:** Format-preserving masking (last-4 NRIC,
  first/last email char) supports pseudonymisation use-cases while retaining
  structural context.

---

## Project Structure

```
sentinel-shield/
├── sanitizer.py        # Core PII regex engine + Luhn validator
├── app.py              # FastAPI gateway (sanitize / proxy / audit)
├── test_sentinel.py    # Pytest unit & integration tests
├── README.md           # This file
└── BOB_USAGE.md        # IBM Bob AI-assisted generation notes
```

---

## License

MIT — see `LICENSE` for details.
