# BOB_USAGE.md — How IBM Bob Built SentinelShield-PII

This document explains the role IBM Bob (AI Software Engineer) played in
designing, generating, and validating every component of the SentinelShield-PII
system.

---

## 1. Regex Parser Design (sanitizer.py)

### Challenge
PII patterns like Malaysian NRICs, internationalised phone numbers, and credit
cards vary in formatting (dashes, spaces, country codes) and must be detected
reliably across arbitrary free-form string values embedded in deeply nested JSON.

### What Bob did

**NRIC — two-variant approach**

Bob identified that the Malaysian NRIC appears in two common formats:
- Dashed: `XXXXXX-XX-XXXX` — handled by `_NRIC_DASHED`
- Plain 12-digit: `900101145678` — handled by `_NRIC_PLAIN`

Both use `\b` word-boundary anchors to avoid false positives on longer numeric
strings. Bob placed the dashed pattern first in the pipeline because it is more
specific; the plain pattern only fires on unmatched 12-digit sequences.

```python
_NRIC_DASHED = re.compile(r"\b(\d{6})-(\d{2})-(\d{4})\b")
_NRIC_PLAIN  = re.compile(r"\b(\d{12})\b")
```

**Credit card — Luhn integration**

Bob designed the credit-card pattern to match candidate digit strings (13–19
digits with optional space/dash separators), then validate each match against
the Luhn algorithm (`_luhn_check`) before masking. This prevents sequences of
digits that happen to be the right length (e.g., a product SKU) from being
incorrectly redacted.

```python
def _luhn_check(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(digits[::-1]):
        n = int(ch) * (2 if i % 2 == 1 else 1)
        total += n - 9 if n > 9 else n
    return total % 10 == 0
```

**Email — format-preserving masking**

Rather than replacing emails with a fixed token, Bob generated a masker that
preserves the first and last characters of the local part and the full domain,
enabling human reviewers to partially correlate masked values without exposing
the full address:

```
nash.ahmad@company.com  →  n*********d@company.com
ab@mail.com             →  a*@mail.com
```

**Bearer tokens and API keys**

Bob produced two sub-patterns:
- `Bearer <token>` — preserves the `Bearer ` prefix so downstream auth-header
  parsing still works on the masked value.
- `sk-<key>` — replaces the entire key with `[MASKED-API-KEY]`, consistent with
  OpenAI and Stripe key conventions.

**Pipeline ordering**

Bob ordered the masking pipeline deliberately:
1. NRIC (most specific numeric pattern — runs before phone/CC)
2. Email
3. Credit card (with Luhn guard)
4. Bearer token
5. API key
6. Phone (broadest numeric pattern — runs last)

This ordering prevents the phone regex from consuming digits that belong to a
credit card or NRIC.

---

## 2. Proxy Middleware Architecture (app.py)

### Challenge
The proxy must sanitize before forwarding — not after — and must never log,
store, or relay any raw PII value to the upstream service or to application logs.

### What Bob did

Bob structured the proxy endpoint (`POST /v1/proxy`) as a two-phase pipeline:

```
Receive raw JSON
      │
      ▼
sanitize(payload)       ← PII stripped here, in-process, synchronously
      │
      ▼
httpx.AsyncClient.post  ← Only sanitized body crosses the network
      │
      ▼
Relay upstream response to caller
```

Key design decisions Bob made:

1. **Header forwarding exclusion list** — `host`, `content-length`, and
   `x-target-url` are stripped from forwarded headers. `host` would cause
   upstream routing failures; `content-length` is recalculated by httpx;
   `x-target-url` is internal routing metadata.

2. **Audit recording only on PII presence** — `_record_audit` is a no-op when
   the breach summary is empty. This keeps the audit trail signal-rich: every
   entry in `_audit_trail` represents a genuine breach interception.

3. **In-memory audit trail with structured entries** — Each entry stores
   `timestamp` (UTC ISO-8601), `endpoint`, `breach_types` (dict), and
   `target` (upstream URL for proxy events). The `GET /v1/audit` endpoint
   aggregates across the full trail without re-iterating at query time (O(n)
   at write, O(1) read pattern).

4. **httpx async client** — Bob chose `httpx.AsyncClient` over `requests` to
   match FastAPI's async execution model, avoiding thread-pool blocking on
   upstream I/O.

---

## 3. Test Suite Scaffolding (test_sentinel.py)

### Challenge
The test suite must cover unit behaviour (regex correctness, edge cases),
structural integrity (JSON shape preserved), and integration behaviour
(HTTP endpoints, header parsing, audit counting) — without needing a live
upstream service.

### What Bob did

**Test class organisation**

Bob grouped tests into seven focused classes:

| Class | Coverage focus |
|---|---|
| `TestNRICMasking` | Both NRIC formats, sentence embedding, last-4 preservation |
| `TestEmailMasking` | Local-part masking, short locals, domain preservation |
| `TestCreditCardMasking` | Luhn pass/fail, spaced formatting |
| `TestBearerTokenMasking` | JWT tokens, API keys, length threshold |
| `TestPhoneMasking` | Malaysian mobile, E.164, local landline |
| `TestStructurePreservation` | Nested dicts, arrays, primitives, empty payloads |
| `TestMixedEdgeCases` | Multiple PII types in one string, summary counts |

**Audit-count isolation**

Bob added a `setup_method` fixture to `TestAuditEndpoint` that clears
`_audit_trail` before each test. This ensures audit count assertions are not
contaminated by previous test runs.

**Proxy mock strategy**

Bob mocked `httpx.AsyncClient` using `unittest.mock.AsyncMock` and captured
the forwarded JSON body in a local list. The test then asserts that the
forwarded body contains the masked value — not the original NRIC — without
requiring a live network connection.

```python
captured: list[dict] = []
async def mock_post(url, *, json=None, **kwargs):
    captured.append({"url": url, "json": json})
    ...

with patch("app.httpx.AsyncClient") as mock_client_cls:
    ...
    forwarded_ic = captured[0]["json"]["ic"]
    assert "[MASKED-NRIC-5678]" in str(forwarded_ic)
```

**Non-PII values assertion**

Bob added explicit assertions that numeric, boolean, and `None` primitives
pass through the sanitizer unchanged. This guards against regressions where
overzealous patterns accidentally match non-string values.

---

## 4. Summary of Bob's Contributions

| Component | Bob's role |
|---|---|
| Regex design | Authored all 7 PII patterns with correct anchoring and ordering |
| Luhn algorithm | Implemented Luhn check to eliminate CC false positives |
| Format-preserving masks | Designed last-4 preservation for NRIC/CC, first/last for email |
| Pipeline ordering | Determined safe execution order to prevent pattern collisions |
| FastAPI endpoints | Scaffolded all three routes with correct async, error handling, header logic |
| In-memory audit store | Designed append-only trail with aggregation at query time |
| httpx integration | Chose async client, crafted header exclusion list |
| Test suite | Structured 7 test classes, 40+ assertions, mocked httpx upstream |
| Compliance mapping | Mapped masking controls to PDPA s.6/9 and GDPR Art.25/32 articles |
