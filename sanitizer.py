"""
sanitizer.py — SentinelShield-PII Core Sanitization Engine
Recursively sanitizes arbitrary JSON payloads, masking PII patterns
while preserving structure, key names, and value types.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# Malaysian NRIC: XXXXXX-XX-XXXX  or  12 continuous digits
_NRIC_DASHED = re.compile(r"\b(\d{6})-(\d{2})-(\d{4})\b")
_NRIC_PLAIN = re.compile(r"\b(\d{12})\b")

# Email addresses
_EMAIL = re.compile(
    r"\b([A-Za-z0-9._%+\-]{1,64})(@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b"
)

# Credit cards — 13-19 digits optionally separated by spaces or dashes
_CC_RAW = re.compile(r"\b(\d[ \-]?){13,19}\d\b")

# Bearer tokens and common API key prefixes
_BEARER = re.compile(r"(Bearer\s+)([\w\-\.]{8,})", re.IGNORECASE)
_API_KEY = re.compile(r"\b(sk-[A-Za-z0-9]{8,})\b")

# Phone numbers: Malaysian (+60 / 01x) and generic international (+XX...)
# All branches require an explicit prefix so bare digit strings are not matched.
_PHONE = re.compile(
    r"(\+60[\-\s]?1[0-9][\-\s]?\d{3,4}[\-\s]?\d{4,5}"  # +60 1x…
    r"|\b01[0-9][\-\s]?\d{3,4}[\-\s]?\d{4,5}"            # 01x… (local MY)
    r"|\+[1-9]\d{6,14}"                                   # International E.164
    r"|\b0\d{1,2}[\-\s]\d{3,4}[\-\s]\d{4,5}\b)"          # Local landline with separator
)


# ---------------------------------------------------------------------------
# Luhn check helper (credit card validation)
# ---------------------------------------------------------------------------

def _luhn_check(digits: str) -> bool:
    """Return True if *digits* (string of digits) passes the Luhn algorithm."""
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Audit record
# ---------------------------------------------------------------------------

@dataclass
class Redaction:
    pii_type: str
    field_path: str
    original_snippet: str   # first 6 chars + "…" — never log full value


@dataclass
class SanitizationResult:
    sanitized: Any
    redactions: list[Redaction] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in self.redactions:
            counts[r.pii_type] = counts.get(r.pii_type, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Individual masking helpers
# ---------------------------------------------------------------------------

def _snippet(value: str) -> str:
    """Return a safe short snippet for audit logs (never full PII)."""
    return value[:6] + "…" if len(value) > 6 else value + "…"


def _mask_nric(text: str, path: str, redactions: list[Redaction]) -> str:
    def _replace_dashed(m: re.Match) -> str:
        last4 = m.group(3)
        redactions.append(Redaction("NRIC", path, _snippet(m.group(0))))
        return f"[MASKED-NRIC-{last4}]"

    def _replace_plain(m: re.Match) -> str:
        last4 = m.group(1)[-4:]
        redactions.append(Redaction("NRIC", path, _snippet(m.group(0))))
        return f"[MASKED-NRIC-{last4}]"

    text = _NRIC_DASHED.sub(_replace_dashed, text)
    text = _NRIC_PLAIN.sub(_replace_plain, text)
    return text


def _mask_email(text: str, path: str, redactions: list[Redaction]) -> str:
    def _replace(m: re.Match) -> str:
        local: str = m.group(1)
        domain: str = m.group(2)
        if len(local) <= 2:
            masked = local[0] + "*"
        else:
            masked = local[0] + "*" * (len(local) - 2) + local[-1]
        redactions.append(Redaction("EMAIL", path, _snippet(m.group(0))))
        return masked + domain

    return _EMAIL.sub(_replace, text)


def _mask_credit_card(text: str, path: str, redactions: list[Redaction]) -> str:
    def _replace(m: re.Match) -> str:
        raw = m.group(0)
        digits_only = re.sub(r"[ \-]", "", raw)
        if len(digits_only) < 13 or not _luhn_check(digits_only):
            return raw  # not a valid card — leave untouched
        last4 = digits_only[-4:]
        redactions.append(Redaction("CREDIT_CARD", path, _snippet(raw)))
        return f"[MASKED-CC-{last4}]"

    return _CC_RAW.sub(_replace, text)


def _mask_bearer(text: str, path: str, redactions: list[Redaction]) -> str:
    def _replace(m: re.Match) -> str:
        redactions.append(Redaction("BEARER_TOKEN", path, _snippet(m.group(2))))
        return m.group(1) + "[MASKED-TOKEN]"

    return _BEARER.sub(_replace, text)


def _mask_api_key(text: str, path: str, redactions: list[Redaction]) -> str:
    def _replace(m: re.Match) -> str:
        redactions.append(Redaction("API_KEY", path, _snippet(m.group(1))))
        return "[MASKED-API-KEY]"

    return _API_KEY.sub(_replace, text)


def _mask_phone(text: str, path: str, redactions: list[Redaction]) -> str:
    def _replace(m: re.Match) -> str:
        raw = m.group(0)
        redactions.append(Redaction("PHONE", path, _snippet(raw)))
        return "[MASKED-PHONE]"

    return _PHONE.sub(_replace, text)


# ---------------------------------------------------------------------------
# String-level pipeline
# ---------------------------------------------------------------------------

_PIPELINE = [
    _mask_nric,
    _mask_email,
    _mask_credit_card,
    _mask_bearer,
    _mask_api_key,
    _mask_phone,
]


def _sanitize_string(value: str, path: str, redactions: list[Redaction]) -> str:
    for fn in _PIPELINE:
        value = fn(value, path, redactions)
    return value


# ---------------------------------------------------------------------------
# Recursive sanitizer
# ---------------------------------------------------------------------------

def _sanitize_node(node: Any, path: str, redactions: list[Redaction]) -> Any:
    if isinstance(node, str):
        return _sanitize_string(node, path, redactions)

    if isinstance(node, dict):
        return {
            k: _sanitize_node(v, f"{path}.{k}" if path else k, redactions)
            for k, v in node.items()
        }

    if isinstance(node, list):
        return [
            _sanitize_node(item, f"{path}[{i}]", redactions)
            for i, item in enumerate(node)
        ]

    # int, float, bool, None — returned as-is
    return node


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def sanitize(payload: Any) -> SanitizationResult:
    """Sanitize *payload* (any JSON-serialisable value).

    Returns a :class:`SanitizationResult` containing the sanitized payload
    and a list of :class:`Redaction` records for the audit trail.
    """
    redactions: list[Redaction] = []
    sanitized = _sanitize_node(payload, "", redactions)
    return SanitizationResult(sanitized=sanitized, redactions=redactions)
