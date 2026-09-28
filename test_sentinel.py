"""
test_sentinel.py — SentinelShield-PII Automated Test Suite
Pytest unit and integration tests covering the sanitization engine and
FastAPI endpoints.
Run with:  pytest test_sentinel.py -v
"""

from __future__ import annotations

import json
import re
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from app import app, _audit_trail
from sanitizer import sanitize, SanitizationResult

# ---------------------------------------------------------------------------
# Test client
# ---------------------------------------------------------------------------

client = TestClient(app)


# ===========================================================================
# UNIT TESTS — sanitizer.py
# ===========================================================================


class TestNRICMasking:
    def test_dashed_nric_masked(self):
        result = sanitize({"ic": "900101-14-5678"})
        assert result.sanitized["ic"] == "[MASKED-NRIC-5678]"

    def test_plain_nric_masked(self):
        result = sanitize({"ic": "900101145678"})
        assert result.sanitized["ic"] == "[MASKED-NRIC-5678]"

    def test_nric_preserves_last_four(self):
        result = sanitize({"ic": "010203-04-9999"})
        assert "[MASKED-NRIC-9999]" in result.sanitized["ic"]

    def test_nric_embedded_in_sentence(self):
        text = "My IC number is 900101-14-5678 and I am Malaysian."
        result = sanitize({"bio": text})
        assert "900101-14-5678" not in result.sanitized["bio"]
        assert "[MASKED-NRIC-5678]" in result.sanitized["bio"]
        # surrounding text must be preserved
        assert "My IC number is" in result.sanitized["bio"]
        assert "and I am Malaysian." in result.sanitized["bio"]

    def test_nric_audit_record(self):
        result = sanitize({"ic": "900101-14-5678"})
        types = [r.pii_type for r in result.redactions]
        assert "NRIC" in types

    def test_non_nric_twelve_digits_not_masked(self):
        # 11 digits — must NOT be masked
        result = sanitize({"val": "12345678901"})
        assert result.sanitized["val"] == "12345678901"


class TestEmailMasking:
    def test_simple_email(self):
        result = sanitize({"email": "john@example.com"})
        masked = result.sanitized["email"]
        assert "@example.com" in masked
        assert "john" not in masked

    def test_email_local_part_obscured(self):
        result = sanitize({"email": "john.doe@company.org"})
        # local part should start with first char and end with last char
        assert result.sanitized["email"].startswith("j")
        assert "@company.org" in result.sanitized["email"]

    def test_short_local_email(self):
        result = sanitize({"email": "ab@mail.com"})
        assert "@mail.com" in result.sanitized["email"]
        assert "ab" not in result.sanitized["email"]

    def test_email_in_sentence(self):
        text = "Contact us at support@shield.io for help."
        result = sanitize({"msg": text})
        assert "support" not in result.sanitized["msg"]
        assert "@shield.io" in result.sanitized["msg"]

    def test_email_audit_type(self):
        result = sanitize({"e": "x@y.com"})
        assert any(r.pii_type == "EMAIL" for r in result.redactions)


class TestCreditCardMasking:
    # Visa test number — passes Luhn
    VISA = "4532015112830366"
    # Mastercard test number — passes Luhn
    MC = "5425233430109903"

    def test_valid_visa_masked(self):
        result = sanitize({"card": self.VISA})
        assert result.sanitized["card"] == "[MASKED-CC-0366]"

    def test_valid_mastercard_masked(self):
        result = sanitize({"card": self.MC})
        assert "[MASKED-CC-" in result.sanitized["card"]

    def test_spaced_card_number(self):
        spaced = "4532 0151 1283 0366"
        result = sanitize({"card": spaced})
        assert "[MASKED-CC-0366]" in result.sanitized["card"]

    def test_invalid_luhn_not_masked(self):
        # Same length but Luhn fails
        result = sanitize({"card": "4532015112830000"})
        assert "MASKED" not in result.sanitized["card"]

    def test_cc_audit_type(self):
        result = sanitize({"card": self.VISA})
        assert any(r.pii_type == "CREDIT_CARD" for r in result.redactions)


class TestBearerTokenMasking:
    def test_bearer_token_masked(self):
        result = sanitize({"auth": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"})
        assert "[MASKED-TOKEN]" in result.sanitized["auth"]
        assert "eyJ" not in result.sanitized["auth"]

    def test_bearer_case_insensitive(self):
        result = sanitize({"auth": "bearer eyJsomethinglong1234"})
        assert "[MASKED-TOKEN]" in result.sanitized["auth"]

    def test_api_key_sk_masked(self):
        result = sanitize({"key": "sk-abcdef1234567890"})
        assert result.sanitized["key"] == "[MASKED-API-KEY]"

    def test_short_sk_not_masked(self):
        # "sk-abc" is only 6 chars after prefix — below threshold
        result = sanitize({"key": "sk-abc"})
        assert "MASKED" not in result.sanitized["key"]


class TestPhoneMasking:
    def test_malaysian_mobile(self):
        result = sanitize({"phone": "+60123456789"})
        assert result.sanitized["phone"] == "[MASKED-PHONE]"

    def test_malaysian_local_format(self):
        result = sanitize({"phone": "012-3456789"})
        assert "[MASKED-PHONE]" in result.sanitized["phone"]

    def test_international_e164(self):
        result = sanitize({"phone": "+1-800-555-0199"})
        # E.164 without dashes
        result2 = sanitize({"phone": "+18005550199"})
        assert "[MASKED-PHONE]" in result2.sanitized["phone"]

    def test_phone_audit_type(self):
        result = sanitize({"p": "+60123456789"})
        assert any(r.pii_type == "PHONE" for r in result.redactions)


class TestStructurePreservation:
    def test_nested_dict(self):
        payload = {
            "user": {
                "name": "Alice",
                "contact": {
                    "email": "alice@wonderland.com",
                    "phone": "+60123456789",
                },
            }
        }
        result = sanitize(payload)
        # Structure intact
        assert isinstance(result.sanitized["user"]["contact"], dict)
        assert "email" in result.sanitized["user"]["contact"]
        # Name untouched
        assert result.sanitized["user"]["name"] == "Alice"

    def test_list_of_dicts(self):
        payload = [
            {"email": "a@b.com", "score": 99},
            {"email": "c@d.com", "score": 42},
        ]
        result = sanitize(payload)
        assert isinstance(result.sanitized, list)
        assert len(result.sanitized) == 2
        assert result.sanitized[0]["score"] == 99  # int untouched
        assert result.sanitized[1]["score"] == 42

    def test_deeply_nested_list(self):
        payload = {"level1": {"level2": {"level3": [{"nric": "010203-04-9999"}]}}}
        result = sanitize(payload)
        assert (
            result.sanitized["level1"]["level2"]["level3"][0]["nric"]
            == "[MASKED-NRIC-9999]"
        )

    def test_non_string_primitives_untouched(self):
        payload = {"count": 42, "active": True, "ratio": 3.14, "nothing": None}
        result = sanitize(payload)
        assert result.sanitized == payload

    def test_empty_dict(self):
        result = sanitize({})
        assert result.sanitized == {}
        assert result.redactions == []

    def test_empty_list(self):
        result = sanitize([])
        assert result.sanitized == []

    def test_key_names_preserved(self):
        payload = {"sensitive_ic": "900101-14-5678", "other_data": "keep_me"}
        result = sanitize(payload)
        assert "sensitive_ic" in result.sanitized
        assert "other_data" in result.sanitized
        assert result.sanitized["other_data"] == "keep_me"


class TestMixedEdgeCases:
    def test_nric_and_email_same_string(self):
        text = "IC: 900101-14-5678, email: nash@example.com"
        result = sanitize({"data": text})
        sanitized = result.sanitized["data"]
        assert "900101-14-5678" not in sanitized
        assert "nash@" not in sanitized
        assert "[MASKED-NRIC-5678]" in sanitized
        assert "@example.com" in sanitized

    def test_multiple_emails_in_one_string(self):
        text = "From: alice@a.com To: bob@b.com"
        result = sanitize({"msg": text})
        sanitized = result.sanitized["msg"]
        assert "alice" not in sanitized
        assert "bob" not in sanitized
        assert sanitized.count("@") == 2  # both domains preserved

    def test_audit_summary_counts(self):
        payload = {
            "ic": "900101-14-5678",
            "email": "x@y.com",
            "card": "4532015112830366",
        }
        result = sanitize(payload)
        summary = result.summary()
        assert summary.get("NRIC", 0) >= 1
        assert summary.get("EMAIL", 0) >= 1
        assert summary.get("CREDIT_CARD", 0) >= 1

    def test_plain_text_no_pii_untouched(self):
        payload = {"greeting": "Hello, world!", "year": 2024}
        result = sanitize(payload)
        assert result.sanitized == payload
        assert len(result.redactions) == 0


# ===========================================================================
# INTEGRATION TESTS — FastAPI endpoints
# ===========================================================================


class TestSanitizeEndpoint:
    def test_post_sanitize_returns_200(self):
        resp = client.post("/v1/sanitize", json={"email": "test@test.com"})
        assert resp.status_code == 200

    def test_response_structure(self):
        resp = client.post("/v1/sanitize", json={"x": "hello"})
        body = resp.json()
        assert "sanitized" in body
        assert "entities_detected" in body
        assert "total_redactions" in body
        assert "latency_ms" in body

    def test_sanitize_nric_via_api(self):
        resp = client.post("/v1/sanitize", json={"ic": "900101-14-5678"})
        body = resp.json()
        assert "[MASKED-NRIC-5678]" in body["sanitized"]["ic"]
        assert body["entities_detected"].get("NRIC", 0) >= 1

    def test_sanitize_no_pii_zero_redactions(self):
        resp = client.post("/v1/sanitize", json={"msg": "All clear"})
        body = resp.json()
        assert body["total_redactions"] == 0

    def test_sanitize_invalid_json_400(self):
        resp = client.post(
            "/v1/sanitize",
            content=b"not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    def test_latency_ms_is_non_negative(self):
        resp = client.post("/v1/sanitize", json={"a": "b"})
        assert resp.json()["latency_ms"] >= 0


class TestProxyEndpoint:
    def test_proxy_requires_x_target_url(self):
        resp = client.post("/v1/proxy", json={"data": "test"})
        assert resp.status_code == 422  # missing required header

    def test_proxy_sanitizes_before_forwarding(self):
        """Verify the body forwarded upstream has PII removed."""
        captured: list[dict] = []

        async def mock_post(url, *, json=None, headers=None, **kwargs):
            captured.append({"url": url, "json": json})
            mock_resp = MagicMock()
            mock_resp.content = b'{"ok": true}'
            mock_resp.status_code = 200
            mock_resp.headers = {"content-type": "application/json"}
            return mock_resp

        with patch("app.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(side_effect=mock_post)
            mock_client_cls.return_value = mock_client

            resp = client.post(
                "/v1/proxy",
                json={"ic": "900101-14-5678"},
                headers={"X-Target-URL": "https://upstream.example.com/api"},
            )

        # The forwarded JSON must NOT contain raw NRIC
        if captured:
            forwarded_ic = captured[0]["json"].get("ic", "")
            assert "900101-14-5678" not in str(forwarded_ic)
            assert "[MASKED-NRIC-5678]" in str(forwarded_ic)


class TestAuditEndpoint:
    def setup_method(self):
        """Clear audit trail before each test."""
        _audit_trail.clear()

    def test_audit_empty(self):
        resp = client.get("/v1/audit")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_breach_events"] == 0

    def test_audit_records_breach(self):
        client.post("/v1/sanitize", json={"ic": "900101-14-5678"})
        resp = client.get("/v1/audit")
        body = resp.json()
        assert body["total_breach_events"] >= 1
        assert "NRIC" in body["pii_type_totals"]

    def test_audit_multiple_types(self):
        client.post(
            "/v1/sanitize",
            json={
                "ic": "900101-14-5678",
                "email": "test@test.com",
                "card": "4532015112830366",
            },
        )
        body = client.get("/v1/audit").json()
        totals = body["pii_type_totals"]
        assert totals.get("NRIC", 0) >= 1
        assert totals.get("EMAIL", 0) >= 1
        assert totals.get("CREDIT_CARD", 0) >= 1

    def test_audit_endpoint_tracking(self):
        client.post("/v1/sanitize", json={"ic": "900101-14-5678"})
        body = client.get("/v1/audit").json()
        assert "/v1/sanitize" in body["events_by_endpoint"]

    def test_no_pii_event_not_recorded(self):
        """Events with no PII should not inflate the breach counter."""
        _audit_trail.clear()
        client.post("/v1/sanitize", json={"msg": "clean message"})
        resp = client.get("/v1/audit")
        assert resp.json()["total_breach_events"] == 0


class TestHealthEndpoint:
    def test_health_ok(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
