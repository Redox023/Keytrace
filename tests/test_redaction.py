"""Tests for keytrace.core.redaction."""
from keytrace.core.redaction import redact


def test_credit_card_redacted_when_luhn_valid():
    # 4242 4242 4242 4242 is a Stripe test card (Luhn valid)
    rep = redact("paying with 4242 4242 4242 4242 today")
    assert "[REDACTED:CREDIT_CARD]" in rep.text
    assert rep.counts.get("CREDIT_CARD") == 1


def test_credit_card_skipped_when_luhn_invalid():
    rep = redact("not a card: 1234 5678 9012 3456")
    assert "[REDACTED:CREDIT_CARD]" not in rep.text


def test_ssn_redacted():
    rep = redact("SSN 123-45-6789 do not log")
    assert "[REDACTED:SSN]" in rep.text


def test_jwt_redacted():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    rep = redact(f"token={jwt} bearer")
    assert "[REDACTED:JWT]" in rep.text


def test_aws_access_key_redacted():
    rep = redact("env: AKIAIOSFODNN7EXAMPLE")
    assert "[REDACTED:AWS_ACCESS_KEY]" in rep.text


def test_email_preserves_domain():
    rep = redact("contact alice@example.com please")
    assert "[REDACTED:EMAIL@example.com]" in rep.text
    assert "alice" not in rep.text


def test_pan_redacted():
    rep = redact("PAN ABCDE1234F is mine")
    assert "[REDACTED:PAN_IN]" in rep.text


def test_aadhaar_redacted():
    rep = redact("aadhaar 1234 5678 9012")
    assert "[REDACTED:AADHAAR_IN]" in rep.text


def test_clean_text_passes_through():
    rep = redact("hello world, nothing sensitive here")
    assert rep.text == "hello world, nothing sensitive here"
    assert rep.total == 0
