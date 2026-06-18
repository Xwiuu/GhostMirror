"""Tests for SafetyPolicy."""

from __future__ import annotations

from ghostmirror.models.payload_profile import PayloadCategory, SafetyLevel
from ghostmirror.modules.payloads.models import PayloadDefinition
from ghostmirror.modules.payloads.safety import SafetyPolicy


def test_validate_safe_payload() -> None:
    policy = SafetyPolicy()
    payload = PayloadDefinition(
        id="gm_test",
        name="Test",
        category=PayloadCategory.XSS_REFLECTION,
        description="Safe",
        value="<script>alert(1)</script>",
        safety_level=SafetyLevel.SAFE_REFLECTION,
    )
    allowed, reason = policy.validate(payload)
    assert allowed
    assert reason is None


def test_validate_destructive_blocked() -> None:
    policy = SafetyPolicy()
    payload = PayloadDefinition(
        id="gm_destructive",
        name="Destructive",
        category=PayloadCategory.XSS_REFLECTION,
        description="Bad",
        value="rm -rf /",
        destructive=True,
        safety_level=SafetyLevel.SAFE_REFLECTION,
    )
    allowed, reason = policy.validate(payload)
    assert not allowed
    assert "destrutivo" in reason.lower()


def test_validate_blocked_level() -> None:
    policy = SafetyPolicy()
    payload = PayloadDefinition(
        id="gm_blocked",
        name="Blocked",
        category=PayloadCategory.XSS_REFLECTION,
        description="Blocked",
        value="test",
        safety_level=SafetyLevel.BLOCKED,
    )
    allowed, reason = policy.validate(payload)
    assert not allowed
    assert "blocked" in reason.lower()


def test_validate_confirmation_required_without_flag() -> None:
    policy = SafetyPolicy(confirm_sensitive=False)
    payload = PayloadDefinition(
        id="gm_sensitive",
        name="Sensitive",
        category=PayloadCategory.XSS_REFLECTION,
        description="Needs confirmation",
        value="test",
        safety_level=SafetyLevel.MANUAL_CONFIRMATION_REQUIRED,
        requires_confirmation=True,
    )
    allowed, reason = policy.validate(payload)
    assert not allowed
    assert "confirmação" in reason.lower()


def test_validate_confirmation_required_with_flag() -> None:
    policy = SafetyPolicy(confirm_sensitive=True)
    payload = PayloadDefinition(
        id="gm_sensitive",
        name="Sensitive",
        category=PayloadCategory.XSS_REFLECTION,
        description="Needs confirmation",
        value="test",
        safety_level=SafetyLevel.MANUAL_CONFIRMATION_REQUIRED,
        requires_confirmation=True,
    )
    policy.confirm_payload("gm_sensitive")
    allowed, reason = policy.validate(payload)
    assert allowed
    assert reason is None


def test_confirm_payload() -> None:
    policy = SafetyPolicy(confirm_sensitive=True)
    policy.confirm_payload("gm_test")
    payload = PayloadDefinition(
        id="gm_test",
        name="Test",
        category=PayloadCategory.XSS_REFLECTION,
        description="Test",
        value="test",
        safety_level=SafetyLevel.MANUAL_CONFIRMATION_REQUIRED,
        requires_confirmation=True,
    )
    allowed, _ = policy.validate(payload)
    assert allowed


def test_check_payload_value_safe() -> None:
    assert SafetyPolicy.check_payload_value("<script>alert(1)</script>")
    assert SafetyPolicy.check_payload_value("'")
    assert SafetyPolicy.check_payload_value("{{7*7}}")
    assert SafetyPolicy.check_payload_value("../ghostmirror_probe")


def test_check_payload_value_dangerous() -> None:
    assert not SafetyPolicy.check_payload_value("/etc/passwd")
    assert not SafetyPolicy.check_payload_value("169.254.169.254")
    assert not SafetyPolicy.check_payload_value("metadata.google.internal")
    assert not SafetyPolicy.check_payload_value("rm -rf /")


def test_is_registry_valid_ok() -> None:
    payloads = [
        PayloadDefinition(
            id="gm_ok1",
            name="OK1",
            category=PayloadCategory.XSS_REFLECTION,
            description="Safe",
            value="<test>",
            safety_level=SafetyLevel.SAFE_REFLECTION,
        ),
    ]
    valid, msg = SafetyPolicy.is_registry_valid(payloads)
    assert valid


def test_is_registry_valid_with_destructive() -> None:
    payloads = [
        PayloadDefinition(
            id="gm_bad",
            name="Bad",
            category=PayloadCategory.XSS_REFLECTION,
            description="Destructive",
            value="test",
            destructive=True,
            safety_level=SafetyLevel.SAFE_REFLECTION,
        ),
    ]
    valid, msg = SafetyPolicy.is_registry_valid(payloads)
    assert not valid
    assert "destrutivo" in msg.lower()


def test_reset_policy() -> None:
    policy = SafetyPolicy(confirm_sensitive=True)
    policy.confirm_payload("gm_a")
    policy.reset()
    payload = PayloadDefinition(
        id="gm_a",
        name="A",
        category=PayloadCategory.XSS_REFLECTION,
        description="A",
        value="test",
        safety_level=SafetyLevel.MANUAL_CONFIRMATION_REQUIRED,
        requires_confirmation=True,
    )
    allowed, _ = policy.validate(payload)
    assert not allowed


def test_dangerous_value_blocked_in_registry() -> None:
    payloads = [
        PayloadDefinition(
            id="gm_danger",
            name="Danger",
            category=PayloadCategory.PATH_TRAVERSAL_INDICATOR,
            description="/etc/passwd attempt",
            value="/etc/passwd",
            safety_level=SafetyLevel.PASSIVE,
        ),
    ]
    valid, msg = SafetyPolicy.is_registry_valid(payloads)
    assert not valid
    assert "perigoso" in msg.lower()
