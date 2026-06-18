"""Tests for PayloadRegistry."""

from __future__ import annotations

import pytest

from ghostmirror.models.payload_profile import PayloadCategory, SafetyLevel
from ghostmirror.modules.payloads.models import PayloadDefinition
from ghostmirror.modules.payloads.registry import PayloadRegistry


@pytest.fixture()
def registry() -> PayloadRegistry:
    r = PayloadRegistry()
    r.register_defaults()
    return r


def test_register_and_count(registry: PayloadRegistry) -> None:
    assert registry.count() > 0


def test_get_by_id_found(registry: PayloadRegistry) -> None:
    p = registry.get_by_id("gm_xss_probe_001")
    assert p is not None
    assert p.id == "gm_xss_probe_001"
    assert p.category == PayloadCategory.XSS_REFLECTION


def test_get_by_id_not_found(registry: PayloadRegistry) -> None:
    assert registry.get_by_id("nonexistent") is None


def test_list_by_category(registry: PayloadRegistry) -> None:
    xss_payloads = registry.list_by_category(PayloadCategory.XSS_REFLECTION)
    assert len(xss_payloads) > 0
    for p in xss_payloads:
        assert p.category == PayloadCategory.XSS_REFLECTION


def test_list_all(registry: PayloadRegistry) -> None:
    all_p = registry.list_all()
    assert len(all_p) == registry.count()


def test_list_categories(registry: PayloadRegistry) -> None:
    cats = registry.list_categories()
    assert PayloadCategory.XSS_REFLECTION in cats
    assert PayloadCategory.SQL_ERROR_INDICATOR in cats
    assert PayloadCategory.OPEN_REDIRECT_INDICATOR in cats


def test_register_custom_payload(registry: PayloadRegistry) -> None:
    custom = PayloadDefinition(
        id="gm_custom_001",
        name="Custom Test Payload",
        category=PayloadCategory.XSS_REFLECTION,
        description="Custom test",
        value="<test>",
        safety_level=SafetyLevel.PASSIVE,
    )
    registry.register(custom)
    assert registry.get_by_id("gm_custom_001") is not None
    assert registry.count() > 0


def test_register_duplicate_overwrites(registry: PayloadRegistry) -> None:
    count_before = registry.count()
    dup = PayloadDefinition(
        id="gm_xss_probe_001",
        name="Overwritten",
        category=PayloadCategory.XSS_REFLECTION,
        description="Overwritten",
        value="<overwritten>",
        safety_level=SafetyLevel.PASSIVE,
    )
    registry.register(dup)
    assert registry.count() == count_before
    assert registry.get_by_id("gm_xss_probe_001").name == "Overwritten"


def test_unregister(registry: PayloadRegistry) -> None:
    registry.unregister("gm_xss_probe_001")
    assert registry.get_by_id("gm_xss_probe_001") is None


def test_validate_all_ok(registry: PayloadRegistry) -> None:
    valid, msg = registry.validate_all()
    assert valid
    assert "válido" in msg.lower()


def test_clear(registry: PayloadRegistry) -> None:
    registry.clear()
    assert registry.count() == 0


def test_register_destructive_raises() -> None:
    reg = PayloadRegistry()
    destructive = PayloadDefinition(
        id="gm_harmful",
        name="Destructive",
        category=PayloadCategory.XSS_REFLECTION,
        description="Should be blocked",
        value="rm -rf /",
        destructive=True,
        safety_level=SafetyLevel.SAFE_REFLECTION,
    )
    with pytest.raises(ValueError, match="inseguro"):
        reg.register(destructive)


def test_register_blocked_raises() -> None:
    reg = PayloadRegistry()
    blocked = PayloadDefinition(
        id="gm_blocked",
        name="Blocked",
        category=PayloadCategory.XSS_REFLECTION,
        description="Should be blocked",
        value="test",
        safety_level=SafetyLevel.BLOCKED,
    )
    with pytest.raises(ValueError, match="inseguro"):
        reg.register(blocked)
