"""PayloadRegistry — register, organize, and query safe payloads."""

from __future__ import annotations

from ghostmirror.models.payload_profile import PayloadCategory
from ghostmirror.modules.payloads.models import PayloadDefinition
from ghostmirror.modules.payloads.payload_sets import get_default_payloads
from ghostmirror.modules.payloads.safety import SafetyPolicy


class PayloadRegistry:
    """Central registry for safe payloads.

    Responsibilities:
    - Register and unregister payloads
    - List payloads by category
    - Search payloads by id
    - Validate all payloads against the safety policy
    """

    def __init__(self) -> None:
        self._payloads: dict[str, PayloadDefinition] = {}

    def register(self, payload: PayloadDefinition) -> None:
        """Register a single payload definition."""
        allowed, _ = SafetyPolicy().validate(payload)
        if not allowed:
            raise ValueError(
                f"Não é possível registrar payload inseguro: {payload.id}"
            )
        self._payloads[payload.id] = payload

    def register_many(self, payloads: list[PayloadDefinition]) -> None:
        """Register multiple payload definitions."""
        for p in payloads:
            self.register(p)

    def register_defaults(self) -> None:
        """Register all default safe payload sets."""
        self.register_many(get_default_payloads())

    def unregister(self, payload_id: str) -> None:
        """Remove a payload from the registry by id."""
        self._payloads.pop(payload_id, None)

    def get_by_id(self, payload_id: str) -> PayloadDefinition | None:
        """Look up a payload by its unique id."""
        return self._payloads.get(payload_id)

    def list_by_category(
        self, category: PayloadCategory
    ) -> list[PayloadDefinition]:
        """Return all payloads for a given category."""
        return [p for p in self._payloads.values() if p.category == category]

    def list_all(self) -> list[PayloadDefinition]:
        """Return all registered payloads."""
        return list(self._payloads.values())

    def list_categories(self) -> list[PayloadCategory]:
        """Return all distinct categories currently registered."""
        seen: set[PayloadCategory] = set()
        for p in self._payloads.values():
            seen.add(p.category)
        return sorted(seen, key=lambda c: c.value)

    def count(self) -> int:
        """Return the total number of registered payloads."""
        return len(self._payloads)

    def validate_all(self) -> tuple[bool, str]:
        """Validate all registered payloads against the safety policy."""
        return SafetyPolicy.is_registry_valid(self.list_all())

    def clear(self) -> None:
        """Remove all payloads from the registry."""
        self._payloads.clear()
