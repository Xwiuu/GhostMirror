"""SafetyPolicy — validates payload safety, blocks destructive payloads."""

from __future__ import annotations

from ghostmirror.models.payload_profile import SafetyLevel
from ghostmirror.modules.payloads.models import PayloadDefinition


class SafetyPolicy:
    """Enforces security guardrails for payload execution.

    Blocks:
    - Payloads marked as destructive
    - Payloads with safety_level == BLOCKED
    - Payloads with requires_confirmation (gated by explicit approval)
    """

    def __init__(self, confirm_sensitive: bool = False) -> None:
        self.confirm_sensitive = confirm_sensitive
        self._confirmation_cache: set[str] = set()

    def validate(self, payload: PayloadDefinition) -> tuple[bool, str | None]:
        """Validate a payload against the safety policy.

        Returns (is_allowed, reason_if_blocked).
        """
        if payload.destructive:
            return False, "Payload marcado como destrutivo — bloqueado pelo SafetyPolicy"

        if payload.safety_level == SafetyLevel.BLOCKED:
            return False, (
                f"Payload {payload.id} possui safety_level=BLOCKED — "
                f"bloqueado pelo SafetyPolicy"
            )

        if payload.requires_confirmation and not self.confirm_sensitive:
            return False, (
                f"Payload {payload.id} requer confirmação manual. "
                f"Use --confirm-sensitive para permitir."
            )

        if payload.requires_confirmation and payload.id not in self._confirmation_cache:
            return False, f"Payload {payload.id} aguardando confirmação manual."

        return True, None

    def confirm_payload(self, payload_id: str) -> None:
        """Mark a payload as confirmed for execution."""
        self._confirmation_cache.add(payload_id)

    def reset(self) -> None:
        """Clear all confirmation cache entries."""
        self._confirmation_cache.clear()

    @staticmethod
    def check_payload_value(value: str) -> bool:
        """Static check: return False if the payload value is potentially dangerous."""
        dangerous_patterns = [
            "/etc/passwd",
            "/etc/shadow",
            "/proc/self/environ",
            "169.254.169.254",
            "metadata.google.internal",
            "metadata.amazonaws.com",
            "rm -rf",
            "DROP TABLE",
            "DROP DATABASE",
            "exec(",
            "system(",
            "eval(",
            "os.system",
            "subprocess",
            "socket.",
        ]
        value_lower = value.lower()
        for pattern in dangerous_patterns:
            if pattern in value_lower:
                return False
        return True

    @staticmethod
    def is_registry_valid(registry: list[PayloadDefinition]) -> tuple[bool, str]:
        """Validate an entire registry of payloads."""
        for p in registry:
            allowed, reason = SafetyPolicy().validate(p)
            if not allowed and p.destructive:
                return False, (
                    f"Payload destrutivo encontrado no registry: "
                    f"{p.id} — {reason}"
                )
            if p.safety_level == SafetyLevel.BLOCKED:
                return False, (
                    f"Payload BLOCKED encontrado no registry: "
                    f"{p.id} — {reason}"
                )
            if not SafetyPolicy.check_payload_value(p.value):
                return False, (
                    f"Payload {p.id} contém valor perigoso: {p.value!r}"
                )
        return True, "Registry válido e seguro"
