"""Integration models representing external tool results and port findings."""

from ghostmirror.integrations.models.result import ToolExecutionResult
from ghostmirror.integrations.models.port_finding import PortFinding

__all__ = [
    "ToolExecutionResult",
    "PortFinding",
]
