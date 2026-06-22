from __future__ import annotations

from enum import Enum


class BountySeverity(str, Enum):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class BountyPriority(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    P5 = "P5"
