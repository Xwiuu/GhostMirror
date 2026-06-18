"""GhostMirror — Internal Pentest Automation Platform.

GhostMirror is an **internal** platform used exclusively by our software house
for authorized security audits, attack-surface mapping and reporting. It is not
a public tool and must only ever be pointed at assets covered by a formally
approved engagement scope.
"""

from __future__ import annotations

__all__ = ["__version__", "BUILD_DATE"]

#: Single source of truth for the application version.
__version__: str = "1.0-alpha"

BUILD_DATE: str = "2026.06.18"
