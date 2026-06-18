"""Loader for JSON-based threat intelligence and risk definitions."""

from __future__ import annotations

import json
from pathlib import Path

from ghostmirror.core.logger import get_logger
from ghostmirror.models.technology_risk import TechnologyRisk

logger = get_logger()


class KnowledgeBase:
    """Manages dynamic loading of threat intelligence signatures from JSON files."""

    JSON_FILES = [
        "servers.json",
        "cms.json",
        "technologies.json",
        "frameworks.json",
        "databases.json",
    ]

    def __init__(self, knowledge_dir: Path | str | None = None) -> None:
        if knowledge_dir:
            self.knowledge_dir = Path(knowledge_dir)
        else:
            self.knowledge_dir = Path(__file__).parent.parent.parent / "knowledge"

        self.definitions: dict[str, dict] = {}
        self.load()

    def load(self) -> None:
        """Load all JSON files in the knowledge directory into definitions dict."""
        self.definitions.clear()
        if not self.knowledge_dir.exists():
            logger.error("KNOWLEDGE_DIR_MISSING path={}", self.knowledge_dir)
            return

        for filename in self.JSON_FILES:
            file_path = self.knowledge_dir / filename
            if not file_path.exists():
                logger.warning("KNOWLEDGE_FILE_MISSING path={}", file_path)
                continue

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                # Merge into definitions using lower-cased keys for case-insensitive lookup
                for tech, info in data.items():
                    # Preserve standard name in data dictionary if needed
                    info["standard_name"] = tech
                    self.definitions[tech.lower()] = info
                
                logger.info("KNOWLEDGE_FILE_LOADED file={} keys={}", filename, len(data))
            except Exception as exc:
                logger.error("KNOWLEDGE_LOAD_FAILED file={} error={}", filename, exc)

    def get_technology_risk(self, name: str, confidence: float = 1.0) -> TechnologyRisk | None:
        """Finds threat definitions and returns a TechnologyRisk model.

        Parameters
        ----------
        name : str
            The technology name (e.g. Apache, WordPress)
        confidence : float
            The detection confidence score (0.0 to 1.0)

        Returns
        -------
        TechnologyRisk | None
            The populated risk model or None if not defined.
        """
        clean_name = name.strip()
        key = clean_name.lower()
        
        info = self.definitions.get(key)
        if not info:
            return None

        return TechnologyRisk(
            technology=info.get("standard_name", clean_name),
            category=info.get("category", "UNKNOWN"),
            risk_level=info.get("risk_level", "LOW"),
            attack_surface=info.get("attack_surface", []),
            recommended_scans=info.get("recommended_scans", []),
            common_exposures=info.get("common_exposures", []),
            confidence=confidence,
        )
