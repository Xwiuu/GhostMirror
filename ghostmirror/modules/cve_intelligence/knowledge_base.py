"""Knowledge base loader for the CVE Intelligence Engine."""

from __future__ import annotations

import json
from pathlib import Path
from ghostmirror.core.logger import get_logger
from ghostmirror.models.cve import CVEModel

logger = get_logger()


class CVEKnowledgeBase:
    """Manages local vulnerability database loading and querying."""

    def __init__(self, knowledge_dir: Path | str | None = None) -> None:
        if knowledge_dir is None:
            # Standard path: ghostmirror/knowledge/cves
            knowledge_dir = Path(__file__).parent.parent.parent / "knowledge" / "cves"
        self.knowledge_dir = Path(knowledge_dir)

        self.cves: list[CVEModel] = []
        self.aliases_path = self.knowledge_dir / "technology_aliases.json"
        self.rules_path = self.knowledge_dir / "version_rules.json"
        self.nuclei_path = self.knowledge_dir / "nuclei_template_map.json"

        self.version_rules: dict = {}
        self.nuclei_map: dict = {}

        self.load()

    def load(self) -> None:
        """Loads all database components from knowledge directory."""
        cves_path = self.knowledge_dir / "known_cves.json"
        if cves_path.exists():
            try:
                with open(cves_path, "r", encoding="utf-8") as f:
                    raw_cves = json.load(f)
                self.cves = [CVEModel.model_validate(c) for c in raw_cves]
                logger.info("Loaded {} CVEs from {}", len(self.cves), cves_path)
            except Exception as exc:
                logger.error("Failed to load known CVEs from {}: {}", cves_path, exc)
        else:
            logger.warning("known_cves.json not found in {}", self.knowledge_dir)

        if self.rules_path.exists():
            try:
                with open(self.rules_path, "r", encoding="utf-8") as f:
                    self.version_rules = json.load(f)
            except Exception as exc:
                logger.error("Failed to load version rules: {}", exc)

        if self.nuclei_path.exists():
            try:
                with open(self.nuclei_path, "r", encoding="utf-8") as f:
                    self.nuclei_map = json.load(f)
            except Exception as exc:
                logger.error("Failed to load nuclei templates map: {}", exc)

    def get_cves_for_product(self, product: str) -> list[CVEModel]:
        """Retrieve all CVE models matching a normalized product name."""
        return [c for c in self.cves if c.affected_product.lower() == product.lower()]
