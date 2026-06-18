"""Template Selector for automated intelligence-based Nuclei template filtering."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()


class NucleiTemplateSelector:
    """Selects and maps relevant Nuclei templates based on project profiles."""

    @staticmethod
    def select_templates(
        project_path: Path,
        knowledge_dir: Path | None = None,
    ) -> list[str]:
        """Auto-selects templates from prior sprint intelligence files.

        Looks for:
        - `recommended_nuclei_templates.json` in recommendations/
        - `technology_profile.json` in profiles/
        - `cve_intelligence.json` in profiles/

        If not found or some matches exist, maps technology profile + CVE matches
        to corresponding nuclei paths.

        Parameters
        ----------
        project_path : Path
            The project root directory.
        knowledge_dir : Path | None
            Custom directory containing vulnerability map databases.

        Returns
        -------
        list[str]
            List of selected Nuclei templates.
        """
        templates: set[str] = set()

        recommendations_dir = project_path / "recommendations"
        profiles_dir = project_path / "profiles"

        # 1. Load recommended_nuclei_templates.json if exists
        rec_templates_file = recommendations_dir / "recommended_nuclei_templates.json"
        if rec_templates_file.exists():
            try:
                with open(rec_templates_file, "r", encoding="utf-8") as f:
                    rec_data = json.load(f)
                recs = rec_data.get("templates") or []
                for t in recs:
                    templates.add(t)
                logger.info("Loaded {} templates from recommended_nuclei_templates.json", len(recs))
            except Exception as exc:
                logger.warning("Failed to load recommended_nuclei_templates.json: {}", exc)

        # 2. Map from technology_profile.json
        tech_profile_file = profiles_dir / "technology_profile.json"
        
        # Load template map from knowledge base
        if knowledge_dir is None:
            knowledge_dir = Path(__file__).parent.parent.parent / "knowledge" / "cves"
        
        nuclei_map_file = knowledge_dir / "nuclei_template_map.json"
        nuclei_map: dict[str, Any] = {}
        if nuclei_map_file.exists():
            try:
                with open(nuclei_map_file, "r", encoding="utf-8") as f:
                    nuclei_map = json.load(f)
            except Exception as exc:
                logger.error("Failed to load nuclei template map from knowledge base: {}", exc)

        if tech_profile_file.exists() and nuclei_map:
            try:
                with open(tech_profile_file, "r", encoding="utf-8") as f:
                    tech_data = json.load(f)
                
                techs = tech_data.get("technologies") or []
                tech_mapping = nuclei_map.get("technologies") or {}
                
                # Check for technologies
                for tech in techs:
                    name = tech.get("name")
                    if name in tech_mapping:
                        templates.add(tech_mapping[name])
                        
                # Check for exposures
                exposures = nuclei_map.get("exposures") or {}
                
                # Database check
                has_db = any(
                    t.get("category", "").upper() == "DATABASE" or
                    t.get("name", "").lower() in ["redis", "mongodb", "mysql", "postgresql", "postgres"]
                    for t in techs
                )
                if has_db and "databases" in exposures:
                    templates.add(exposures["databases"])

                # Config check
                has_waf = any(
                    t.get("category", "").upper() == "WAF" or
                    t.get("name", "").lower() == "cloudflare"
                    for t in techs
                )
                if not has_waf and "configs" in exposures:
                    templates.add(exposures["configs"])

            except Exception as exc:
                logger.warning("Failed to map from technology_profile.json: {}", exc)

        # 3. Map CVEs from cve_intelligence.json
        cve_intel_file = profiles_dir / "cve_intelligence.json"
        if cve_intel_file.exists() and nuclei_map:
            try:
                with open(cve_intel_file, "r", encoding="utf-8") as f:
                    cve_data = json.load(f)
                
                findings = cve_data.get("findings") or []
                cve_mapping = nuclei_map.get("cves") or {}
                
                for finding in findings:
                    title = finding.get("title", "")
                    # Extract CVE-ID from title
                    for cve_id in cve_mapping:
                        if cve_id in title:
                            templates.add(cve_mapping[cve_id])
            except Exception as exc:
                logger.warning("Failed to map CVEs from cve_intelligence.json: {}", exc)

        # Filter out empty paths or templates that didn't map
        selected = sorted(list({t for t in templates if t}))
        logger.info("Total templates selected: {}", len(selected))
        return selected
