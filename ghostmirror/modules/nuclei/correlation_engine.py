"""Correlation Engine for cross-referencing scan findings with prior intelligence profiles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.nuclei_result import NucleiResult
from ghostmirror.modules.models.finding import FindingModel

logger = get_logger()


class NucleiCorrelationEngine:
    """Correlates scan results with prior Technology and CVE intelligence profiles."""

    @staticmethod
    def correlate(
        project_path: Path,
        results: list[NucleiResult],
        findings: list[FindingModel],
    ) -> int:
        """Enriches standard findings with correlation intelligence.

        If a finding corresponds to a previously suspected CVE or technology,
        updates the finding's description and title to reflect CONFIRMED status or technology match.

        Parameters
        ----------
        project_path : Path
            Project root directory.
        results : list[NucleiResult]
            List of parsed Nuclei scan results.
        findings : list[FindingModel]
            List of mapped standard FindingModels to mutate/enrich.

        Returns
        -------
        int
            Count of correlated findings.
        """
        correlated_count = 0

        profiles_dir = project_path / "profiles"
        cve_intel_file = profiles_dir / "cve_intelligence.json"
        tech_profile_file = profiles_dir / "technology_profile.json"

        # 1. Load CVE Intelligence Matches
        suspected_cves: set[str] = set()
        if cve_intel_file.exists():
            try:
                with open(cve_intel_file, "r", encoding="utf-8") as f:
                    cve_data = json.load(f)
                
                # Check the matches or findings from sprint 7
                for finding in cve_data.get("findings") or []:
                    # Extract CVE-ID if title contains it (e.g. CVE-2021-41773)
                    title = finding.get("title", "")
                    for word in title.split():
                        if word.startswith("CVE-"):
                            # Clean up characters like brackets or colons
                            cve_id = word.strip("[]():,")
                            suspected_cves.add(cve_id)
            except Exception as exc:
                logger.warning("Failed to load CVE intelligence matches for correlation: {}", exc)

        # 2. Load Technology Profile
        detected_techs: set[str] = set()
        if tech_profile_file.exists():
            try:
                with open(tech_profile_file, "r", encoding="utf-8") as f:
                    tech_data = json.load(f)
                for tech in tech_data.get("technologies") or []:
                    name = tech.get("name")
                    if name:
                        detected_techs.add(name.lower())
            except Exception as exc:
                logger.warning("Failed to load Technology Profile for correlation: {}", exc)

        # 3. Correlate Nuclei scan results with findings
        for finding in findings:
            # Locate original parsed result matching this template or CVE
            matching_result: NucleiResult | None = None
            for res in results:
                # Basic lookup mapping
                cve_match = res.cve and res.cve in finding.title
                template_match = res.template_id in finding.evidence
                if cve_match or template_match:
                    matching_result = res
                    break

            if not matching_result:
                continue

            correlated = False
            correlation_notes = []

            # Check CVE Match
            if matching_result.cve and matching_result.cve in suspected_cves:
                correlated = True
                correlation_notes.append(
                    f"Match Confidence: CONFIRMED\n"
                    f"Vulnerabilidade anteriormente prevista no CVE Intelligence Engine: {matching_result.cve}"
                )
                # Elevate standard title prefix if confirmed
                if "Nuclei Detection:" in finding.title:
                    finding.title = finding.title.replace("Nuclei Detection:", "Confirmed Vulnerability:")

            # Check Technology Match
            # Check if any tag or template id contains a detected technology name
            tech_match_name = None
            for tech_name in detected_techs:
                in_tags = any(tech_name in tag.lower() for tag in matching_result.tags)
                in_id = tech_name in matching_result.template_id.lower()
                in_desc = matching_result.description and tech_name in matching_result.description.lower()
                if in_tags or in_id or in_desc:
                    tech_match_name = tech_name
                    break

            if tech_match_name:
                correlated = True
                correlation_notes.append(
                    f"Match de Tecnologia: {tech_match_name.upper()}\n"
                    f"Atividade detectada correlaciona-se com a tecnologia ativa identificada no technology_profile.json."
                )

            # Append correlation details to finding description if correlated
            if correlated:
                correlated_count += 1
                finding.description += "\n\n### Correlação de Inteligência (GhostMirror)\n" + "\n".join(correlation_notes)

        logger.info("NUCLEI_CORRELATION_COMPLETE findings_correlated={}", correlated_count)
        return correlated_count
