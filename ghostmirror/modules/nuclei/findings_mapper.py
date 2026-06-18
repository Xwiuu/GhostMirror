"""Mapper class to convert NucleiResult findings to standard FindingModel format."""

from __future__ import annotations

from ghostmirror.models.nuclei_result import NucleiResult
from ghostmirror.modules.models.finding import FindingModel, FindingSeverity


class NucleiFindingsMapper:
    """Handles mapping of NucleiResult objects into standard Project FindingModels."""

    @staticmethod
    def map_to_finding(result: NucleiResult, target: str) -> FindingModel:
        """Converts a NucleiResult item into a standard FindingModel.

        Normalizes severity to uppercase CRITICAL, HIGH, MEDIUM, LOW, INFO.

        Parameters
        ----------
        result : NucleiResult
            Parsed Nuclei result item.
        target : str
            Project target address.

        Returns
        -------
        FindingModel
            Constructed finding model instance.
        """
        # 1. Normalize Severity
        sev_raw = result.severity.upper()
        if sev_raw == "CRITICAL":
            severity = FindingSeverity.CRITICAL
        elif sev_raw == "HIGH":
            severity = FindingSeverity.HIGH
        elif sev_raw == "MEDIUM":
            severity = FindingSeverity.MEDIUM
        elif sev_raw == "LOW":
            severity = FindingSeverity.LOW
        else:
            severity = FindingSeverity.INFO

        # 2. Build Title
        cve_suffix = f" [{result.cve}]" if result.cve else ""
        title = f"Nuclei Detection: {result.template_name}{cve_suffix}"

        # 3. Build Description
        desc_lines = []
        if result.description:
            desc_lines.append(result.description)
        else:
            desc_lines.append(f"Vulnerabilidade identificada via template Nuclei: {result.template_id}")
        
        if result.cve:
            desc_lines.append(f"CVE ID: {result.cve}")
        if result.cvss is not None:
            desc_lines.append(f"CVSS Score: {result.cvss}")
        
        description = "\n".join(desc_lines)

        # 4. Build Evidence
        evidence_lines = [
            f"Template ID: {result.template_id}",
            f"Host Scaneado: {result.host}",
            f"IP: {result.ip or 'Desconhecido'}",
            f"Ponto de correspondência: {result.matched_at}",
        ]
        if result.matcher_name:
            evidence_lines.append(f"Filtro correspondido (Matcher): {result.matcher_name}")
        if result.curl_command:
            evidence_lines.append(f"Comando curl para reproduzir:\n{result.curl_command}")

        evidence = "\n".join(evidence_lines)

        # 5. Build Recommendation
        recs = ["Revisar os logs e as referências associadas para confirmar a vulnerabilidade."]
        if result.reference:
            recs.append("Referências adicionais:")
            for ref in result.reference[:3]:
                recs.append(f"- {ref}")
        
        recommendation = "\n".join(recs)

        return FindingModel(
            title=title,
            description=description,
            severity=severity,
            target=target,
            evidence=evidence,
            recommendation=recommendation,
        )
