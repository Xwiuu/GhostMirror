"""Version comparison and CVE matcher engine."""

from __future__ import annotations

import re
from ghostmirror.core.logger import get_logger
from ghostmirror.models.cve import CVEModel
from ghostmirror.models.cve_match import CVEMatchModel
from ghostmirror.modules.cve_intelligence.knowledge_base import CVEKnowledgeBase
from ghostmirror.modules.cve_intelligence.normalizer import TechnologyNormalizer

logger = get_logger()


def parse_version(version_str: str | None) -> list[int | str]:
    """Parse version string into list of integers and strings for comparison.

    E.g. '8.5p1' -> [8, 5, 'p', 1]
    '1.23.2' -> [1, 23, 2]
    """
    if not version_str:
        return []

    # Replace commas, spaces, dashes with separator tokens or dots
    version_str = version_str.strip()
    parts = re.split(r'(\d+)', version_str)
    parsed: list[int | str] = []
    for p in parts:
        if not p or p in [".", "-", "_", " "]:
            continue
        if p.isdigit():
            parsed.append(int(p))
        else:
            parsed.append(p)
    return parsed


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings.

    Returns:
        -1 if v1 < v2
        1 if v1 > v2
        0 if v1 == v2
    """
    p1 = parse_version(v1)
    p2 = parse_version(v2)

    for el1, el2 in zip(p1, p2):
        if isinstance(el1, int) and isinstance(el2, int):
            if el1 < el2:
                return -1
            if el1 > el2:
                return 1
        elif isinstance(el1, str) and isinstance(el2, str):
            if el1 < el2:
                return -1
            if el1 > el2:
                return 1
        else:
            s1 = str(el1)
            s2 = str(el2)
            if s1 < s2:
                return -1
            if s1 > s2:
                return 1

    if len(p1) < len(p2):
        for el2 in p2[len(p1):]:
            if isinstance(el2, int) and el2 > 0:
                return -1
            if isinstance(el2, str):
                return -1
        return 0
    elif len(p1) > len(p2):
        for el1 in p1[len(p2):]:
            if isinstance(el1, int) and el1 > 0:
                return 1
            if isinstance(el1, str):
                return 1
        return 0

    return 0


def check_constraint(detected_version: str, constraint: str) -> bool:
    """Checks whether a detected version matches a single version constraint."""
    constraint = constraint.strip()
    if constraint.startswith(">="):
        return compare_versions(detected_version, constraint[2:]) >= 0
    elif constraint.startswith("<="):
        return compare_versions(detected_version, constraint[2:]) <= 0
    elif constraint.startswith(">"):
        return compare_versions(detected_version, constraint[1:]) > 0
    elif constraint.startswith("<"):
        return compare_versions(detected_version, constraint[1:]) < 0
    elif constraint.startswith("=="):
        return compare_versions(detected_version, constraint[2:]) == 0
    else:
        # Implicit ==
        return compare_versions(detected_version, constraint) == 0


def check_rule(detected_version: str, rule: str) -> bool:
    """Checks whether a version matches a version rule (supporting range: operator)."""
    rule = rule.strip()
    if rule.startswith("range:"):
        parts = rule[len("range:"):].split(",")
        return all(check_constraint(detected_version, p) for p in parts)
    else:
        return check_constraint(detected_version, rule)


def is_parseable_version(version_str: str | None) -> bool:
    """Returns True if the version contains digits, making it parseable."""
    if not version_str:
        return False
    return any(c.isdigit() for c in version_str)


class CVEVulnerabilityMatcher:
    """Evaluates detected technology versions against the CVE database."""

    def __init__(self, kb: CVEKnowledgeBase) -> None:
        self.kb = kb
        self.normalizer = TechnologyNormalizer(self.kb.aliases_path)

    def match_technology(self, target: str, name: str, detected_version: str | None) -> list[CVEMatchModel]:
        """Correlates a technology name and version with the CVE DB.

        Parameters
        ----------
        target : str
            Domain or IP of target.
        name : str
            Name of technology.
        detected_version : str | None
            Version detected.

        Returns
        -------
        list[CVEMatchModel]
            List of matched CVE results.
        """
        normalized_name = self.normalizer.normalize(name)
        cves = self.kb.get_cves_for_product(normalized_name)
        matches: list[CVEMatchModel] = []

        if not cves:
            return []

        for cve in cves:
            # 1. No version detected
            if not detected_version or detected_version.strip() in ("", "?", "unknown"):
                matches.append(
                    CVEMatchModel(
                        target=target,
                        technology=normalized_name,
                        detected_version=None,
                        matched_cve=cve,
                        match_confidence="POTENTIAL",
                        match_reason=(
                            f"Tecnologia '{normalized_name}' detectada sem versão. "
                            f"Existe potencial exposição para {cve.cve_id}."
                        ),
                        risk_level="MEDIUM",  # reduced for potential exposure
                        priority="MEDIUM",
                        recommended_action=(
                            "Executar varredura ativa ou auditoria de configuração local "
                            "para confirmar a versão instalada."
                        ),
                        recommended_scans=cve.fixed_versions,  # placeholder/future scans hint
                    )
                )
                continue

            # 2. Version is not parseable
            v_clean = detected_version.strip()
            if not is_parseable_version(v_clean):
                matches.append(
                    CVEMatchModel(
                        target=target,
                        technology=normalized_name,
                        detected_version=v_clean,
                        matched_cve=cve,
                        match_confidence="UNKNOWN",
                        match_reason=(
                            f"Versão '{v_clean}' não é parseável para comparação. "
                            f"Impossível confirmar vulnerabilidade {cve.cve_id}."
                        ),
                        risk_level="LOW",
                        priority="LOW",
                        recommended_action="Verificar manualmente a versão instalada no servidor.",
                        recommended_scans=[],
                    )
                )
                continue

            # 3. Check if it's a fixed version
            # E.g. if fixed rule is 2.4.50 (implying >=2.4.50), check if detected is fixed
            is_fixed = False
            for fixed_rule in cve.fixed_versions:
                if fixed_rule:
                    fixed_rule_clean = fixed_rule.strip()
                    if not any(fixed_rule_clean.startswith(op) for op in [">=", "<=", ">", "<", "=="]):
                        fixed_rule_clean = f">={fixed_rule_clean}"
                    try:
                        if check_rule(v_clean, fixed_rule_clean):
                            is_fixed = True
                            break
                    except Exception as exc:
                        logger.warning(
                            "Error comparing fixed rule {} against version {}: {}",
                            fixed_rule_clean, v_clean, exc
                        )

            # "Tecnologia com versão corrigida → não gerar CVE finding, apenas info opcional"
            # We skip generating matches for fixed versions.
            if is_fixed:
                continue

            # 4. Check if it matches affected versions criteria
            is_vulnerable = False
            matching_rule = ""
            for rule in cve.affected_versions:
                try:
                    if check_rule(v_clean, rule):
                        is_vulnerable = True
                        matching_rule = rule
                        break
                except Exception as exc:
                    logger.warning(
                        "Error comparing affected rule {} against version {}: {}",
                        rule, v_clean, exc
                    )

            if is_vulnerable:
                priority = cve.severity.upper()
                matches.append(
                    CVEMatchModel(
                        target=target,
                        technology=normalized_name,
                        detected_version=v_clean,
                        matched_cve=cve,
                        match_confidence="CONFIRMED",
                        match_reason=(
                            f"Versão detectada '{v_clean}' coincide com a regra de versão afetada "
                            f"'{matching_rule}' do {cve.cve_id}."
                        ),
                        risk_level=cve.severity.upper(),
                        priority=priority,
                        recommended_action=(
                            f"Atualizar o produto para a versão corrigida (ex: "
                            f"{', '.join(cve.fixed_versions)}) imediatamente."
                        ),
                        recommended_scans=[],
                    )
                )

        return matches
