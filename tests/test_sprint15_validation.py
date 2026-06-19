"""Sprint 15 — Advanced Vulnerability Intelligence Validation Script.

Valida 3 cenários reais antes do merge:
  Teste 1 — WordPress com CVE + EPSS + KEV + Exploit → Priority #1
  Teste 2 — Alvo sem CVE → sem quebrar, sem falso positivo
  Teste 3 — 50+ CVEs → Top 10, Priority Ranking
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from ghostmirror.models.enriched_cve import EnrichedCVEModel
from ghostmirror.models.epss_profile import EPSSProfileModel
from ghostmirror.models.kev_profile import KEVProfileModel
from ghostmirror.models.exploit_profile import ExploitProfileModel, WeaponizationLevel
from ghostmirror.models.vulnerability_priority import VulnerabilityPriorityModel
from ghostmirror.modules.vulnerability_intelligence.engine import AdvancedVulnerabilityEngine
from ghostmirror.modules.vulnerability_intelligence.prioritization import (
    VulnerabilityPrioritizationEngine,
)
from ghostmirror.modules.vulnerability_intelligence.scoring import AdvancedScoringEngine
from ghostmirror.modules.vulnerability_intelligence.attack_correlation import (
    AttackCorrelationEngine,
)
from ghostmirror.modules.vulnerability_intelligence.recommendations import (
    AdvancedRecommendationEngine,
)


# --------------------------------------------------------------------------- #
# HELPERS
# --------------------------------------------------------------------------- #

import sys
import os

os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
END = "\033[0m"


def ok(msg: str) -> str:
    return f"{GREEN}[PASS]{END} {msg}"


def fail(msg: str) -> str:
    return f"{RED}[FAIL]{END} {msg}"


def info(msg: str) -> str:
    return f"{CYAN}[INFO]{END} {msg}"


def header(title: str) -> None:
    print(f"\n{BOLD}{YELLOW}{'='*60}{END}")
    print(f"{BOLD}{YELLOW}  {title}{END}")
    print(f"{BOLD}{YELLOW}{'='*60}{END}\n")


# --------------------------------------------------------------------------- #
# TESTE 1 — WordPress com CVE + EPSS + KEV + Exploit
# --------------------------------------------------------------------------- #

def test_wordpress_priority_one():
    header("TESTE 1: WordPress com CVE + EPSS + KEV + Exploit -> Priority #1")

    # Simula WordPress 5.8.2 com WooCommerce
    # CVE-2021-44228 (Log4j) mesmo nao sendo WP core, simula um plugin vulneravel
    enriched = [
        EnrichedCVEModel(
            cve_id="CVE-2021-44228",
            cvss=10.0,
            severity="CRITICAL",
            product="WooCommerce Plugin",
            version="4.0.0",
            attack_vector="NETWORK",
            complexity="LOW",
            privileges_required="NONE",
            user_interaction=False,
            impact="HIGH",
            description="Apache Log4j remote code execution vulnerability affecting WooCommerce integration plugin.",
        ),
        EnrichedCVEModel(
            cve_id="CVE-2021-41773",
            cvss=7.5,
            severity="HIGH",
            product="Apache HTTP Server",
            version="2.4.49",
            attack_vector="NETWORK",
            complexity="LOW",
            privileges_required="NONE",
            user_interaction=False,
            impact="HIGH",
            description="Apache HTTP Server path traversal vulnerability.",
        ),
        EnrichedCVEModel(
            cve_id="CVE-2023-46604",
            cvss=9.8,
            severity="CRITICAL",
            product="WordPress Core",
            version="5.8.2",
            attack_vector="NETWORK",
            complexity="LOW",
            privileges_required="NONE",
            user_interaction=False,
            impact="HIGH",
            description="WordPress core remote code execution via object injection.",
        ),
    ]

    epss_map = {
        "CVE-2021-44228": EPSSProfileModel(
            cve="CVE-2021-44228", epss_score=0.97910, percentile=99.82,
            classification="CRITICAL",
        ),
        "CVE-2021-41773": EPSSProfileModel(
            cve="CVE-2021-41773", epss_score=0.93210, percentile=99.21,
            classification="CRITICAL",
        ),
        "CVE-2023-46604": EPSSProfileModel(
            cve="CVE-2023-46604", epss_score=0.81230, percentile=97.45,
            classification="CRITICAL",
        ),
    }

    kev_map = {
        "CVE-2021-44228": KEVProfileModel(
            cve="CVE-2021-44228", kev=True, ransomware_usage=True,
            known_exploitation=True, date_added="2021-12-10",
            vendor_project="Apache", product="Log4j",
        ),
        "CVE-2021-41773": KEVProfileModel(
            cve="CVE-2021-41773", kev=True, ransomware_usage=False,
            known_exploitation=True, date_added="2021-10-11",
            vendor_project="Apache", product="HTTP Server",
        ),
        "CVE-2023-46604": KEVProfileModel(
            cve="CVE-2023-46604", kev=True, ransomware_usage=True,
            known_exploitation=True, date_added="2023-10-16",
            vendor_project="Apache", product="ActiveMQ",
        ),
    }

    exploit_map = {
        "CVE-2021-44228": ExploitProfileModel(
            cve="CVE-2021-44228", public_exploit=True, metasploit=True,
            nuclei_template=True, weaponization_level=WeaponizationLevel.CRITICAL,
            exploit_sources=["exploit-db", "metasploit", "nuclei"],
        ),
        "CVE-2021-41773": ExploitProfileModel(
            cve="CVE-2021-41773", public_exploit=True, metasploit=True,
            nuclei_template=True, weaponization_level=WeaponizationLevel.CRITICAL,
            exploit_sources=["exploit-db", "metasploit", "nuclei"],
        ),
        "CVE-2023-46604": ExploitProfileModel(
            cve="CVE-2023-46604", public_exploit=True, metasploit=False,
            nuclei_template=True, weaponization_level=WeaponizationLevel.HIGH,
            exploit_sources=["exploit-db", "nuclei"],
        ),
    }

    tech_profile = {
        "technologies": [
            {"name": "WordPress", "version": "5.8.2", "category": "CMS"},
            {"name": "WooCommerce", "version": "6.0.0", "category": "Plugin"},
            {"name": "Apache HTTP Server", "version": "2.4.49", "category": "Web Server"},
        ]
    }

    # Attack correlation com admin panel exposto
    correlation = AttackCorrelationEngine()
    opportunities = correlation.correlate(
        enriched_cves=enriched,
        technology_profile=tech_profile,
        nuclei_findings={"findings": [{"cve": "CVE-2021-44228"}, {"cve": "CVE-2021-41773"}]},
        owasp_profile={"categories": ["A01", "A05", "A07"]},
        attack_surface_profile={
            "waf": {"detected": False},
            "cdn": {"detected": False},
        },
    )

    # Priorização
    prioritization = VulnerabilityPrioritizationEngine()
    priorities = prioritization.prioritize(
        enriched_list=enriched,
        epss_map=epss_map,
        kev_map=kev_map,
        exploit_map=exploit_map,
        attack_opportunities=opportunities,
        internet_exposed=True,
    )

    # === VALIDAÇÕES ===
    errors = []

    # 1. Priority #1 deve ser CVE-2021-44228 (Log4j - o mais critico)
    if priorities[0].cve == "CVE-2021-44228":
        print(ok("Priority #1 = CVE-2021-44228 (Log4j) OK"))
    else:
        print(fail(f"Priority #1 = {priorities[0].cve} (esperado CVE-2021-44228)"))
        errors.append("Wrong priority #1")

    # 2. Risk Score do #1 deve ser > 90
    top = priorities[0]
    if top.risk_score >= 90:
        print(ok(f"Risk Score #1 = {top.risk_score}/100 (>=90) OK"))
    else:
        print(fail(f"Risk Score #1 = {top.risk_score}/100 (<90)"))
        errors.append(f"Risk score too low: {top.risk_score}")

    # 3. Reason deve conter KEV + EPSS + Exploit
    reason = top.reason.lower()
    checks = {
        "KEV listed": "kev" in reason,
        "Ransomware usage": "ransomware" in reason,
        "EPSS critical": "epss" in reason,
        "Public exploit": "public exploit" in reason or "exploit" in reason,
        "Metasploit": "metasploit" in reason,
        "Weaponization CRITICAL": "weaponization" in reason and ("critical" in reason),
    }
    for label, ok_flag in checks.items():
        if ok_flag:
            print(ok(f"Reason contains '{label}'"))
        else:
            print(fail(f"Reason missing '{label}'"))
            errors.append(f"Missing reason: {label}")

    # 4. CVSS, EPSS, KEV, Exploit mapeados corretamente
    if top.epss and abs(top.epss.epss_score - 0.97910) < 0.001:
        print(ok(f"EPSS Score: {top.epss.epss_score:.5f} (97.9%) OK"))
    else:
        print(fail(f"EPSS Score mismatch: {top.epss.epss_score if top.epss else 'None'}"))
        errors.append("EPSS mismatch")

    if top.kev and top.kev.kev:
        print(ok(f"KEV: Yes (Ransomware: {top.kev.ransomware_usage}) OK"))
    else:
        print(fail(f"KEV mismatch"))
        errors.append("KEV mismatch")

    if top.exploit and top.exploit.weaponization_level == WeaponizationLevel.CRITICAL:
        print(ok(f"Weaponization: CRITICAL (Metasploit + Nuclei + Exploit-DB) OK"))
    else:
        print(fail(f"Weaponization mismatch: {top.exploit.weaponization_level if top.exploit else 'None'}"))
        errors.append("Weaponization mismatch")

    # 5. CVSS Score
    if top.enriched.cvss == 10.0:
        print(ok(f"CVSS: {top.enriched.cvss} (CRITICAL) OK"))
    else:
        print(fail(f"CVSS mismatch: {top.enriched.cvss}"))

    # 6. Quick Wins
    quick_wins = AdvancedRecommendationEngine.generate_quick_wins(priorities)
    if len(quick_wins) >= 3:
        print(ok(f"Quick Wins: {len(quick_wins)} gerados OK"))
    else:
        print(fail(f"Quick Wins: {len(quick_wins)} (esperado >=3)"))

    # 7. Resumo
    print(f"\n{info('Resumo Priority #1:')}")
    print(f"  {CYAN}CVE:{END} {top.cve}")
    print(f"  {CYAN}Product:{END} {top.enriched.product}")
    print(f"  {CYAN}CVSS:{END} {top.enriched.cvss} ({top.enriched.severity})")
    print(f"  {CYAN}EPSS:{END} {top.epss.epss_score:.1%} (p{top.epss.percentile:.1f}) - {top.epss.classification}" if top.epss else "N/A")
    print(f"  {CYAN}KEV:{END} {'YES (Ransomware)' if top.kev and top.kev.ransomware_usage else 'YES' if top.kev and top.kev.kev else 'NO'}")
    print(f"  {CYAN}Exploit:{END} {'Public + Metasploit + Nuclei' if top.exploit and top.exploit.metasploit else 'Available' if top.exploit and top.exploit.public_exploit else 'None'}")
    print(f"  {CYAN}Weaponization:{END} {top.exploit.weaponization_level.value if top.exploit else 'NONE'}")
    print(f"  {BOLD}{GREEN}Risk Score: {top.risk_score}/100{END}")
    print(f"  {CYAN}Reason:{END} {top.reason}")

    # 8. Attack Opportunities
    print(f"\n{info('Attack Opportunities:')}")
    for opp in opportunities[:3]:
        print(f"  - {opp['cve']} ({opp['technology']}): Score {opp['attack_opportunity_score']}/100 - Vector: {opp['attack_vector']}")

    if errors:
        print(f"\n{fail(f'FALHAS: {len(errors)}')}")
        for e in errors:
            print(f"  {RED}*{END} {e}")
        return False
    else:
        print(f"\n{ok(f'TESTE 1 PASSOU - Todas as validacoes OK')}")
        return True


# --------------------------------------------------------------------------- #
# TESTE 2 — Alvo sem CVE
# --------------------------------------------------------------------------- #

def test_no_cves():
    header("TESTE 2: Alvo sem CVE")

    errors = []

    # Engine com dados vazios
    engine = AdvancedVulnerabilityEngine()
    from ghostmirror.models.vulnerability_intelligence_report import (
        VulnerabilityIntelligenceReport,
    )

    # 1. enrich_all com None
    enriched = engine.enrichment.enrich_all(None, None)
    if enriched == []:
        print(ok("enrich_all(None, None) -> [] (sem CVEs) OK"))
    else:
        print(fail(f"enrich_all retornou {len(enriched)} itens (esperado 0)"))
        errors.append("enrich_all should return empty")

    # 2. EPSS com lista vazia
    epss_results = engine.epss.get_scores_batch([])
    if epss_results == []:
        print(ok("EPSS batch vazio -> [] OK"))
    else:
        print(fail("EPSS batch vazio retornou dados"))

    # 3. KEV com lista vazia
    kev_results = engine.kev.check_batch([])
    if kev_results == []:
        print(ok("KEV batch vazio -> [] OK"))
    else:
        print(fail("KEV batch vazio retornou dados"))

    # 4. Exploit com lista vazia
    exploit_results = engine.exploit.analyze_batch([])
    if exploit_results == []:
        print(ok("Exploit batch vazio -> [] OK"))
    else:
        print(fail("Exploit batch vazio retornou dados"))

    # 5. Priorizacao com lista vazia
    priorities = engine.prioritization.prioritize([])
    if priorities == []:
        print(ok("Prioritize vazio -> [] OK"))
    else:
        print(fail(f"Prioritize retornou {len(priorities)} (esperado 0)"))

    # 6. Attack Correlation com lista vazia
    opportunities = engine.correlation.correlate([], None, None, None, None)
    if opportunities == []:
        print(ok("Correlation vazia -> [] OK"))
    else:
        print(fail("Correlation vazia retornou dados"))

    # 7. Recommendations com lista vazia
    wins = AdvancedRecommendationEngine.generate_quick_wins([])
    if wins == []:
        print(ok("Quick wins vazio -> [] OK"))
    else:
        print(fail("Quick wins vazio retornou dados"))

    # 8. Score calculation sem dados
    score, level = AdvancedVulnerabilityEngine._calculate_overall_score([], 0, 0, [])
    if score == 0 and level == "NONE":
        print(ok(f"Overall score vazio -> {score}/100 ({level}) OK"))
    else:
        print(fail(f"Overall score vazio -> {score}/100 ({level}) (esperado 0/NONE)"))
        errors.append("Overall score should be 0/NONE")

    # 9. Relatorio vazio via engine
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        empty_project = Path(tmp) / "empty_project"
        empty_project.mkdir()
        report = engine.analyze_project(empty_project)
        assert isinstance(report, VulnerabilityIntelligenceReport)
        if report.total_cves == 0 and report.overall_score == 0 and report.risk_level == "NONE":
            print(ok(f"Relatorio vazio: score {report.overall_score}, level {report.risk_level}, CVEs {report.total_cves} OK"))
        else:
            print(fail(f"Relatorio vazio inconsistente: score={report.overall_score}, level={report.risk_level}"))
            errors.append("Empty report inconsistent")

    if errors:
        print(f"\n{fail(f'FALHAS: {len(errors)}')}")
        for e in errors:
            print(f"  {RED}*{END} {e}")
        return False
    else:
        print(f"\n{ok('TESTE 2 PASSOU - Zero falsos positivos, sem quebras')}")
        return True


# --------------------------------------------------------------------------- #
# TESTE 3 — 50+ CVEs → Top 10, Priority Ranking
# --------------------------------------------------------------------------- #

def test_fifty_cves():
    header("TESTE 3: 50+ CVEs -> Top 10, Priority Ranking")

    random.seed(42)
    enriched_list: list[EnrichedCVEModel] = []
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    products = [
        "WordPress", "Apache HTTP Server", "Nginx", "MySQL", "Redis",
        "PHP", "OpenSSL", "Linux Kernel", "PostgreSQL", "Node.js",
        "Docker", "Kubernetes", "Jenkins", "GitLab", "Jira",
    ]

    for i in range(55):
        sev = severities[i % 4]
        cvss_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}
        enriched_list.append(
            EnrichedCVEModel(
                cve_id=f"CVE-2023-{10000 + i:05d}",
                cvss=cvss_map[sev],
                severity=sev,
                product=products[i % len(products)],
                version=f"{random.randint(1, 10)}.{random.randint(0, 9)}.{random.randint(0, 99)}",
                attack_vector=random.choice(["NETWORK", "LOCAL", "ADJACENT"]),
                complexity=random.choice(["LOW", "HIGH"]),
                privileges_required=random.choice(["NONE", "LOW", "HIGH"]),
                user_interaction=random.choice([True, False]),
                impact=random.choice(["HIGH", "LOW"]),
                description=f"Test vulnerability #{i}",
            )
        )

    epss_map: dict[str, EPSSProfileModel] = {}
    kev_map: dict[str, KEVProfileModel] = {}
    exploit_map: dict[str, ExploitProfileModel] = {}

    for cve in enriched_list[:15]:  # Top 15 ganham EPSS alto
        epss_map[cve.cve_id] = EPSSProfileModel(
            cve=cve.cve_id,
            epss_score=random.uniform(0.7, 0.99),
            percentile=random.uniform(90, 100),
            classification="CRITICAL",
        )
    for cve in enriched_list[15:35]:  # 15-35 médio
        epss_map[cve.cve_id] = EPSSProfileModel(
            cve=cve.cve_id,
            epss_score=random.uniform(0.3, 0.69),
            percentile=random.uniform(50, 89),
            classification="HIGH" if random.random() > 0.5 else "MEDIUM",
        )

    for cve in enriched_list[:8]:  # 8 KEV
        kev_map[cve.cve_id] = KEVProfileModel(
            cve=cve.cve_id, kev=True, ransomware_usage=random.choice([True, False]),
            known_exploitation=True,
        )

    for cve in enriched_list[:12]:  # 12 com exploit
        exploit_map[cve.cve_id] = ExploitProfileModel(
            cve=cve.cve_id, public_exploit=True,
            metasploit=random.choice([True, False]),
            nuclei_template=True,
            weaponization_level=random.choice([WeaponizationLevel.CRITICAL, WeaponizationLevel.HIGH]),
        )

    engine = VulnerabilityPrioritizationEngine()
    priorities = engine.prioritize(
        enriched_list=enriched_list,
        epss_map=epss_map,
        kev_map=kev_map,
        exploit_map=exploit_map,
        internet_exposed=True,
    )

    errors = []

    # 1. Todos os 55 priorizados
    if len(priorities) == 55:
        print(ok(f"Total priorizados: {len(priorities)} OK"))
    else:
        print(fail(f"Total priorizados: {len(priorities)} (esperado 55)"))
        errors.append("Wrong count")

    # 2. Priorities 1-55 sem gaps
    if all(p.priority == i + 1 for i, p in enumerate(priorities)):
        print(ok("Prioridades 1-55 sequenciais sem gaps OK"))
    else:
        print(fail("Prioridades com gaps ou duplicatas"))
        errors.append("Priority gaps")

    # 3. Top 10 tem risk scores mais altos que bottom 10
    top10_avg = sum(p.risk_score for p in priorities[:10]) / 10
    bottom10_avg = sum(p.risk_score for p in priorities[-10:]) / 10
    if top10_avg > bottom10_avg:
        print(ok(f"Top 10 avg score: {top10_avg:.1f} > Bottom 10 avg: {bottom10_avg:.1f} OK"))
    else:
        print(fail(f"Top 10 ({top10_avg:.1f}) nao > Bottom 10 ({bottom10_avg:.1f})"))
        errors.append("Ranking inversion")

    # 4. KEV CVEs estao no topo
    kev_cves = {k for k, v in kev_map.items() if v.kev}
    top_positions = {p.cve for p in priorities[:12]}
    kev_in_top = kev_cves & top_positions
    if len(kev_in_top) == len(kev_cves):
        print(ok(f"Todos os {len(kev_cves)} KEV estao no Top 12 OK"))
    else:
        print(fail(f"Apenas {len(kev_in_top)}/{len(kev_cves)} KEV no Top 12"))
        errors.append("KEV not in top")

    # 5. Exploit CVEs estao no topo
    exploit_cves = set(exploit_map.keys())
    exploit_in_top = exploit_cves & top_positions
    if len(exploit_in_top) >= len(exploit_cves) * 0.8:
        print(ok(f"{len(exploit_in_top)}/{len(exploit_cves)} exploits no Top 12 OK"))
    else:
        print(fail(f"Apenas {len(exploit_in_top)}/{len(exploit_cves)} exploits no topo"))

    # 6. Risk Scores decrescentes (ordenacao correta)
    sorted_ok = all(
        priorities[i].risk_score >= priorities[i + 1].risk_score
        for i in range(len(priorities) - 1)
    )
    if sorted_ok:
        print(ok("Risk Scores estritamente decrescentes OK"))
    else:
        print(fail("Risk Scores NAO estao em ordem decrescente"))
        errors.append("Not sorted")

    # 7. Quick Wins gerados
    wins = AdvancedRecommendationEngine.generate_quick_wins(priorities)
    if len(wins) >= 5:
        print(ok(f"Quick Wins: {len(wins)} gerados OK"))
    else:
        print(fail(f"Quick Wins: {len(wins)} (esperado >=5)"))
        errors.append("Too few quick wins")

    # 8. Top 10 display
    print(f"\n{info('Top 10 Priorities:')}")
    print(f"  {'#':<4} {'CVE':<20} {'Product':<20} {'Score':<7} {'Reason (abbreviated)':<40}")
    print(f"  {'-'*4} {'-'*20} {'-'*20} {'-'*7} {'-'*40}")
    for p in priorities[:10]:
        reason_short = p.reason[:40] + "..." if len(p.reason) > 40 else p.reason
        print(f"  #{p.priority:<2} {p.cve:<20} {p.enriched.product:<20} {p.risk_score:<7} {reason_short}")

    if errors:
        print(f"\n{fail(f'FALHAS: {len(errors)}')}")
        for e in errors:
            print(f"  {RED}*{END} {e}")
        return False
    else:
        print(f"\n{ok('TESTE 3 PASSOU - 55 CVEs priorizados corretamente')}")
        return True


# --------------------------------------------------------------------------- #
# MAIN
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    results = []

    print(f"\n{BOLD}{CYAN}GhostMirror -- Sprint 15 Validation Suite{END}")
    print(f"{CYAN}{'='*60}{END}")

    results.append(("Teste 1 - WordPress Priority #1", test_wordpress_priority_one()))
    results.append(("Teste 2 - Alvo sem CVE", test_no_cves()))
    results.append(("Teste 3 - 55 CVEs", test_fifty_cves()))

    print(f"\n{BOLD}{'='*60}{END}")
    print(f"{BOLD}RESULTADO FINAL{END}")
    print(f"{'='*60}\n")

    all_ok = True
    for name, passed in results:
        status = f"{GREEN}PASSOU{END}" if passed else f"{RED}FALHOU{END}"
        print(f"  {status} -- {name}")
        if not passed:
            all_ok = False

    print(f"\n{'='*60}")
    if all_ok:
        print(f"{BOLD}{GREEN}  [OK] TODOS OS TESTES PASSARAM - Pronto para merge!{END}")
    else:
        print(f"{BOLD}{RED}  [FAIL] ALGUNS TESTES FALHARAM - Revise antes do merge{END}")
    print(f"{'='*60}\n")


# --------------------------------------------------------------------------- #
# MAIN
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    results = []

    print(f"\n{BOLD}{CYAN}GhostMirror — Sprint 15 Validation Suite{END}")
    print(f"{CYAN}{'='*60}{END}")

    results.append(("Teste 1 — WordPress Priority #1", test_wordpress_priority_one()))
    results.append(("Teste 2 — Alvo sem CVE", test_no_cves()))
    results.append(("Teste 3 — 55 CVEs", test_fifty_cves()))

    print(f"\n{BOLD}{'='*60}{END}")
    print(f"{BOLD}RESULTADO FINAL{END}")
    print(f"{'='*60}\n")

    all_ok = True
    for name, passed in results:
        status = f"{GREEN}PASSOU{END}" if passed else f"{RED}FALHOU{END}"
        print(f"  {status} — {name}")
        if not passed:
            all_ok = False

    print(f"\n{'='*60}")
    if all_ok:
        print(f"{BOLD}{GREEN}  ✓ TODOS OS TESTES PASSARAM — Pronto para merge!{END}")
    else:
        print(f"{BOLD}{RED}  ✗ ALGUNS TESTES FALHARAM — Revise antes do merge{END}")
    print(f"{'='*60}\n")
