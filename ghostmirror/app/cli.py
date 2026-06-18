"""GhostMirror command-line interface (Typer + Rich).

Running ``ghostmirror`` with no arguments opens an interactive menu. Every menu
action is also available as a non-interactive sub-command (``create``, ``list``,
``open``, ``config``, ``version``) for scripting and CI.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from ghostmirror import BUILD_DATE, __version__
from ghostmirror.core.config_manager import ConfigManager
from ghostmirror.core.logger import get_logger, setup_logger
from ghostmirror.core.project_manager import ProjectManager
from ghostmirror.core.exceptions import (
    InvalidConfigurationError,
    OutOfScopeError,
    ProjectAlreadyExistsError,
    ProjectError,
    ProjectNotFoundError,
    ReportGenerationError,
    ScopeViolationError,
    TemplateNotFoundError,
    ToolNotFoundError,
)
from ghostmirror.core.scope_manager import ScopeManager
from ghostmirror.modules.platform.doctor import DoctorEngine
from ghostmirror.modules.platform.health_check import HealthCheckEngine
from ghostmirror.modules.platform.status import StatusEngine


def _configure_stdio_encoding() -> None:
    """Force UTF-8 on stdout/stderr so Rich's box/unicode glyphs never crash on
    legacy Windows code pages (e.g. cp1252). Safe no-op elsewhere."""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):  # pragma: no cover - stream not reconfigurable
            pass


_configure_stdio_encoding()

console = Console()
logger = get_logger()

app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,
    help="GhostMirror — Internal Pentest Automation Platform.",
)


# --------------------------------------------------------------------------- #
# Application context / bootstrap
# --------------------------------------------------------------------------- #
@dataclass
class AppContext:
    """Wires together the collaborators needed by the CLI."""

    config: ConfigManager
    projects: ProjectManager
    scopes: ScopeManager


def bootstrap() -> AppContext:
    """Build configuration, logging and managers for a CLI invocation."""

    config = ConfigManager()
    config.load()

    setup_logger(config.logs_dir)
    logger = get_logger()

    # Ensure the top-level working directories exist.
    for directory in (config.projects_dir, config.logs_dir, config.reports_dir):
        directory.mkdir(parents=True, exist_ok=True)

    logger.info("CLI_INIT version={} home={}", __version__, config.base_dir)

    scopes = ScopeManager()
    projects = ProjectManager(config=config, scope_manager=scopes)
    return AppContext(config=config, projects=projects, scopes=scopes)


# --------------------------------------------------------------------------- #
# Presentation helpers
# --------------------------------------------------------------------------- #
def render_banner() -> None:
    banner = (
        "╔════════════════════════════════╗\n"
        "║        GHOSTMIRROR CLI         ║\n"
        "║   Internal Pentest Platform    ║\n"
        "╚════════════════════════════════╝"
    )
    console.print(Text(banner, style="bold cyan"))


def _render_projects_table(handles: list[ProjectHandle]) -> None:
    if not handles:
        console.print("[yellow]Nenhum projeto encontrado.[/]")
        return

    table = Table(box=box.ROUNDED, header_style="bold cyan", title="Projetos")
    table.add_column("Slug", style="green")
    table.add_column("Cliente")
    table.add_column("Projeto")
    table.add_column("Status")
    table.add_column("Criado em")

    for handle in handles:
        meta = handle.metadata
        table.add_row(
            handle.slug,
            meta.client,
            meta.name,
            meta.status.value,
            meta.created_at.strftime("%Y-%m-%d %H:%M"),
        )
    console.print(table)


def _render_project_detail(ctx: AppContext, handle: ProjectHandle) -> None:
    meta = handle.metadata
    table = Table(box=box.MINIMAL, show_header=False)
    table.add_column("Campo", style="bold cyan")
    table.add_column("Valor")
    table.add_row("UUID", meta.uuid)
    table.add_row("Cliente", meta.client)
    table.add_row("Projeto", meta.name)
    table.add_row("Domínio", meta.domain or "—")
    table.add_row("Observações", meta.notes or "—")
    table.add_row("Status", meta.status.value)
    table.add_row("Criado em", meta.created_at.strftime("%Y-%m-%d %H:%M:%S %Z"))
    table.add_row("Versão GhostMirror", meta.ghostmirror_version)
    table.add_row("Caminho", str(handle.path))
    console.print(Panel(table, title=f"Projeto • {handle.slug}", border_style="green"))

    # Scope summary.
    try:
        scope = ctx.projects.read_scope(handle)
    except Exception as exc:  # noqa: BLE001 - surface but don't crash the menu
        console.print(f"[bold red]Escopo inválido:[/] {exc}")
        return

    scope_table = Table(box=box.MINIMAL, header_style="bold cyan", title="Escopo")
    scope_table.add_column("Categoria")
    scope_table.add_column("Permitido")
    for field, allowed in scope.allowed_tests.model_dump().items():
        flag = "[green]sim[/]" if allowed else "[red]não[/]"
        scope_table.add_row(field, flag)
    console.print(scope_table)
    console.print(
        f"[dim]Domínios:[/] {', '.join(scope.targets.domains) or '—'}   "
        f"[dim]IPs:[/] {', '.join(scope.targets.ips) or '—'}"
    )


def _render_config(ctx: AppContext) -> None:
    settings = ctx.config.settings
    table = Table(box=box.ROUNDED, show_header=False, title="Configurações")
    table.add_column("Chave", style="bold cyan")
    table.add_column("Valor")
    table.add_row("app.name", settings.app.name)
    table.add_row("app.version", settings.app.version)
    table.add_row("app.environment", settings.app.environment)
    table.add_row("home", str(ctx.config.base_dir))
    table.add_row("config file", str(ctx.config.config_path))
    table.add_row("paths.projects", str(ctx.config.projects_dir))
    table.add_row("paths.logs", str(ctx.config.logs_dir))
    table.add_row("paths.reports", str(ctx.config.reports_dir))
    console.print(table)


def _pause() -> None:
    Prompt.ask("\n[dim]Pressione ENTER para continuar[/]", default="", show_default=False)


def _ask_required(label: str) -> str:
    """Prompt until a non-empty value is provided."""

    while True:
        value = Prompt.ask(label).strip()
        if value:
            return value
        console.print("[red]Campo obrigatório.[/]")


# --------------------------------------------------------------------------- #
# Interactive menu actions
# --------------------------------------------------------------------------- #
def _action_create(ctx: AppContext) -> None:
    console.print(Panel("Criar Novo Projeto", border_style="cyan"))
    client = _ask_required("Nome do cliente")
    name = _ask_required("Nome do projeto")
    domain = Prompt.ask("Domínio principal", default="").strip()
    notes = Prompt.ask("Observações", default="").strip()

    try:
        handle = ctx.projects.create_project(
            client=client,
            name=name,
            domain=domain or None,
            notes=notes or None,
        )
    except ProjectAlreadyExistsError as exc:
        console.print(f"[bold red]Erro:[/] {exc}")
        return
    except Exception as exc:  # noqa: BLE001 - report any unexpected failure
        get_logger().exception("PROJECT_CREATE_FAILED error={}", exc)
        console.print(f"[bold red]Falha ao criar projeto:[/] {exc}")
        return

    console.print(f"[bold green]Projeto criado:[/] {handle.slug}")
    _render_project_detail(ctx, handle)


def _action_list(ctx: AppContext) -> None:
    _render_projects_table(ctx.projects.list_projects())


def _action_open(ctx: AppContext) -> None:
    handles = ctx.projects.list_projects()
    if not handles:
        console.print("[yellow]Nenhum projeto para abrir.[/]")
        return
    _render_projects_table(handles)
    slug = Prompt.ask("Slug do projeto a abrir").strip()
    try:
        handle = ctx.projects.open_project(slug)
    except (ProjectNotFoundError, ProjectError) as exc:
        console.print(f"[bold red]Erro:[/] {exc}")
        return
    _render_project_detail(ctx, handle)


def _action_config(ctx: AppContext) -> None:
    _render_config(ctx)


class SessionState:
    """Session state helper to keep track of the currently opened/active project."""
    def __init__(self) -> None:
        self.active_project: ProjectHandle | None = None


def _menu_projects(ctx: AppContext, state: SessionState) -> None:
    """Nested interactive menu for project actions."""
    while True:
        console.print()
        render_banner()
        console.print()
        if state.active_project:
            console.print(f"Projeto Ativo: [bold green]{state.active_project.slug}[/]")
        else:
            console.print("Projeto Ativo: [yellow]Nenhum[/]")
        console.print()
        console.print("[bold]\\[1][/] Criar projeto")
        console.print("[bold]\\[2][/] Listar projetos")
        console.print("[bold]\\[3][/] Abrir projeto")
        console.print("[bold]\\[4][/] Ver escopo")
        console.print("[bold]\\[5][/] Validar escopo")
        console.print("[bold]\\[0][/] Voltar")

        try:
            choice = Prompt.ask(
                "\nEscolha uma opção",
                choices=["0", "1", "2", "3", "4", "5"],
                default="0",
                show_choices=False,
            )
        except (EOFError, KeyboardInterrupt):
            return

        if choice == "0":
            return
        elif choice == "1":
            _action_create_menu(ctx, state)
        elif choice == "2":
            _action_list(ctx)
        elif choice == "3":
            _action_open_menu(ctx, state)
        elif choice == "4":
            if not state.active_project:
                console.print("[yellow]Nenhum projeto ativo para visualizar o escopo.[/]")
            else:
                scope_path = state.active_project.path / "scope.yaml"
                if scope_path.exists():
                    console.print(Panel(scope_path.read_text(encoding="utf-8"), title=f"Escopo • {state.active_project.slug}"))
                else:
                    console.print("[red]Arquivo scope.yaml não encontrado.[/]")
        elif choice == "5":
            if not state.active_project:
                console.print("[yellow]Nenhum projeto ativo para validar o escopo.[/]")
            else:
                scope_path = state.active_project.path / "scope.yaml"
                valid, reason = ctx.scopes.validate_scope(scope_path)
                if valid:
                    console.print("[bold green]Escopo do projeto é 100% válido![/]")
                else:
                    console.print(f"[bold red]Escopo inválido:[/] {reason}")
        _pause()


def _action_create_menu(ctx: AppContext, state: SessionState) -> None:
    console.print(Panel("Criar Novo Projeto", border_style="cyan"))
    client = _ask_required("Nome do cliente")
    name = _ask_required("Nome do projeto")
    domain = Prompt.ask("Domínio principal", default="").strip()
    notes = Prompt.ask("Observações", default="").strip()

    try:
        handle = ctx.projects.create_project(
            client=client,
            name=name,
            domain=domain or None,
            notes=notes or None,
        )
        state.active_project = handle
        console.print(f"[bold green]Projeto criado e selecionado como ativo:[/] {handle.slug}")
        _render_project_detail(ctx, handle)
    except Exception as exc:
        console.print(f"[bold red]Falha ao criar projeto:[/] {exc}")


def _action_open_menu(ctx: AppContext, state: SessionState) -> None:
    handles = ctx.projects.list_projects()
    if not handles:
        console.print("[yellow]Nenhum projeto para abrir.[/]")
        return
    _render_projects_table(handles)
    slug = Prompt.ask("Slug do projeto a abrir").strip()
    try:
        handle = ctx.projects.open_project(slug)
        state.active_project = handle
        console.print(f"[bold green]Projeto aberto:[/] {handle.slug}")
        _render_project_detail(ctx, handle)
    except Exception as exc:
        console.print(f"[bold red]Erro ao abrir projeto:[/] {exc}")


def _menu_scans(ctx: AppContext, state: SessionState) -> None:
    """Nested interactive menu for running individual scans."""
    while True:
        if not state.active_project:
            console.print("[yellow]Aviso: Nenhum projeto ativo para realizar varreduras.[/]")
            _action_open_menu(ctx, state)
            if not state.active_project:
                return

        console.print()
        render_banner()
        console.print()
        console.print(f"Projeto Ativo: [bold green]{state.active_project.slug}[/]")
        console.print()
        console.print("[bold]\\[1][/] Headers Security Scan")
        console.print("[bold]\\[2][/] SSL/TLS Scan")
        console.print("[bold]\\[3][/] Nmap Port Scan")
        console.print("[bold]\\[4][/] Fingerprint / WhatWeb Scan")
        console.print("[bold]\\[5][/] Nuclei Smart Scan")
        console.print("[bold]\\[6][/] OWASP Top 10 Light Assessment")
        console.print("[bold]\\[7][/] Safe Payload Scan")
        console.print("[bold]\\[0][/] Voltar")

        try:
            choice = Prompt.ask(
                "\nEscolha uma opção",
                choices=["0", "1", "2", "3", "4", "5", "6", "7"],
                default="0",
                show_choices=False,
            )
        except (EOFError, KeyboardInterrupt):
            return

        if choice == "0":
            return

        # Load targets list from active project scope
        scope = ctx.projects.read_scope(state.active_project)
        console.print(
            f"[dim]Domínios em escopo:[/] {', '.join(scope.targets.domains) or '—'}\n"
            f"[dim]IPs em escopo:[/] {', '.join(scope.targets.ips) or '—'}"
        )
        default_target = state.active_project.metadata.domain or (scope.targets.domains[0] if scope.targets.domains else "")
        target = Prompt.ask("Digite o alvo para o scan", default=default_target).strip()
        if not target:
            console.print("[bold red]Alvo obrigatório.[/]")
            _pause()
            continue

        if choice == "1":
            from ghostmirror.modules.headers.scanner import HeadersScanner
            scanner = HeadersScanner(state.active_project.path, target, ctx.scopes)
            try:
                with console.status("[bold green]Executando Headers scan...[/]"):
                    res = scanner.run()
                console.print(f"[green]Headers Scan concluído com sucesso![/] Findings: {res.statistics.get('total', 0)}")
            except Exception as exc:
                console.print(f"[bold red]Erro:[/] {exc}")
        elif choice == "2":
            from ghostmirror.modules.ssl.scanner import SSLScanner
            scanner = SSLScanner(state.active_project.path, target, ctx.scopes)
            try:
                with console.status("[bold green]Executando SSL/TLS scan...[/]"):
                    res = scanner.run()
                console.print(f"[green]SSL/TLS Scan concluído com sucesso![/] Findings: {res.statistics.get('total', 0)}")
            except Exception as exc:
                console.print(f"[bold red]Erro:[/] {exc}")
        elif choice == "3":
            from ghostmirror.modules.nmap.scanner import NmapScanner
            scanner = NmapScanner(state.active_project.path, target, ctx.scopes)
            try:
                with console.status("[bold green]Executando Nmap scan...[/]"):
                    res = scanner.run()
                console.print(f"[green]Nmap Scan concluído com sucesso![/] Findings: {res.statistics.get('total', 0)}")
            except Exception as exc:
                console.print(f"[bold red]Erro:[/] {exc}")
        elif choice == "4":
            from ghostmirror.modules.fingerprint.scanner import FingerprintScanner
            scanner = FingerprintScanner(state.active_project.path, target, ctx.scopes)
            try:
                with console.status("[bold green]Executando Fingerprint scan...[/]"):
                    res = scanner.run()
                console.print(f"[green]Fingerprint Scan concluído com sucesso![/] Findings: {res.statistics.get('total', 0)}")
            except Exception as exc:
                console.print(f"[bold red]Erro:[/] {exc}")
        elif choice == "5":
            # Nuclei smart scan needs fingerprints/cves
            tech_profile_path = state.active_project.path / "profiles" / "technology_profile.json"
            if not tech_profile_path.exists():
                console.print("[yellow]Aviso: Perfil de tecnologia não encontrado. Executando Fingerprint scan automático primeiro...[/]")
                from ghostmirror.modules.fingerprint.scanner import FingerprintScanner
                try:
                    FingerprintScanner(state.active_project.path, target, ctx.scopes).run()
                except Exception as exc:
                    console.print(f"[red]Erro no fingerprint:[/] {exc}")
                    _pause()
                    continue

            cve_intel_path = state.active_project.path / "profiles" / "cve_intelligence.json"
            if not cve_intel_path.exists():
                console.print("[yellow]Aviso: CVE Intelligence não executado. Executando análise de CVEs automática primeiro...[/]")
                from ghostmirror.modules.cve_intelligence.engine import CVEIntelligenceEngine
                try:
                    CVEIntelligenceEngine().analyze_project(state.active_project.path)
                except Exception as exc:
                    console.print(f"[red]Erro na análise de CVEs:[/] {exc}")
                    _pause()
                    continue

            from ghostmirror.modules.nuclei.scanner import NucleiScanner
            scanner = NucleiScanner(state.active_project.path, target, ctx.scopes, profile="standard")
            try:
                with console.status("[bold green]Executando Nuclei Smart Scan...[/]"):
                    res = scanner.run()
                console.print(f"[green]Nuclei Smart Scan concluído com sucesso![/] Findings: {res.statistics.get('total', 0)}")
            except Exception as exc:
                console.print(f"[bold red]Erro:[/] {exc}")
        elif choice == "6":
            from ghostmirror.modules.owasp.scanner import OWASPScanner
            scanner = OWASPScanner(state.active_project.path, target, ctx.scopes)
            try:
                with console.status("[bold green]Executando OWASP Top 10 Light Assessment...[/]"):
                    res = scanner.run()
                console.print(f"[green]OWASP Assessment concluído com sucesso![/] Findings: {res.statistics.get('total', 0)}")
                # Show OWASP summary from profile
                owasp_profile_path = state.active_project.path / "profiles" / "owasp_profile.json"
                if owasp_profile_path.exists():
                    import json
                    with open(owasp_profile_path, "r", encoding="utf-8") as f:
                        prof = json.load(f)
                    console.print("\nOWASP ASSESSMENT COMPLETE")
                    console.print(f"Target:\n{prof.get('target', target)}")
                    console.print(f"\nCategories:\n{prof.get('total_categories', 0) if 'total_categories' in prof else len(prof.get('categories', []))}")
                    total = len(prof.get("findings", []))
                    console.print(f"\nFindings:\n{total}")
                    by_sev = prof.get("risk_score", 0)
                    console.print(f"\nOWASP Risk:\n{prof.get('risk_level', 'N/A')} (Score: {by_sev})")
            except Exception as exc:
                console.print(f"[bold red]Erro:[/] {exc}")
        elif choice == "7":
            from ghostmirror.modules.payloads.engine import PayloadEngine
            dry_run = Prompt.ask("Modo dry-run? (apenas listar, sem executar)", choices=["s", "n"], default="s").strip().lower() == "s"
            category_str = Prompt.ask("Categoria (deixe vazio para todas)", default="").strip()
            category = None
            if category_str:
                from ghostmirror.models.payload_profile import PayloadCategory
                try:
                    category = PayloadCategory(category_str.upper())
                except ValueError:
                    console.print(f"[red]Categoria inválida: {category_str}. Ignorando filtro.[/]")
            confirm_sensitive = Prompt.ask("Confirmar payloads sensíveis manualmente?", choices=["s", "n"], default="n").strip().lower() == "s"
            param = Prompt.ask("Parâmetro alvo (query parameter)", default="q").strip()
            engine = PayloadEngine(
                project_path=state.active_project.path,
                target=target,
                dry_run=dry_run,
                confirm_sensitive=confirm_sensitive,
            )
            try:
                with console.status("[bold green]Executando Safe Payload Scan...[/]"):
                    report = engine.analyze_project(category=category, parameter=param)
                console.print(f"[green]Safe Payload Scan concluído![/]")
                console.print(f"Registered: {report['total_payloads_registered']}")
                console.print(f"Executed: {report['payloads_executed']}")
                console.print(f"Blocked: {report['payloads_blocked']}")
                console.print(f"Findings: {report['findings_generated']}")
                console.print(f"Risk: {report['risk_level']} (Score: {report['risk_score']})")
            except Exception as exc:
                console.print(f"[bold red]Erro:[/] {exc}")
        _pause()


def _menu_full_scan(ctx: AppContext, state: SessionState) -> None:
    """Nested interactive menu for executing a full authorized scan."""
    while True:
        if not state.active_project:
            console.print("[yellow]Aviso: Nenhum projeto ativo para realizar scan completo.[/]")
            _action_open_menu(ctx, state)
            if not state.active_project:
                return

        console.print()
        render_banner()
        console.print()
        console.print(f"Projeto Ativo: [bold green]{state.active_project.slug}[/]")
        console.print()
        console.print("[bold]\\[1][/] Full Lite")
        console.print("[bold]\\[2][/] Full Standard")
        console.print("[bold]\\[3][/] Full Deep")
        console.print("[bold]\\[0][/] Voltar")

        try:
            choice = Prompt.ask(
                "\nEscolha uma opção",
                choices=["0", "1", "2", "3"],
                default="0",
                show_choices=False,
            )
        except (EOFError, KeyboardInterrupt):
            return

        if choice == "0":
            return

        scope = ctx.projects.read_scope(state.active_project)
        console.print(
            f"[dim]Domínios em escopo:[/] {', '.join(scope.targets.domains) or '—'}\n"
            f"[dim]IPs em escopo:[/] {', '.join(scope.targets.ips) or '—'}"
        )
        default_target = state.active_project.metadata.domain or (scope.targets.domains[0] if scope.targets.domains else "")
        target = Prompt.ask("Digite o alvo para o scan completo", default=default_target).strip()
        if not target:
            console.print("[bold red]Alvo obrigatório.[/]")
            _pause()
            continue

        profile = "standard"
        if choice == "1":
            profile = "lite"
        elif choice == "2":
            profile = "standard"
        elif choice == "3":
            profile = "deep"
            # Deep confirmation guard
            console.print("[bold yellow]ATENÇÃO: O perfil DEEP executará varreduras mais lentas e testes abrangentes do Nuclei no alvo.[/]")
            confirm = Prompt.ask("Confirma a execução deste profile?", choices=["s", "n"], default="n").strip().lower()
            if confirm != "s":
                console.print("[yellow]Execução cancelada.[/]")
                _pause()
                continue

        from ghostmirror.modules.orchestrator.full_scan import FullScanOrchestrator
        orchestrator = FullScanOrchestrator(state.active_project.path, target, profile)
        try:
            with console.status(f"[bold green]Executando Full Scan ({profile.upper()})...[/]"):
                res = orchestrator.run()
            console.print(f"[bold green]Full Scan ({profile.upper()}) concluído com sucesso![/]")
            
            console.print("\n[bold]Linha do tempo da execução:[/]")
            for step in res.get("steps", []):
                status_color = "green" if step.get("status") == "completed" else "red"
                console.print(
                    f"- [cyan]{step.get('name')}[/]: [{status_color}]{step.get('status')}[/] "
                    f"({step.get('duration')}s) | Findings: [magenta]{step.get('findings')}[/]"
                )
        except Exception as exc:
            console.print(f"[bold red]Erro durante a orquestração do scan completo:[/] {exc}")
        _pause()


def _menu_intelligence(ctx: AppContext, state: SessionState) -> None:
    """Nested interactive menu for threat intelligence mapping."""
    while True:
        if not state.active_project:
            console.print("[yellow]Aviso: Nenhum projeto ativo para análises de inteligência.[/]")
            _action_open_menu(ctx, state)
            if not state.active_project:
                return

        console.print()
        render_banner()
        console.print()
        console.print(f"Projeto Ativo: [bold green]{state.active_project.slug}[/]")
        console.print()
        console.print("[bold]\\[1][/] Technology Intelligence")
        console.print("[bold]\\[2][/] CVE Intelligence")
        console.print("[bold]\\[0][/] Voltar")

        try:
            choice = Prompt.ask(
                "\nEscolha uma opção",
                choices=["0", "1", "2"],
                default="0",
                show_choices=False,
            )
        except (EOFError, KeyboardInterrupt):
            return

        if choice == "0":
            return

        if choice == "1":
            from ghostmirror.modules.technology_intelligence.engine import TechnologyIntelligenceEngine
            engine = TechnologyIntelligenceEngine()
            try:
                with console.status("[bold green]Executando Technology Intelligence...[/]"):
                    report = engine.analyze_project(state.active_project.path)
                console.print("[green]Technology Intelligence concluído![/]")
                console.print(f"Risco da superfície de ataque: [cyan]{report.get('risk_level')}[/] (Score: {report.get('risk_score')})")
            except Exception as exc:
                console.print(f"[bold red]Erro:[/] {exc}")
        elif choice == "2":
            from ghostmirror.modules.cve_intelligence.engine import CVEIntelligenceEngine
            engine = CVEIntelligenceEngine()
            try:
                with console.status("[bold green]Executando CVE Intelligence...[/]"):
                    report = engine.analyze_project(state.active_project.path)
                console.print("[green]CVE Intelligence concluído![/]")
                console.print(f"Total CVEs correlacionadas: [cyan]{report.get('total_cves')}[/]")
            except Exception as exc:
                console.print(f"[bold red]Erro:[/] {exc}")
        _pause()


def _menu_reports(ctx: AppContext, state: SessionState) -> None:
    """Nested interactive menu for report generation."""
    while True:
        if not state.active_project:
            console.print("[yellow]Aviso: Nenhum projeto ativo para exportação de relatórios.[/]")
            _action_open_menu(ctx, state)
            if not state.active_project:
                return

        console.print()
        render_banner()
        console.print()
        console.print(f"Projeto Ativo: [bold green]{state.active_project.slug}[/]")
        console.print()
        console.print("[bold]\\[1][/] Gerar HTML")
        console.print("[bold]\\[2][/] Gerar Markdown")
        console.print("[bold]\\[3][/] Gerar PDF")
        console.print("[bold]\\[4][/] Gerar Todos")
        console.print("[bold]\\[5][/] Abrir pasta de relatórios")
        console.print("[bold]\\[0][/] Voltar")

        try:
            choice = Prompt.ask(
                "\nEscolha uma opção",
                choices=["0", "1", "2", "3", "4", "5"],
                default="0",
                show_choices=False,
            )
        except (EOFError, KeyboardInterrupt):
            return

        if choice == "0":
            return

        from ghostmirror.modules.reporting.generator import ReportGenerator
        generator = ReportGenerator(state.active_project.path)

        if choice == "1":
            try:
                with console.status("[bold green]Gerando relatório HTML...[/]"):
                    res = generator.generate("html")
                console.print(f"[green]Relatório HTML gerado em:[/] {res.get('generated_files')}")
            except Exception as exc:
                console.print(f"[bold red]Erro:[/] {exc}")
        elif choice == "2":
            try:
                with console.status("[bold green]Gerando relatório Markdown...[/]"):
                    res = generator.generate("md")
                console.print(f"[green]Relatório Markdown gerado em:[/] {res.get('generated_files')}")
            except Exception as exc:
                console.print(f"[bold red]Erro:[/] {exc}")
        elif choice == "3":
            try:
                with console.status("[bold green]Gerando relatório PDF...[/]"):
                    res = generator.generate("pdf")
                console.print(f"[green]Relatório PDF gerado em:[/] {res.get('generated_files')}")
            except Exception as exc:
                console.print(f"[bold red]Erro:[/] {exc}")
        elif choice == "4":
            try:
                with console.status("[bold green]Gerando relatórios...[/]"):
                    res = generator.generate("all")
                console.print(f"[green]Todos os relatórios gerados em:[/] {res.get('generated_files')}")
            except Exception as exc:
                console.print(f"[bold red]Erro:[/] {exc}")
        elif choice == "5":
            reports_dir = state.active_project.path / "reports"
            console.print(f"[bold green]Caminho da pasta de relatórios:[/] {reports_dir.absolute()}")
        _pause()


def _menu_updates(ctx: AppContext, state: SessionState) -> None:
    """Nested interactive menu for updater utilities."""
    while True:
        console.print()
        render_banner()
        console.print()
        console.print("[bold]\\[1][/] Atualizar templates do Nuclei")
        console.print("[bold]\\[0][/] Voltar")

        try:
            choice = Prompt.ask(
                "\nEscolha uma opção",
                choices=["0", "1"],
                default="0",
                show_choices=False,
            )
        except (EOFError, KeyboardInterrupt):
            return

        if choice == "0":
            return

        if choice == "1":
            from ghostmirror.integrations.nuclei.updater import NucleiUpdater
            updater = NucleiUpdater()
            try:
                with console.status("[bold green]Atualizando templates do Nuclei...[/]"):
                    result = updater.update_templates()
                if result.success:
                    console.print("[green]Templates do Nuclei atualizados com sucesso![/]")
                else:
                    console.print(f"[red]Erro ao atualizar templates: Exit Code {result.exit_code}[/]")
            except Exception as exc:
                console.print(f"[bold red]Erro inesperado ao atualizar templates:[/] {exc}")
        _pause()


def interactive_menu(ctx: AppContext) -> None:
    """Run the interactive Rich menu loop with nested levels and active project state."""

    logger = get_logger()
    logger.info("CLI_MENU_OPENED")

    state = SessionState()
    
    # Try auto-opening the first project if only one exists for ease of use
    projects = ctx.projects.list_projects()
    if len(projects) == 1:
        state.active_project = projects[0]

    while True:
        console.print()
        render_banner()
        console.print()
        if state.active_project:
            console.print(f"Projeto Ativo: [bold green]{state.active_project.slug}[/]")
        else:
            console.print("Projeto Ativo: [yellow]Nenhum[/]")
        console.print()
        console.print("[bold]\\[1][/] Projetos")
        console.print("[bold]\\[2][/] Scans Individuais")
        console.print("[bold]\\[3][/] Scan Completo Autorizado")
        console.print("[bold]\\[4][/] Intelligence")
        console.print("[bold]\\[5][/] Relatórios")
        console.print("[bold]\\[6][/] Atualizações")
        console.print("[bold]\\[7][/] Doctor")
        console.print("[bold]\\[8][/] Health Check")
        console.print("[bold]\\[9][/] Status")
        console.print("[bold]\\[0][/] Sair")

        try:
            choice = Prompt.ask(
                "\nEscolha uma opção",
                choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
                default="0",
                show_choices=False,
            )
        except (EOFError, KeyboardInterrupt):
            console.print("\n[bold green]Encerrando GhostMirror.[/]")
            logger.info("CLI_EXIT reason=interrupt")
            return

        if choice == "0":
            console.print("[bold green]Encerrando GhostMirror. Até logo![/]")
            logger.info("CLI_EXIT")
            return
        elif choice == "1":
            _menu_projects(ctx, state)
        elif choice == "2":
            _menu_scans(ctx, state)
        elif choice == "3":
            _menu_full_scan(ctx, state)
        elif choice == "4":
            _menu_intelligence(ctx, state)
        elif choice == "5":
            _menu_reports(ctx, state)
        elif choice == "6":
            _menu_updates(ctx, state)
        elif choice == "7":
            engine = DoctorEngine(ctx.config)
            engine.run_doctor()
            _pause()
        elif choice == "8":
            engine = HealthCheckEngine(ctx.config)
            engine.run_health_check()
            _pause()
        elif choice == "9":
            try:
                engine = StatusEngine(config=ctx.config, project_manager=ctx.projects)
                status = engine.get_status(
                    state.active_project.slug if state.active_project else None
                )
            except ProjectNotFoundError as exc:
                console.print(f"[bold red]Erro:[/] {exc}")
                _pause()
                continue

            if "error" in status:
                console.print(f"[yellow]{status['error']}[/]")
                _pause()
                continue

            console.print("[bold cyan]GhostMirror Status[/]\n")
            console.print(f"Project: [green]{status['client']} — {status['project']}[/]")
            console.print(f"Target: [cyan]{status['target']}[/]")
            console.print(f"Status: [magenta]{status.get('status', '—')}[/]")
            if status.get("last_scan"):
                console.print(f"Last Scan: [yellow]{status['last_scan']}[/]")
            else:
                console.print("Last Scan: [dim]Nenhum scan realizado[/]")

            findings = status.get("findings", {})
            total = status.get("total_findings", 0)
            console.print(f"\nFindings: [bold]{total}[/]")
            if total > 0:
                console.print(f"  Critical: [bold red]{findings.get('critical', 0)}[/]")
                console.print(f"  High:     [bold orange1]{findings.get('high', 0)}[/]")
                console.print(f"  Medium:   [bold yellow]{findings.get('medium', 0)}[/]")
                console.print(f"  Low:      [cyan]{findings.get('low', 0)}[/]")
                console.print(f"  Info:     [dim]{findings.get('info', 0)}[/]")
            _pause()


# --------------------------------------------------------------------------- #
# Typer wiring
# --------------------------------------------------------------------------- #
@app.callback(invoke_without_command=True)
def _main(ctx: typer.Context) -> None:
    """Bootstrap the application; launch the menu when no sub-command is given."""

    ctx.obj = bootstrap()
    if ctx.invoked_subcommand is None:
        interactive_menu(ctx.obj)


@app.command("interactive", help="Abre o menu interativo do GhostMirror.")
def cmd_interactive(ctx: typer.Context) -> None:
    interactive_menu(ctx.obj)


@app.command("create", help="Cria um novo projeto de auditoria.")
def cmd_create(
    ctx: typer.Context,
    client: str = typer.Option(..., "--client", "-c", help="Nome do cliente"),
    name: str = typer.Option(..., "--name", "-n", help="Nome do projeto"),
    domain: str | None = typer.Option(None, "--domain", "-d", help="Domínio principal"),
    notes: str | None = typer.Option(None, "--notes", help="Observações"),
) -> None:
    app_ctx: AppContext = ctx.obj
    try:
        handle = app_ctx.projects.create_project(
            client=client, name=name, domain=domain, notes=notes
        )
    except ProjectAlreadyExistsError as exc:
        console.print(f"[bold red]Erro:[/] {exc}")
        raise typer.Exit(code=1)
    console.print(f"[bold green]Projeto criado:[/] {handle.slug}")
    _render_project_detail(app_ctx, handle)


@app.command("list", help="Lista todos os projetos.")
def cmd_list(ctx: typer.Context) -> None:
    app_ctx: AppContext = ctx.obj
    _render_projects_table(app_ctx.projects.list_projects())


@app.command("open", help="Abre e exibe um projeto pelo slug.")
def cmd_open(
    ctx: typer.Context,
    slug: str = typer.Argument(..., help="Slug do projeto (cliente-projeto)"),
) -> None:
    app_ctx: AppContext = ctx.obj
    try:
        handle = app_ctx.projects.open_project(slug)
    except (ProjectNotFoundError, ProjectError) as exc:
        console.print(f"[bold red]Erro:[/] {exc}")
        raise typer.Exit(code=1)
    _render_project_detail(app_ctx, handle)


@app.command("config", help="Mostra as configurações globais resolvidas.")
def cmd_config(ctx: typer.Context) -> None:
    _render_config(ctx.obj)


@app.command("version", help="Mostra a versão e a data de build do GhostMirror.")
def cmd_version() -> None:
    render_banner()
    console.print(f"GhostMirror [bold green]v{__version__}[/]")
    console.print(f"Build: [cyan]{BUILD_DATE}[/]")


@app.command("doctor", help="Executa diagnóstico completo do ambiente.")
def cmd_doctor(ctx: typer.Context) -> None:
    app_ctx: AppContext = ctx.obj
    try:
        engine = DoctorEngine(app_ctx.config)
        ok = engine.run_doctor()
        if not ok:
            raise typer.Exit(code=1)
    except typer.Exit:
        raise
    except Exception as exc:
        console.print(f"[bold red][ERROR][/] Falha ao executar diagnóstico: {exc}")
        logger.exception("DOCTOR_FAILED error={}", exc)
        raise typer.Exit(code=1)


@app.command("health-check", help="Executa verificações rápidas de saúde do sistema.")
def cmd_health_check(ctx: typer.Context) -> None:
    app_ctx: AppContext = ctx.obj
    try:
        engine = HealthCheckEngine(app_ctx.config)
        ok = engine.run_health_check()
        if not ok:
            raise typer.Exit(code=1)
    except typer.Exit:
        raise
    except Exception as exc:
        console.print(f"[bold red][ERROR][/] Falha ao executar health check: {exc}")
        logger.exception("HEALTH_CHECK_FAILED error={}", exc)
        raise typer.Exit(code=1)


@app.command("status", help="Mostra o status atual de um projeto.")
def cmd_status(
    ctx: typer.Context,
    project: str | None = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    app_ctx: AppContext = ctx.obj
    engine = StatusEngine(config=app_ctx.config, project_manager=app_ctx.projects)
    try:
        status = engine.get_status(project)
    except ProjectNotFoundError as exc:
        console.print(f"[bold red]Erro:[/] {exc}")
        raise typer.Exit(code=1)

    if "error" in status:
        console.print(f"[yellow]{status['error']}[/]")
        if "projects" in status:
            console.print("Projetos disponíveis: " + ", ".join(status["projects"]))
        raise typer.Exit(code=1)

    console.print("[bold cyan]GhostMirror Status[/]\n")
    console.print(f"Project: [green]{status['client']} — {status['project']}[/]")
    console.print(f"Target: [cyan]{status['target']}[/]")
    console.print(f"Status: [magenta]{status.get('status', '—')}[/]")
    if status.get("last_scan"):
        console.print(f"Last Scan: [yellow]{status['last_scan']}[/]")
    else:
        console.print("Last Scan: [dim]Nenhum scan realizado[/]")

    findings = status.get("findings", {})
    total = status.get("total_findings", 0)
    console.print(f"\nFindings: [bold]{total}[/]")
    if total > 0:
        console.print(f"  Critical: [bold red]{findings.get('critical', 0)}[/]")
        console.print(f"  High:     [bold orange1]{findings.get('high', 0)}[/]")
        console.print(f"  Medium:   [bold yellow]{findings.get('medium', 0)}[/]")
        console.print(f"  Low:      [cyan]{findings.get('low', 0)}[/]")
        console.print(f"  Info:     [dim]{findings.get('info', 0)}[/]")


@app.command("full-scan", help="Executa um pipeline de scan completo autorizado.")
def cmd_full_scan(
    ctx: typer.Context,
    project: str = typer.Option(..., "--project", "-p", help="Slug do projeto"),
    profile: str = typer.Option("standard", "--profile", help="Perfil de execução (lite, standard, deep)"),
) -> None:
    app_ctx: AppContext = ctx.obj
    try:
        handle = app_ctx.projects.open_project(project)
    except Exception as exc:
        console.print(f"[bold red]Erro ao abrir o projeto:[/] {exc}")
        raise typer.Exit(code=1)

    scope = app_ctx.projects.read_scope(handle)
    target = handle.metadata.domain or (scope.targets.domains[0] if scope.targets.domains else "")
    if not target:
        console.print("[bold red]Nenhum alvo cadastrado no projeto. Edite scope.yaml ou metadata.json primeiro.[/]")
        raise typer.Exit(code=1)

    from ghostmirror.modules.orchestrator.full_scan import FullScanOrchestrator
    orchestrator = FullScanOrchestrator(handle.path, target, profile)
    try:
        with console.status(f"[bold green]Executando Full Scan ({profile.upper()})...[/]"):
            res = orchestrator.run()
        console.print(f"[bold green]Full Scan ({profile.upper()}) concluído com sucesso![/]")
        for step in res.get("steps", []):
            status_color = "green" if step.get("status") == "completed" else "red"
            console.print(
                f"- {step.get('name')}: [{status_color}]{step.get('status')}[/] "
                f"({step.get('duration')}s) | Findings: {step.get('findings')}"
            )
    except Exception as exc:
        console.print(f"[bold red]Erro durante a orquestração do scan completo:[/] {exc}")
        raise typer.Exit(code=1)


report_app = typer.Typer(help="Geração e gerenciamento de relatórios.")
app.add_typer(report_app, name="report")


@report_app.command("generate", help="Gera relatório nos formatos especificados.")
def cmd_report_generate(
    ctx: typer.Context,
    project: str = typer.Option(..., "--project", "-p", help="Slug do projeto"),
    format: str = typer.Option("all", "--format", "-f", help="Formato de exportação (html, pdf, md, all)"),
) -> None:
    app_ctx: AppContext = ctx.obj
    try:
        handle = app_ctx.projects.open_project(project)
    except Exception as exc:
        console.print(f"[bold red]Erro ao abrir o projeto:[/] {exc}")
        raise typer.Exit(code=1)

    from ghostmirror.modules.reporting.generator import ReportGenerator
    generator = ReportGenerator(handle.path)
    try:
        with console.status(f"[bold green]Gerando relatório ({format.upper()})...[/]"):
            res = generator.generate(format)
        console.print(f"[bold green]Relatório ({format.upper()}) gerado com sucesso![/]")
        console.print(f"Risco Global Mapeado: [cyan]{res.get('risk_level')}[/] (Score: {res.get('score')})")
        console.print(f"Arquivos salvos em reports/: {res.get('generated_files')}")
    except Exception as exc:
        console.print(f"[bold red]Erro ao gerar relatório:[/] {exc}")
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------- #
# Scan command sub-app
# --------------------------------------------------------------------------- #
scan_app = typer.Typer(help="Executa ferramentas de scan de segurança.")
app.add_typer(scan_app, name="scan")


@scan_app.command("headers", help="Executa o scanner de headers HTTP de segurança.")
def cmd_scan_headers(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
    target: str = typer.Option(None, "--target", "-t", help="Alvo do scan (domínio, URL ou IP)"),
) -> None:
    """Executa o scanner de headers HTTP de segurança no alvo especificado."""
    app_ctx: AppContext = ctx.obj

    # 1. Seleciona projeto
    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado. Por favor, crie um projeto primeiro.[/]")
            raise typer.Exit(code=1)
        _render_projects_table(handles)
        project = Prompt.ask("Selecione o projeto pelo slug").strip()
        if not project:
            console.print("[bold red]Slug do projeto obrigatório.[/]")
            raise typer.Exit(code=1)

    try:
        handle = app_ctx.projects.open_project(project)
    except Exception as exc:
        console.print(f"[bold red]Erro ao abrir o projeto:[/] {exc}")
        raise typer.Exit(code=1)

    # 2. Seleciona alvo
    if not target:
        scope = app_ctx.projects.read_scope(handle)
        console.print(
            f"[dim]Domínios em escopo:[/] {', '.join(scope.targets.domains) or '—'}\n"
            f"[dim]IPs em escopo:[/] {', '.join(scope.targets.ips) or '—'}"
        )
        target = Prompt.ask("Digite o alvo para o scan (ex: empresa.com.br)").strip()
        if not target:
            console.print("[bold red]Alvo obrigatório.[/]")
            raise typer.Exit(code=1)

    # 3. Executa scanner
    from ghostmirror.modules.base.scanner import OutOfScopeError
    from ghostmirror.modules.headers.scanner import HeadersScanner

    scanner = HeadersScanner(
        project_path=handle.path,
        target=target,
        scope_manager=app_ctx.scopes,
    )

    try:
        result = scanner.run()
    except OutOfScopeError as exc:
        console.print(f"[bold red]Execução Bloqueada:[/] {exc}")
        raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[bold red]Erro durante a execução do scan:[/] {exc}")
        raise typer.Exit(code=1)

    # 4. Mostra resumo
    console.print("---")
    console.print("## HEADERS SCAN COMPLETE\n")
    console.print("Target:")
    console.print(result.target)
    console.print("\nFindings:")
    console.print(str(result.statistics.get("total", 0)))
    console.print("\nCritical:")
    console.print(str(result.statistics.get("critical", 0)))
    console.print("\nHigh:")
    console.print(str(result.statistics.get("high", 0)))
    console.print("\nMedium:")
    console.print(str(result.statistics.get("medium", 0)))
    console.print("\nLow:")
    console.print(str(result.statistics.get("low", 0)))
    console.print("\nInfo:")
    console.print(str(result.statistics.get("info", 0)))
    console.print("---")


@scan_app.command("ssl", help="Executa o scanner de SSL/TLS e certificados de segurança.")
def cmd_scan_ssl(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
    target: str = typer.Option(None, "--target", "-t", help="Alvo do scan (domínio, URL ou IP)"),
) -> None:
    """Executa o scanner de SSL/TLS e certificados no alvo especificado."""
    app_ctx: AppContext = ctx.obj

    # 1. Seleciona projeto
    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado. Por favor, crie um projeto primeiro.[/]")
            raise typer.Exit(code=1)
        _render_projects_table(handles)
        project = Prompt.ask("Selecione o projeto pelo slug").strip()
        if not project:
            console.print("[bold red]Slug do projeto obrigatório.[/]")
            raise typer.Exit(code=1)

    try:
        handle = app_ctx.projects.open_project(project)
    except Exception as exc:
        console.print(f"[bold red]Erro ao abrir o projeto:[/] {exc}")
        raise typer.Exit(code=1)

    # 2. Seleciona alvo
    if not target:
        scope = app_ctx.projects.read_scope(handle)
        console.print(
            f"[dim]Domínios em escopo:[/] {', '.join(scope.targets.domains) or '—'}\n"
            f"[dim]IPs em escopo:[/] {', '.join(scope.targets.ips) or '—'}"
        )
        target = Prompt.ask("Digite o alvo para o scan (ex: empresa.com.br)").strip()
        if not target:
            console.print("[bold red]Alvo obrigatório.[/]")
            raise typer.Exit(code=1)

    # 3. Executa scanner
    from ghostmirror.modules.base.scanner import OutOfScopeError
    from ghostmirror.modules.ssl.scanner import SSLScanner

    scanner = SSLScanner(
        project_path=handle.path,
        target=target,
        scope_manager=app_ctx.scopes,
    )

    try:
        result = scanner.run()
    except OutOfScopeError as exc:
        console.print(f"[bold red]Execução Bloqueada:[/] {exc}")
        raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[bold red]Erro durante a execução do scan:[/] {exc}")
        raise typer.Exit(code=1)

    if result.status == "failed" or not result.certificate_summary:
        console.print("[bold red]Falha ao executar o scan de SSL/TLS (não foi possível obter o certificado).[/]")
        raise typer.Exit(code=1)

    # 4. Mostra resumo
    # Determine if certificate is valid (i.e. no validation failure finding or self-signed finding or expired finding)
    is_valid = True
    for f in result.findings:
        if f.title in (
            "Expired SSL Certificate",
            "Self-Signed Certificate",
            "Hostname Validation Failure",
            "Certificate Chain Validation Failure",
        ):
            is_valid = False
            break

    cert_status = "Valid" if is_valid else "Invalid"

    console.print("---")
    console.print("## SSL SCAN COMPLETE\n")
    console.print("Target:")
    console.print(result.target)
    console.print("\nCertificate:")
    console.print(cert_status)
    console.print("\nIssuer:")
    console.print(result.certificate_summary.get("issuer", "Unknown"))
    console.print("\nExpires:")
    console.print(result.certificate_summary.get("expires_at", "Unknown"))
    console.print("\nFindings:")
    console.print(str(result.statistics.get("total", 0)))

    for sev in ["critical", "high", "medium", "low", "info"]:
        val = result.statistics.get(sev, 0)
        if val > 0 or sev in ("high", "medium"):
            console.print(f"\n{sev.capitalize()}:")
            console.print(str(val))
    console.print("---")


@scan_app.command("nmap", help="Executa o scanner de portas e serviços Nmap.")
def cmd_scan_nmap(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
    target: str = typer.Option(None, "--target", "-t", help="Alvo do scan (domínio ou IP)"),
) -> None:
    """Executa o scanner Nmap no alvo especificado dentro do escopo do projeto."""
    app_ctx: AppContext = ctx.obj

    # 1. Seleciona projeto
    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado. Por favor, crie um projeto primeiro.[/]")
            raise typer.Exit(code=1)
        _render_projects_table(handles)
        project = Prompt.ask("Selecione o projeto pelo slug").strip()
        if not project:
            console.print("[bold red]Slug do projeto obrigatório.[/]")
            raise typer.Exit(code=1)

    try:
        handle = app_ctx.projects.open_project(project)
    except Exception as exc:
        console.print(f"[bold red]Erro ao abrir o projeto:[/] {exc}")
        raise typer.Exit(code=1)

    # 2. Seleciona alvo
    if not target:
        scope = app_ctx.projects.read_scope(handle)
        console.print(
            f"[dim]Domínios em escopo:[/] {', '.join(scope.targets.domains) or '—'}\n"
            f"[dim]IPs em escopo:[/] {', '.join(scope.targets.ips) or '—'}"
        )
        target = Prompt.ask("Digite o alvo para o scan (ex: empresa.com.br ou IP)").strip()
        if not target:
            console.print("[bold red]Alvo obrigatório.[/]")
            raise typer.Exit(code=1)

    # 3. Executa scanner
    from ghostmirror.modules.base.scanner import OutOfScopeError
    from ghostmirror.modules.nmap.scanner import NmapScanner

    scanner = NmapScanner(
        project_path=handle.path,
        target=target,
        scope_manager=app_ctx.scopes,
    )

    try:
        with console.status("[bold green]Executando Nmap scan (pode levar alguns minutos)...[/]"):
            result = scanner.run()
    except OutOfScopeError as exc:
        console.print(f"[bold red]Execução Bloqueada:[/] {exc}")
        raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[bold red]Erro durante a execução do scan:[/] {exc}")
        raise typer.Exit(code=1)

    # 4. Mostra resumo
    console.print("---")
    console.print("## NMAP SCAN COMPLETE\n")
    console.print("Target:")
    console.print(result.target)
    
    open_ports_count = len(result.open_ports or [])
    console.print("\nOpen Ports:")
    console.print(str(open_ports_count))
    
    console.print("\nServices:")
    if result.services:
        # Deduplicate and sort services
        unique_services = sorted(list(set(result.services)))
        for svc in unique_services:
            console.print(svc)
    else:
        console.print("Nenhum serviço identificado")
        
    console.print("\nFindings:")
    console.print(str(result.statistics.get("total", 0)))
    
    for sev in ["high", "medium", "info"]:
        val = result.statistics.get(sev, 0)
        console.print(f"\n{sev.capitalize()}:")
        console.print(str(val))
    console.print("---")


@scan_app.command("fingerprint", help="Executa o fingerprint e profiling de tecnologia no alvo.")
def cmd_scan_fingerprint(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
    target: str = typer.Option(None, "--target", "-t", help="Alvo do scan (domínio ou IP)"),
) -> None:
    """Executa o scanner de Fingerprint, Technology Profiler e AI Detection no alvo."""
    app_ctx: AppContext = ctx.obj

    # 1. Seleciona projeto
    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado. Por favor, crie um projeto primeiro.[/]")
            raise typer.Exit(code=1)
        _render_projects_table(handles)
        project = Prompt.ask("Selecione o projeto pelo slug").strip()
        if not project:
            console.print("[bold red]Slug do projeto obrigatório.[/]")
            raise typer.Exit(code=1)

    try:
        handle = app_ctx.projects.open_project(project)
    except Exception as exc:
        console.print(f"[bold red]Erro ao abrir o projeto:[/] {exc}")
        raise typer.Exit(code=1)

    # 2. Seleciona alvo
    if not target:
        scope = app_ctx.projects.read_scope(handle)
        console.print(
            f"[dim]Domínios em escopo:[/] {', '.join(scope.targets.domains) or '—'}\n"
            f"[dim]IPs em escopo:[/] {', '.join(scope.targets.ips) or '—'}"
        )
        target = Prompt.ask("Digite o alvo para o scan (ex: empresa.com.br ou IP)").strip()
        if not target:
            console.print("[bold red]Alvo obrigatório.[/]")
            raise typer.Exit(code=1)

    # 3. Executa scanner
    from ghostmirror.modules.base.scanner import OutOfScopeError
    from ghostmirror.modules.fingerprint.scanner import FingerprintScanner

    scanner = FingerprintScanner(
        project_path=handle.path,
        target=target,
        scope_manager=app_ctx.scopes,
    )

    try:
        with console.status("[bold green]Executando scan de Fingerprint e Technology Intelligence...[/]"):
            result = scanner.run()
    except OutOfScopeError as exc:
        console.print(f"[bold red]Execução Bloqueada:[/] {exc}")
        raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[bold red]Erro durante a execução do scan:[/] {exc}")
        raise typer.Exit(code=1)

    # Load profiles to print summary
    import json
    profile_path = handle.path / "profiles" / "technology_profile.json"
    ai_profile_path = handle.path / "profiles" / "ai_profile.json"

    webserver = "—"
    backend = "—"
    framework = "—"
    frontend = "—"
    hosting = "—"
    waf = "—"
    ai_prob = "0%"
    tech_count = 0

    if profile_path.exists():
        try:
            with open(profile_path, "r", encoding="utf-8") as f:
                tech_data = json.load(f)
            webserver = tech_data.get("webserver") or "—"
            backend = tech_data.get("backend_language") or "—"
            framework = tech_data.get("backend_framework") or "—"
            frontend = tech_data.get("frontend_framework") or "—"
            hosting = tech_data.get("hosting") or "—"
            waf = tech_data.get("waf") or "—"
            tech_count = len(tech_data.get("technologies", []))
        except Exception:
            pass

    if ai_profile_path.exists():
        try:
            with open(ai_profile_path, "r", encoding="utf-8") as f:
                ai_data = json.load(f)
            ai_prob = f"{ai_data.get('ai_probability', 0)}%"
        except Exception:
            pass

    # 4. Mostra resumo conforme exemplo CLI do prompt
    console.print("---")
    console.print("FINGERPRINT SCAN COMPLETE\n")
    console.print("Target:")
    console.print(result.target)
    console.print("\nWeb Server:")
    console.print(webserver)
    console.print("\nBackend:")
    console.print(backend)
    console.print("\nFramework:")
    console.print(framework)
    console.print("\nFrontend:")
    console.print(frontend)
    console.print("\nHosting:")
    console.print(hosting)
    console.print("\nWAF:")
    console.print(waf)
    console.print("\nAI Probability:")
    console.print(ai_prob)
    console.print("\nTechnologies Found:")
    console.print(str(tech_count))
    console.print("\nFindings:")
    console.print(str(result.statistics.get("total", 0)))
    console.print("---")


@scan_app.command("nuclei", help="Executa o scanner de vulnerabilidades inteligente Nuclei.")
def cmd_scan_nuclei(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
    profile: str = typer.Option("standard", "--profile", help="Perfil de execução (lite, standard, deep)"),
) -> None:
    """Executa o scanner Nuclei com inteligência de alvos e templates."""
    app_ctx: AppContext = ctx.obj

    # 1. Seleciona projeto
    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado. Por favor, crie um projeto primeiro.[/]")
            raise typer.Exit(code=1)
        _render_projects_table(handles)
        project = Prompt.ask("Selecione o projeto pelo slug").strip()
        if not project:
            console.print("[bold red]Slug do projeto obrigatório.[/]")
            raise typer.Exit(code=1)

    try:
        handle = app_ctx.projects.open_project(project)
    except Exception as exc:
        console.print(f"[bold red]Erro ao abrir o projeto:[/] {exc}")
        raise typer.Exit(code=1)

    # Validate that prior sprints intelligence profiles exist
    tech_profile_path = handle.path / "profiles" / "technology_profile.json"
    cve_intelligence_path = handle.path / "profiles" / "cve_intelligence.json"
    recommended_templates_path = handle.path / "recommendations" / "recommended_nuclei_templates.json"

    if not tech_profile_path.exists():
        console.print(f"[bold red]Erro: Perfil de tecnologia não encontrado em {tech_profile_path}. Executar o scan de fingerprint primeiro.[/]")
        raise typer.Exit(code=1)

    if not cve_intelligence_path.exists():
        console.print(f"[bold red]Erro: Análise de CVEs não encontrada em {cve_intelligence_path}. Executar a análise de cves primeiro.[/]")
        raise typer.Exit(code=1)

    if not recommended_templates_path.exists():
        console.print(f"[bold red]Erro: Templates recomendados não encontrados em {recommended_templates_path}. Executar a análise de cves primeiro.[/]")
        raise typer.Exit(code=1)

    # Load target from technology profile
    import json
    try:
        with open(tech_profile_path, "r", encoding="utf-8") as f:
            tech_data = json.load(f)
        target = tech_data.get("target")
        if not target:
            raise ValueError("Target não especificado no technology_profile.json")
    except Exception as exc:
        console.print(f"[bold red]Erro ao ler target do projeto:[/] {exc}")
        raise typer.Exit(code=1)

    # 2. Executa scanner
    from ghostmirror.modules.base.scanner import OutOfScopeError
    from ghostmirror.modules.nuclei.scanner import NucleiScanner

    scanner = NucleiScanner(
        project_path=handle.path,
        target=target,
        scope_manager=app_ctx.scopes,
        profile=profile,
    )

    try:
        with console.status("[bold green]Executando Nuclei scan (pode levar alguns minutos)...[/]"):
            result = scanner.run()
    except OutOfScopeError as exc:
        console.print(f"[bold red]Execução Bloqueada:[/] {exc}")
        raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[bold red]Erro durante a execução do scan:[/] {exc}")
        raise typer.Exit(code=1)

    # Load nuclei_profile to print summary
    nuclei_profile_path = handle.path / "profiles" / "nuclei_profile.json"
    templates_executed = 0
    findings_count = 0
    critical = 0
    high = 0
    medium = 0
    low = 0
    correlated_findings = 0
    execution_time = 0.0

    if nuclei_profile_path.exists():
        try:
            with open(nuclei_profile_path, "r", encoding="utf-8") as f:
                prof_data = json.load(f)
            templates_executed = prof_data.get("templates_executed", 0)
            findings_count = prof_data.get("findings", 0)
            critical = prof_data.get("critical", 0)
            high = prof_data.get("high", 0)
            medium = prof_data.get("medium", 0)
            low = prof_data.get("low", 0)
            correlated_findings = prof_data.get("correlated_findings", 0)
            execution_time = prof_data.get("execution_time", 0.0)
        except Exception:
            pass

    # 4. Mostra resumo conforme exemplo CLI do prompt
    console.print("---")
    console.print("NUCLEI SCAN COMPLETE\n")
    console.print("Target:")
    console.print(result.target)
    console.print("\nTemplates Executed:")
    console.print(str(templates_executed))
    console.print("\nCritical:")
    console.print(str(critical))
    console.print("\nHigh:")
    console.print(str(high))
    console.print("\nMedium:")
    console.print(str(medium))
    console.print("\nLow:")
    console.print(str(low))
    console.print("\nCorrelated Findings:")
    console.print(str(correlated_findings))
    console.print("\nExecution Time:")
    console.print(f"{int(execution_time)}s")
    console.print("---")



# --------------------------------------------------------------------------- #
# Analyze command sub-app
# --------------------------------------------------------------------------- #
analyze_app = typer.Typer(help="Analisa perfis e dados coletados para inteligência.")
app.add_typer(analyze_app, name="analyze")


@scan_app.command("rust-portscan", help="Executa o Port Scanner nativo em Rust (TCP Connect Scan).")
def cmd_scan_rust_portscan(
    ctx: typer.Context,
    host: str = typer.Option(..., "--host", help="Alvo do scan (domínio ou IP)"),
    ports: str = typer.Option(..., "--ports", help="Portas (ex: 80, 80,443, 1-1000)"),
    timeout: int = typer.Option(3, "--timeout", help="Timeout por conexão em segundos"),
) -> None:
    """Executa o port scanner Rust no alvo especificado."""
    try:
        from ghostmirror.integrations.rust.runner import RustBridge
        bridge = RustBridge()
        with console.status("[bold green]Executando Rust Port Scanner...[/]"):
            result = bridge.portscan(host=host, ports=ports, timeout=timeout)
        console.print("---")
        console.print("RUST PORT SCAN COMPLETE\n")
        console.print(f"Target: {result.target}")
        console.print(f"Open Ports: {len(result.open_ports)}")
        for p in result.open_ports:
            console.print(f"  - {p.port}/{p.state}")
        console.print(f"Duration: {result.duration_ms}ms")
        console.print("---")
    except Exception as exc:
        console.print(f"[bold red]Erro:[/] {exc}")


@scan_app.command("rust-banner", help="Executa o Banner Grabber nativo em Rust (TCP + HTTP).")
def cmd_scan_rust_banner(
    ctx: typer.Context,
    host: str = typer.Option(..., "--host", help="Alvo do scan (domínio ou IP)"),
    port: int = typer.Option(80, "--port", help="Porta alvo"),
    tls: bool = typer.Option(False, "--tls", help="Usar TLS/HTTPS"),
) -> None:
    """Executa o banner grabber Rust no alvo especificado."""
    try:
        from ghostmirror.integrations.rust.runner import RustBridge
        bridge = RustBridge()
        with console.status("[bold green]Executando Rust Banner Grabber...[/]"):
            result = bridge.banner(host=host, port=port, tls=tls)
        console.print("---")
        console.print("RUST BANNER GRAB COMPLETE\n")
        console.print(f"Host: {result.host}")
        console.print(f"Port: {result.port}")
        console.print(f"Server: {result.server or '—'}")
        console.print(f"X-Powered-By: {result.powered_by or '—'}")
        console.print(f"Via: {result.via or '—'}")
        console.print(f"Technologies: {', '.join(result.technologies) if result.technologies else '—'}")
        console.print("---")
    except Exception as exc:
        console.print(f"[bold red]Erro:[/] {exc}")


@scan_app.command("rust-fingerprint", help="Executa o HTTP Fingerprint nativo em Rust.")
def cmd_scan_rust_fingerprint(
    ctx: typer.Context,
    url: str = typer.Option(..., "--url", help="URL alvo (ex: https://example.com)"),
) -> None:
    """Executa o fingerprint HTTP Rust no alvo especificado."""
    try:
        from ghostmirror.integrations.rust.runner import RustBridge
        bridge = RustBridge()
        with console.status("[bold green]Executando Rust HTTP Fingerprint...[/]"):
            result = bridge.fingerprint(url=url)
        console.print("---")
        console.print("RUST FINGERPRINT COMPLETE\n")
        console.print(f"Target: {result.target}")
        console.print(f"CMS: {result.cms or '—'}")
        console.print(f"WAF: {result.waf or '—'}")
        console.print(f"Cloudflare: {'Yes' if result.cloudflare else 'No'}")
        console.print(f"\nTechnologies ({len(result.technologies)}):")
        for t in result.technologies:
            console.print(f"  - {t.name} ({t.category}) [{t.confidence}%]")
        console.print("---")
    except Exception as exc:
        console.print(f"[bold red]Erro:[/] {exc}")


@scan_app.command("owasp", help="Executa o OWASP Top 10 Light Assessment (seguro, sem exploração).")
def cmd_scan_owasp(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
    target: str = typer.Option(None, "--target", "-t", help="Alvo do scan (domínio, URL ou IP)"),
) -> None:
    """Executa o OWASP Top 10 Light Engine no alvo especificado. Avaliação segura e não invasiva."""
    app_ctx: AppContext = ctx.obj

    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado. Por favor, crie um projeto primeiro.[/]")
            raise typer.Exit(code=1)
        _render_projects_table(handles)
        project = Prompt.ask("Selecione o projeto pelo slug").strip()
        if not project:
            console.print("[bold red]Slug do projeto obrigatório.[/]")
            raise typer.Exit(code=1)

    try:
        handle = app_ctx.projects.open_project(project)
    except Exception as exc:
        console.print(f"[bold red]Erro ao abrir o projeto:[/] {exc}")
        raise typer.Exit(code=1)

    if not target:
        scope = app_ctx.projects.read_scope(handle)
        console.print(
            f"[dim]Domínios em escopo:[/] {', '.join(scope.targets.domains) or '—'}\n"
            f"[dim]IPs em escopo:[/] {', '.join(scope.targets.ips) or '—'}"
        )
        target = Prompt.ask("Digite o alvo para o scan (ex: empresa.com.br)").strip()
        if not target:
            console.print("[bold red]Alvo obrigatório.[/]")
            raise typer.Exit(code=1)

    from ghostmirror.modules.base.scanner import OutOfScopeError
    from ghostmirror.modules.owasp.scanner import OWASPScanner

    scanner = OWASPScanner(
        project_path=handle.path,
        target=target,
        scope_manager=app_ctx.scopes,
    )

    try:
        with console.status("[bold green]Executando OWASP Top 10 Light Assessment...[/]"):
            result = scanner.run()
    except OutOfScopeError as exc:
        console.print(f"[bold red]Execução Bloqueada:[/] {exc}")
        raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[bold red]Erro durante a execução do scan:[/] {exc}")
        raise typer.Exit(code=1)

    import json
    owasp_profile_path = handle.path / "profiles" / "owasp_profile.json"
    try:
        with open(owasp_profile_path, "r", encoding="utf-8") as f:
            prof = json.load(f)
    except Exception:
        prof = {}

    console.print("---")
    console.print("OWASP ASSESSMENT COMPLETE\n")
    console.print("Target:")
    console.print(prof.get("target", result.target))
    categories = prof.get("categories", [])
    console.print("\nCategories:")
    console.print(str(len(categories)))
    findings_total = len(prof.get("findings", []))
    console.print("\nFindings:")
    console.print(str(findings_total))

    by_severity = {}
    for f in prof.get("findings", []):
        sev = f.get("severity", "INFO").upper()
        by_severity[sev] = by_severity.get(sev, 0) + 1

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = by_severity.get(sev, 0)
        if count > 0:
            console.print(f"\n{sev.capitalize()}:")
            console.print(str(count))

    console.print(f"\nOWASP Risk:")
    console.print(f"{prof.get('risk_level', 'N/A')} (Score: {prof.get('risk_score', 0)})")

    if prof.get("recommendations"):
        console.print("\nRecommendations:")
        for rec in prof["recommendations"][:5]:
            console.print(f"  - {rec}")
    console.print("---")


@scan_app.command("payloads", help="Executa o Safe Payload Engine (payloads não destrutivos, controlados).")
def cmd_scan_payloads(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
    target: str = typer.Option(None, "--target", "-t", help="Alvo do scan (domínio, URL ou IP)"),
    category: str | None = typer.Option(None, "--category", "-c", help="Filtrar por categoria de payload"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Modo dry-run: lista payloads sem executar"),
    confirm_sensitive: bool = typer.Option(False, "--confirm-sensitive", help="Permite executar payloads que requerem confirmação manual"),
    parameter: str = typer.Option("q", "--parameter", "-P", help="Query parameter alvo para injeção"),
) -> None:
    """Executa o Safe Payload Engine no alvo especificado. Apenas payloads não destrutivos e controlados."""
    app_ctx: AppContext = ctx.obj

    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado. Por favor, crie um projeto primeiro.[/]")
            raise typer.Exit(code=1)
        _render_projects_table(handles)
        project = Prompt.ask("Selecione o projeto pelo slug").strip()
        if not project:
            console.print("[bold red]Slug do projeto obrigatório.[/]")
            raise typer.Exit(code=1)

    try:
        handle = app_ctx.projects.open_project(project)
    except Exception as exc:
        console.print(f"[bold red]Erro ao abrir o projeto:[/] {exc}")
        raise typer.Exit(code=1)

    if not target:
        scope = app_ctx.projects.read_scope(handle)
        console.print(
            f"[dim]Domínios em escopo:[/] {', '.join(scope.targets.domains) or '—'}\n"
            f"[dim]IPs em escopo:[/] {', '.join(scope.targets.ips) or '—'}"
        )
        target = Prompt.ask("Digite o alvo para o scan (ex: empresa.com.br)").strip()
        if not target:
            console.print("[bold red]Alvo obrigatório.[/]")
            raise typer.Exit(code=1)

    from ghostmirror.models.payload_profile import PayloadCategory

    cat_enum = None
    if category:
        try:
            cat_enum = PayloadCategory(category.upper())
        except ValueError:
            valid = [c.value for c in PayloadCategory]
            console.print(f"[bold red]Categoria inválida: {category}. Válidas: {', '.join(valid)}[/]")
            raise typer.Exit(code=1)

    from ghostmirror.modules.payloads.engine import PayloadEngine

    engine = PayloadEngine(
        project_path=handle.path,
        target=target,
        dry_run=dry_run,
        confirm_sensitive=confirm_sensitive,
    )

    try:
        with console.status("[bold green]Executando Safe Payload Scan...[/]"):
            report = engine.analyze_project(category=cat_enum, parameter=parameter)
    except Exception as exc:
        console.print(f"[bold red]Erro durante a execução do scan:[/] {exc}")
        raise typer.Exit(code=1)

    console.print("---")
    console.print("SAFE PAYLOAD VALIDATION COMPLETE\n")
    console.print("Target:")
    console.print(report["target"])
    console.print("\nDry Run:")
    console.print("Sim" if report["dry_run"] else "Não")
    console.print("\nPayloads Registered:")
    console.print(str(report["total_payloads_registered"]))
    console.print("\nPayloads Executed:")
    console.print(str(report["payloads_executed"]))
    console.print("\nPayloads Blocked:")
    console.print(str(report["payloads_blocked"]))
    console.print("\nCategories Tested:")
    console.print(str(len(report["categories_tested"])))
    console.print("\nFindings Generated:")
    console.print(str(report["findings_generated"]))
    console.print("\nRisk Score:")
    console.print(str(report["risk_score"]))
    console.print("\nRisk Level:")
    console.print(report["risk_level"])
    console.print("---")


@analyze_app.command("technologies", help="Analisa as tecnologias do projeto e gera perfil de risco e superfície de ataque.")
def cmd_analyze_technologies(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Executa a análise inteligente de tecnologia no projeto selecionado."""
    app_ctx: AppContext = ctx.obj

    # 1. Seleciona projeto
    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado. Por favor, crie um projeto primeiro.[/]")
            raise typer.Exit(code=1)
        _render_projects_table(handles)
        project = Prompt.ask("Selecione o projeto pelo slug").strip()
        if not project:
            console.print("[bold red]Slug do projeto obrigatório.[/]")
            raise typer.Exit(code=1)

    try:
        handle = app_ctx.projects.open_project(project)
    except Exception as exc:
        console.print(f"[bold red]Erro ao abrir o projeto:[/] {exc}")
        raise typer.Exit(code=1)

    # 2. Executa a análise de tecnologia
    from ghostmirror.modules.technology_intelligence.engine import TechnologyIntelligenceEngine

    engine = TechnologyIntelligenceEngine()

    try:
        with console.status("[bold green]Executando Technology Intelligence Engine...[/]"):
            report = engine.analyze_project(handle.path)
    except FileNotFoundError as exc:
        console.print(f"[bold red]Erro:[/] {exc}")
        raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[bold red]Erro durante a análise de inteligência:[/] {exc}")
        raise typer.Exit(code=1)

    # 3. Mostrar Resumo
    console.print("---")
    console.print("TECHNOLOGY INTELLIGENCE COMPLETE\n")
    console.print("Target:")
    console.print(report["target"])
    console.print("\nRisk Score:")
    console.print(str(report["risk_score"]))
    console.print("\nRisk Level:")
    console.print(report["risk_level"])
    console.print("\nTechnologies:")
    console.print(str(len(report["technologies"])))
    console.print("\nPotential Entry Points:")
    console.print(str(len(report["potential_entry_points"])))
    console.print("\nHigh Value Assets:")
    console.print(str(len(report["high_value_assets"])))
    console.print("\nRecommended Scans:")
    console.print(str(len(report["recommended_scans"])))
    console.print("\nFindings:")
    console.print(str(len(report["findings"])))
    console.print("---")


@analyze_app.command("cves", help="Executa o CVE Intelligence Engine e correlaciona tecnologias com vulnerabilidades.")
def cmd_analyze_cves(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Executa a análise inteligente de vulnerabilidades e CVEs no projeto selecionado."""
    app_ctx: AppContext = ctx.obj

    # 1. Seleciona projeto
    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado. Por favor, crie um projeto primeiro.[/]")
            raise typer.Exit(code=1)
        _render_projects_table(handles)
        project = Prompt.ask("Selecione o projeto pelo slug").strip()
        if not project:
            console.print("[bold red]Slug do projeto obrigatório.[/]")
            raise typer.Exit(code=1)

    try:
        handle = app_ctx.projects.open_project(project)
    except Exception as exc:
        console.print(f"[bold red]Erro ao abrir o projeto:[/] {exc}")
        raise typer.Exit(code=1)

    # 2. Executa a análise de CVEs
    from ghostmirror.modules.cve_intelligence.engine import CVEIntelligenceEngine

    engine = CVEIntelligenceEngine()

    try:
        with console.status("[bold green]Executando CVE Intelligence Engine...[/]"):
            report = engine.analyze_project(handle.path)
    except FileNotFoundError as exc:
        console.print(f"[bold red]Erro:[/] {exc}")
        raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[bold red]Erro durante a análise de CVEs:[/] {exc}")
        raise typer.Exit(code=1)

    # 3. Mostrar Resumo
    console.print("---")
    console.print("CVE INTELLIGENCE COMPLETE\n")
    console.print("Target:")
    console.print(report["target"])
    console.print("\nTechnologies Analyzed:")
    console.print(str(report["technologies_analyzed"]))
    console.print("\nCVE Matches:")
    console.print(str(report["total_cves"]))
    console.print("\nCritical:")
    console.print(str(report["critical_count"]))
    console.print("\nHigh:")
    console.print(str(report["high_count"]))
    console.print("\nMedium:")
    console.print(str(report["medium_count"]))
    console.print("\nExploit Available:")
    console.print(str(report["exploitable_count"]))
    console.print("\nKEV Listed:")
    console.print(str(report["kev_count"]))
    console.print("\nOverall Vulnerability Score:")
    console.print(str(report["overall_vulnerability_score"]))
    console.print("\nRisk Level:")
    console.print(report["overall_risk_level"])
    console.print("\nRecommended Nuclei Templates:")
    console.print(str(len(report["recommended_nuclei_templates"])))
    console.print("---")


# --------------------------------------------------------------------------- #
# Nuclei template updater sub-app
# --------------------------------------------------------------------------- #
nuclei_app = typer.Typer(help="Gerenciamento de templates do Nuclei.")
app.add_typer(nuclei_app, name="nuclei")


@nuclei_app.command("update", help="Atualiza a base local de templates do Nuclei.")
def cmd_nuclei_update(ctx: typer.Context) -> None:
    """Executa 'nuclei -update-templates' e registra logs."""
    from ghostmirror.integrations.nuclei.updater import NucleiUpdater

    updater = NucleiUpdater()
    try:
        with console.status("[bold green]Atualizando templates do Nuclei...[/]"):
            result = updater.update_templates()
        if result.success:
            console.print("[green]Templates do Nuclei atualizados com sucesso![/]")
            logger.info("NUCLEI_TEMPLATES_UPDATE_SUCCESS stdout={}", result.stdout[:200])
        else:
            console.print(f"[red]Erro ao atualizar templates: Exit Code {result.exit_code}[/]")
            logger.error("NUCLEI_TEMPLATES_UPDATE_FAILED exit_code={} stderr={}", result.exit_code, result.stderr[:200])
            raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[bold red]Erro inesperado ao atualizar templates:[/] {exc}")
        logger.exception("NUCLEI_TEMPLATES_UPDATE_EXCEPTION error={}", exc)
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------- #
# Lab Mode sub-app
# --------------------------------------------------------------------------- #
lab_app = typer.Typer(help="Lab Mode: ambientes vulneráveis controlados.")
app.add_typer(lab_app, name="lab")


@lab_app.command("list", help="Lista todos os ambientes de laboratório disponíveis.")
def cmd_lab_list() -> None:
    """Exibe o catálogo de labs disponíveis com nome, dificuldade e porta."""
    from ghostmirror.modules.lab import LabCatalog

    labs = LabCatalog.get_all()
    if not labs:
        console.print("[yellow]Nenhum laboratório disponível.[/]")
        return

    table = Table(box=box.ROUNDED, header_style="bold cyan", title="Laboratórios Disponíveis")
    table.add_column("ID", style="green")
    table.add_column("Nome")
    table.add_column("Dificuldade")
    table.add_column("Porta")
    table.add_column("URL")
    for lab in labs:
        diff_color = {
            "beginner": "green",
            "easy": "cyan",
            "medium": "yellow",
            "hard": "red",
        }.get(lab.difficulty, "white")
        table.add_row(
            lab.id,
            lab.name,
            f"[{diff_color}]{lab.difficulty}[/]",
            str(lab.default_port),
            lab.default_url,
        )
    console.print(table)


@lab_app.command("start", help="Inicia um ambiente de laboratório via Docker Compose.")
def cmd_lab_start(
    lab_id: str = typer.Argument(..., help="ID do laboratório (ex: juice-shop)"),
) -> None:
    from ghostmirror.modules.lab import LabManager

    manager = LabManager()
    try:
        with console.status(f"[bold green]Iniciando {lab_id}...[/]"):
            result = manager.start(lab_id)
        if result.get("success"):
            console.print(f"[bold green]✓[/] Laboratório [cyan]{lab_id}[/] iniciado com sucesso!")
        else:
            stderr = result.get("stderr", "")
            console.print(f"[bold red]✗[/] Erro ao iniciar {lab_id}: {stderr[:300]}")
            raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[bold red]Erro:[/] {exc}")
        raise typer.Exit(code=1)


@lab_app.command("stop", help="Para e remove um ambiente de laboratório.")
def cmd_lab_stop(
    lab_id: str = typer.Argument(..., help="ID do laboratório (ex: juice-shop)"),
) -> None:
    from ghostmirror.modules.lab import LabManager

    manager = LabManager()
    try:
        with console.status(f"[bold yellow]Parando {lab_id}...[/]"):
            result = manager.stop(lab_id)
        if result.get("success"):
            console.print(f"[bold green]✓[/] Laboratório [cyan]{lab_id}[/] parado com sucesso!")
        else:
            stderr = result.get("stderr", "")
            console.print(f"[bold red]✗[/] Erro ao parar {lab_id}: {stderr[:300]}")
            raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[bold red]Erro:[/] {exc}")
        raise typer.Exit(code=1)


@lab_app.command("status", help="Exibe o status de todos os laboratórios.")
def cmd_lab_status() -> None:
    from ghostmirror.modules.lab import LabManager

    manager = LabManager()
    entries = manager.status_summary()
    if not entries:
        console.print("[yellow]Nenhum laboratório encontrado.[/]")
        return

    table = Table(box=box.ROUNDED, header_style="bold cyan", title="Status dos Laboratórios")
    table.add_column("ID", style="green")
    table.add_column("Nome")
    table.add_column("Status")
    table.add_column("Porta")
    for e in entries:
        status = "[green]✓ Rodando[/]" if e["running"] else "[dim]Parado[/]"
        table.add_row(e["id"], e["name"], status, str(e["port"]))
    console.print(table)


@lab_app.command("health", help="Executa verificação de saúde de 5 pontos em um laboratório.")
def cmd_lab_health(
    lab_id: str = typer.Argument(..., help="ID do laboratório (ex: juice-shop)"),
) -> None:
    from ghostmirror.modules.lab import LabManager, LabHealth

    manager = LabManager()
    try:
        health: LabHealth = manager.health(lab_id)
        results = health.check_all()
        all_ok = all(results.values())

        console.print(f"[bold cyan]Health Check: {lab_id}[/]\n")
        for check_name, passed in results.items():
            icon = "[green]✓[/]" if passed else "[red]✗[/]"
            console.print(f"{icon} {check_name}")

        if all_ok:
            console.print(f"\n[bold green]Health: OK[/]")
        else:
            console.print(f"\n[bold red]Health: FALHA[/] — {sum(1 for v in results.values() if not v)} check(s) com problema")
            raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[bold red]Erro:[/] {exc}")
        raise typer.Exit(code=1)


@lab_app.command("create-project", help="Cria um projeto GhostMirror para um laboratório.")
def cmd_lab_create_project(
    lab_id: str = typer.Argument(..., help="ID do laboratório (ex: juice-shop)"),
) -> None:
    from ghostmirror.modules.lab import LabManager

    manager = LabManager()
    try:
        with console.status(f"[bold green]Criando projeto para {lab_id}...[/]"):
            handle = manager.create_project(lab_id)
        console.print(f"[bold green]✓[/] Projeto criado: [cyan]{handle.slug}[/]")
        console.print(f"  Path: {handle.path}")
        scope_path = handle.path / "scope.yaml"
        if scope_path.exists():
            console.print(f"  Scope: {scope_path}")
            from ghostmirror.storage.filesystem import FileSystemStorage
            scope_content = FileSystemStorage.read_yaml(scope_path)
            import yaml
            console.print(yaml.dump(scope_content, default_flow_style=False).strip())
    except Exception as exc:
        console.print(f"[bold red]Erro:[/] {exc}")
        raise typer.Exit(code=1)


@lab_app.command("benchmark", help="Executa benchmark completo (full-scan deep) em um laboratório.")
def cmd_lab_benchmark(
    lab_id: str = typer.Argument(..., help="ID do laboratório (ex: juice-shop)"),
) -> None:
    from ghostmirror.modules.lab import LabBenchmark

    benchmark = LabBenchmark()
    try:
        with console.status(f"[bold green]Executando benchmark em {lab_id} (deep scan)...[/]"):
            result = benchmark.run(lab_id)
        console.print(f"\n[bold cyan]Benchmark: {lab_id}[/]")
        console.print(f"Projeto: [green]{result.project_slug}[/]")
        console.print(f"Perfil: {result.profile}")
        console.print(f"Duração total: [yellow]{result.total_duration_seconds:.2f}s[/]")
        console.print(f"Total de findings: [yellow]{result.total_findings}[/]")

        if result.steps:
            table = Table(box=box.ROUNDED, header_style="bold cyan", title="Steps")
            table.add_column("Step")
            table.add_column("Duração (s)")
            table.add_column("Findings")
            table.add_column("Status")
            for step in result.steps:
                status = "[green]✓[/]" if step.status == "completed" else "[red]✗[/]"
                table.add_row(
                    step.step_name,
                    f"{step.duration_seconds:.2f}",
                    str(step.findings_count),
                    status,
                )
            console.print(table)

        if result.error:
            console.print(f"[bold red]Erro durante benchmark:[/] {result.error}")
    except Exception as exc:
        console.print(f"[bold red]Erro:[/] {exc}")
        raise typer.Exit(code=1)







