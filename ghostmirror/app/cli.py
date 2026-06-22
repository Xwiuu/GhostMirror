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
from ghostmirror.app.banner import render_banner, render_compact_banner, GHOST_ASCII
from ghostmirror.app.error_handler import handle_error
from ghostmirror.app.url_normalizer import normalize_url, normalize_host


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


def _action_create_menu(ctx: AppContext) -> None:
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
        console.print(f"[bold green]Projeto criado:[/] {handle.slug}")
        _render_project_detail(ctx, handle)
    except Exception as exc:
        handle_error(exc)


def _action_quick_scan(ctx: AppContext) -> None:
    """Quick scan flow — just ask for a URL, run a quick scan."""
    from datetime import datetime
    from ghostmirror.core.scope_manager import ScopeManager

    console.print(Panel("Scan Rápido", border_style="cyan", subtitle="Apenas informe a URL"))
    url = _ask_required("Digite URL")

    try:
        url = normalize_url(url)
        host = normalize_host(url)
    except ValueError as exc:
        console.print(f"[bold red]URL inválida:[/] {exc}")
        return

    slug = f"scan-rapido-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    scope_manager = ScopeManager()

    try:
        handle = ctx.projects.create_project(
            client="Quick Scan",
            name=slug,
            domain=host,
            notes=f"Scan Rápido automático em {url}",
        )
    except Exception as exc:
        handle_error(exc)
        return

    scope_path = handle.path / "scope.yaml"
    scope = scope_manager.load_scope(scope_path)
    scope.targets.domains = [host]
    scope_manager.write_scope(scope_path, scope)

    console.print(f"\n[dim]Projeto temporário:[/] [green]{slug}[/]")
    console.print(f"[dim]Alvo:[/] [cyan]{url}[/]")
    console.print()

    from ghostmirror.modules.orchestrator.full_scan import FullScanOrchestrator
    orchestrator = FullScanOrchestrator(handle.path, host, "quick")
    try:
        with console.status("[bold green]Executando Scan Rápido...[/]"):
            res = orchestrator.run()

        executed = [s for s in res.get("steps", []) if s.get("status") == "completed"]
        skipped = [s for s in res.get("steps", []) if s.get("status") == "skipped"]

        console.print(f"\n[bold green]Scan Rápido concluído![/]")
        if executed:
            console.print(f"\n[green]✓ Módulos executados:[/] {len(executed)}")
        if skipped:
            console.print(f"[yellow]⤵ Módulos pulados:[/] {len(skipped)}")

        total_findings = sum(s.get("findings", 0) for s in executed)
        console.print(f"\nTotal de findings: [bold]{total_findings}[/]")

        if total_findings > 0:
            keep = Prompt.ask("\nSalvar projeto permanentemente?", choices=["s", "n"], default="s").strip().lower()
            if keep != "s":
                import shutil
                shutil.rmtree(handle.path)
                console.print("[yellow]Projeto temporário removido.[/]")
            else:
                console.print(f"[green]Projeto salvo:[/] {handle.slug}")
        else:
            import shutil
            shutil.rmtree(handle.path)
            console.print("[dim]Nenhum finding relevante. Projeto temporário removido.[/]")

    except Exception as exc:
        handle_error(exc, context="Scan Rápido")


def _menu_labs(ctx: AppContext) -> None:
    """Lab management menu."""
    while True:
        console.print()
        render_compact_banner()
        console.print()
        console.print("[bold]\\[1][/] Listar laboratórios")
        console.print("[bold]\\[2][/] Iniciar laboratório")
        console.print("[bold]\\[3][/] Parar laboratório")
        console.print("[bold]\\[4][/] Status dos laboratórios")
        console.print("[bold]\\[5][/] Health check")
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

        if choice == "1":
            from ghostmirror.modules.lab import LabCatalog
            labs = LabCatalog.get_all()
            if not labs:
                console.print("[yellow]Nenhum laboratório disponível.[/]")
            else:
                table = Table(box=box.ROUNDED, header_style="bold cyan", title="Laboratórios")
                table.add_column("ID", style="green")
                table.add_column("Nome")
                table.add_column("Dificuldade")
                table.add_column("Porta")
                table.add_column("URL")
                for lab in labs:
                    diff_color = {"beginner": "green", "easy": "cyan", "medium": "yellow", "hard": "red"}.get(lab.difficulty, "white")
                    table.add_row(lab.id, lab.name, f"[{diff_color}]{lab.difficulty}[/]", str(lab.default_port), lab.default_url)
                console.print(table)

        elif choice in ("2", "3"):
            lab_id = Prompt.ask("ID do laboratório").strip()
            from ghostmirror.modules.lab import LabManager
            manager = LabManager()
            try:
                if choice == "2":
                    with console.status(f"[bold green]Iniciando {lab_id}..."):
                        result = manager.start(lab_id)
                    if result.get("success"):
                        console.print(f"[bold green]✓[/] {lab_id} iniciado!")
                    else:
                        console.print(f"[bold red]✗[/] {result.get('stderr', 'Erro')[:300]}")
                else:
                    with console.status(f"[bold yellow]Parando {lab_id}..."):
                        result = manager.stop(lab_id)
                    if result.get("success"):
                        console.print(f"[bold green]✓[/] {lab_id} parado!")
                    else:
                        console.print(f"[bold red]✗[/] {result.get('stderr', 'Erro')[:300]}")
            except Exception as exc:
                handle_error(exc)

        elif choice == "4":
            from ghostmirror.modules.lab import LabManager
            manager = LabManager()
            entries = manager.status_summary()
            if not entries:
                console.print("[yellow]Nenhum laboratório.[/]")
            else:
                table = Table(box=box.ROUNDED, header_style="bold cyan", title="Status dos Laboratórios")
                table.add_column("ID", style="green")
                table.add_column("Nome")
                table.add_column("Status")
                table.add_column("Porta")
                table.add_column("URL")
                for e in entries:
                    status = "[green]✓ Rodando[/]" if e.get("running") else "[dim]Parado[/]"
                    table.add_row(e["id"], e["name"], status, str(e.get("port", "—")), e.get("url", "—"))
                console.print(table)

        elif choice == "5":
            lab_id = Prompt.ask("ID do laboratório").strip()
            from ghostmirror.modules.lab import LabManager
            manager = LabManager()
            try:
                health = manager.health(lab_id)
                results = health.check_all()
                console.print(f"\n[bold cyan]Health Check: {lab_id}[/]")
                for check_name, passed in results.items():
                    icon = "[green]✓[/]" if passed else "[red]✗[/]"
                    console.print(f"{icon} {check_name}")
            except Exception as exc:
                handle_error(exc)

        _pause()


def _menu_system(ctx: AppContext) -> None:
    """System menu — diagnostics, configuration, updates."""
    while True:
        console.print()
        render_compact_banner()
        console.print()
        console.print("[bold]\\[1][/] Doctor (diagnóstico completo)")
        console.print("[bold]\\[2][/] Health Check")
        console.print("[bold]\\[3][/] Status do projeto")
        console.print("[bold]\\[4][/] Configurações")
        console.print("[bold]\\[5][/] Atualizar templates Nuclei")
        console.print("[bold]\\[6][/] Versão")
        console.print("[bold]\\[0][/] Voltar")

        try:
            choice = Prompt.ask(
                "\nEscolha uma opção",
                choices=["0", "1", "2", "3", "4", "5", "6"],
                default="0",
                show_choices=False,
            )
        except (EOFError, KeyboardInterrupt):
            return

        if choice == "0":
            return

        if choice == "1":
            DoctorEngine(ctx.config).run_doctor()
        elif choice == "2":
            HealthCheckEngine(ctx.config).run_health_check()
        elif choice == "3":
            try:
                engine = StatusEngine(config=ctx.config, project_manager=ctx.projects)
                status = engine.get_status()
            except Exception as exc:
                handle_error(exc)
                _pause()
                continue

            if "error" in status:
                console.print(f"[yellow]{status['error']}[/]")
                _pause()
                continue

            console.print("[bold cyan]GhostMirror Status[/]")
            console.print(f"Project: [green]{status.get('client', '—')} — {status.get('project', '—')}[/]")
            console.print(f"Target: [cyan]{status.get('target', '—')}[/]")
            console.print(f"Status: [magenta]{status.get('status', '—')}[/]")
            if status.get("last_scan"):
                console.print(f"Last Scan: [yellow]{status['last_scan']}[/]")

            findings = status.get("findings", {})
            total = status.get("total_findings", 0)
            console.print(f"\nFindings: [bold]{total}[/]")
            if total > 0:
                console.print(f"  Critical: [bold red]{findings.get('critical', 0)}[/]")
                console.print(f"  High:     [bold orange1]{findings.get('high', 0)}[/]")
                console.print(f"  Medium:   [bold yellow]{findings.get('medium', 0)}[/]")
                console.print(f"  Low:      [cyan]{findings.get('low', 0)}[/]")
                console.print(f"  Info:     [dim]{findings.get('info', 0)}[/]")
        elif choice == "4":
            _render_config(ctx)
        elif choice == "5":
            from ghostmirror.integrations.nuclei.updater import NucleiUpdater
            updater = NucleiUpdater()
            try:
                with console.status("[bold green]Atualizando templates Nuclei..."):
                    result = updater.update_templates()
                if result.success:
                    console.print("[green]Templates atualizados![/]")
                else:
                    console.print(f"[red]Erro: Exit Code {result.exit_code}[/]")
            except Exception as exc:
                handle_error(exc)
        elif choice == "6":
            from ghostmirror.app.banner import render_banner
            render_banner()
            console.print(f"\nVersion: [bold green]v{__version__}[/]")
            console.print(f"Build: [cyan]{BUILD_DATE}[/]")

        _pause()


def interactive_menu(ctx: AppContext) -> None:
    """Run the new simplified interactive menu."""

    logger = get_logger()
    logger.info("CLI_MENU_OPENED")

    while True:
        console.print()
        render_banner()
        console.print()
        console.print(" " + "━" * 40)
        console.print()
        console.print("[bold]\\[1][/] Novo Projeto")
        console.print("[bold]\\[2][/] Scan Rápido")
        console.print("[bold]\\[3][/] Scan Completo")
        console.print("[bold]\\[4][/] Laboratórios")
        console.print("[bold]\\[5][/] Relatórios")
        console.print("[bold]\\[6][/] Sistema")
        console.print()
        console.print(" " + "━" * 40)
        console.print()
        console.print("[bold]\\[0][/] Sair")

        try:
            choice = Prompt.ask(
                "\nEscolha uma opção",
                choices=["0", "1", "2", "3", "4", "5", "6"],
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
            _action_create_menu(ctx)

        elif choice == "2":
            _action_quick_scan(ctx)

        elif choice == "3":
            handles = ctx.projects.list_projects()
            if not handles:
                console.print("[yellow]Nenhum projeto encontrado. Crie um primeiro.[/]")
                _pause()
                continue

            _render_projects_table(handles)
            slug = Prompt.ask("Slug do projeto").strip()
            try:
                handle = ctx.projects.open_project(slug)
            except Exception as exc:
                console.print(f"[bold red]Erro:[/] {exc}")
                _pause()
                continue

            state = SessionState()
            state.active_project = handle
            _menu_full_scan(ctx, state)

        elif choice == "4":
            _menu_labs(ctx)

        elif choice == "5":
            handles = ctx.projects.list_projects()
            if not handles:
                console.print("[yellow]Nenhum projeto encontrado.[/]")
                _pause()
                continue

            _render_projects_table(handles)
            slug = Prompt.ask("Slug do projeto").strip()
            try:
                handle = ctx.projects.open_project(slug)
            except Exception as exc:
                console.print(f"[bold red]Erro:[/] {exc}")
                _pause()
                continue

            from ghostmirror.modules.reporting.generator import ReportGenerator
            generator = ReportGenerator(handle.path)

            fmt = Prompt.ask("Formato", choices=["html", "md", "pdf", "all"], default="all").strip()
            try:
                with console.status(f"[bold green]Gerando relatório ({fmt.upper()})..."):
                    res = generator.generate(fmt)
                console.print(f"[green]Relatório gerado em:[/] {res.get('generated_files')}")
                if res.get("risk_level"):
                    console.print(f"Risco: [cyan]{res.get('risk_level')}[/] (Score: {res.get('score')})")
            except Exception as exc:
                handle_error(exc)

        elif choice == "6":
            _menu_system(ctx)


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
def cmd_doctor(
    ctx: typer.Context,
    fix: bool = typer.Option(False, "--fix", help="Modo reparo assistido"),
) -> None:
    app_ctx: AppContext = ctx.obj
    try:
        if fix:
            from ghostmirror.modules.platform.doctor_fix import run_doctor_fix
            run_doctor_fix(app_ctx.config)
            return
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


# --------------------------------------------------------------------------- #
# Intelligence command
# --------------------------------------------------------------------------- #
intelligence_app = typer.Typer(help="Executa o motor completo de inteligência ofensiva.")
app.add_typer(intelligence_app, name="intelligence")


@intelligence_app.command("run", help="Executa o motor completo de inteligência ofensiva (Attack Surface, Scoring, Attack Paths).")
def cmd_intelligence_run(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Executa o Intelligence Engine completo no projeto. Produz Attack Surface Profile, Risk Matrix, Attack Paths, Executive Summary e Recommendations."""
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

    from ghostmirror.modules.intelligence.engine import IntelligenceEngine

    engine = IntelligenceEngine()
    try:
        with console.status("[bold green]Executando Intelligence Engine...[/]"):
            report = engine.analyze_project(handle.path)
    except Exception as exc:
        console.print(f"[bold red]Erro durante a execução do Intelligence Engine:[/] {exc}")
        logger.exception("INTELLIGENCE_FAILED error={}", exc)
        raise typer.Exit(code=1)

    asp = report.attack_surface_profile

    console.print("---")
    console.print("INTELLIGENCE COMPLETE\n")
    console.print("Target:")
    console.print(report.target)
    console.print("\nAttack Surface Score:")
    console.print(f"{report.overall_attack_surface_score}/100 — {asp.classification if asp else 'N/A'}")
    console.print("\nRisk Score:")
    console.print(f"{report.overall_risk_score}/100")
    console.print("\nSecurity Score:")
    console.print(f"{report.overall_security_score}/100")

    if report.risk_matrix:
        console.print(f"\nRisk Matrix Overall:")
        console.print(report.risk_matrix.overall_level)

    console.print("\nAttack Paths:")
    console.print(str(len(report.attack_paths)))
    console.print("\nRecommendations:")
    console.print(str(len(report.recommendations)))
    console.print("\nWAF:")
    waf_v = asp.waf.vendor if asp and asp.waf.detected else "Not Detected"
    console.print(waf_v)
    console.print("\nCDN:")
    cdn_v = asp.cdn.vendor if asp and asp.cdn.detected else "Not Detected"
    console.print(cdn_v)
    console.print("\nHosting:")
    host_v = asp.hosting.provider if asp and asp.hosting.detected else "Not Identified"
    console.print(host_v)
    console.print("\nDNS Issues:")
    if asp:
        issues = []
        if asp.dns.spf_missing: issues.append("SPF")
        if asp.dns.dmarc_missing: issues.append("DMARC")
        if asp.dns.dkim_missing: issues.append("DKIM")
        console.print(', '.join(issues) if issues else "None")
    console.print("\nProfiles saved:")
    console.print("  attack_surface_profile.json, risk_matrix.json, attack_paths.json,")
    console.print("  executive_summary.json, waf_profile.json, cdn_profile.json,")
    console.print("  hosting_profile.json, dns_profile.json")
    console.print("---")

    handle_error_py = None

    if report.attack_surface_profile and report.attack_surface_profile.attack_surface_score >= 61:
        console.print(f"\n[bold orange1]⚠ High Attack Surface: {report.attack_surface_profile.attack_surface_score}/100[/]")
    if report.overall_risk_score >= 61:
        console.print(f"[bold red]⚠ Elevated Risk Score: {report.overall_risk_score}/100[/]")


@intelligence_app.command("vulnerabilities", help="Advanced Vulnerability Intelligence - enriquece, correlaciona e prioriza CVEs.")
def cmd_intelligence_vulnerabilities(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Executa o Advanced Vulnerability Intelligence: enriquecimento de CVEs, EPSS, KEV, Exploit Intelligence, Attack Correlation e Priorização."""
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

    from ghostmirror.modules.vulnerability_intelligence.engine import AdvancedVulnerabilityEngine

    engine = AdvancedVulnerabilityEngine()
    try:
        with console.status("[bold green]Executando Advanced Vulnerability Intelligence..."):
            report = engine.analyze_project(handle.path)
    except Exception as exc:
        console.print(f"[bold red]Erro durante Advanced Vulnerability Intelligence:[/] {exc}")
        raise typer.Exit(code=1)

    console.print("---")
    console.print("VULNERABILITY INTELLIGENCE COMPLETE\n")
    console.print("Overall Score:")
    console.print(f"{report.overall_score}/100 — {report.risk_level}")
    console.print("\nTotal CVEs:")
    console.print(str(report.total_cves))
    console.print("\nCritical Priorities:")
    console.print(str(report.critical_priorities))
    console.print("\nKEV Count:")
    console.print(str(report.kev_count))
    console.print("\nPublic Exploits:")
    console.print(str(report.public_exploits))
    console.print("\nTop 3 Priorities:")
    for p in report.priorities[:3]:
        console.print(f"  #{p.priority} — {p.cve} ({p.enriched.product}) — Score: {p.risk_score}")
        console.print(f"    Reason: {p.reason}")
    console.print("\nQuick Wins:")
    console.print(str(len(report.quick_wins)))
    console.print("---")


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


@analyze_app.command("attack-surface", help="Analisa a superfície de ataque (WAF, CDN, Hosting, DNS, portas, serviços).")
def cmd_analyze_attack_surface(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Analisa a superfície de ataque do projeto: WAF, CDN, Hosting, DNS e exposição de portas."""
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

    from ghostmirror.modules.intelligence.attack_surface import AttackSurfaceAnalyzer
    from ghostmirror.modules.intelligence.scoring import ScoringEngine

    analyzer = AttackSurfaceAnalyzer()
    target = "Unknown"
    tech_profile = None

    import json
    tech_path = handle.path / "profiles" / "technology_profile.json"
    if tech_path.exists():
        try:
            with open(tech_path, "r", encoding="utf-8") as f:
                tech_data = json.load(f)
            target = tech_data.get("target", target)
            from ghostmirror.models.fingerprint import FingerprintProfile
            tech_profile = FingerprintProfile.model_validate(tech_data)
        except Exception:
            pass

    findings_dir = handle.path / "findings"
    headers_findings = None
    nmap_findings = None
    h_path = findings_dir / "headers.json"
    if h_path.exists():
        try:
            with open(h_path, "r", encoding="utf-8") as f:
                headers_findings = json.load(f)
        except Exception:
            pass
    n_path = findings_dir / "nmap.json"
    if n_path.exists():
        try:
            with open(n_path, "r", encoding="utf-8") as f:
                nmap_findings = json.load(f)
        except Exception:
            pass

    profile = analyzer.analyze(target=target, technology_profile=tech_profile, headers_findings=headers_findings, nmap_findings=nmap_findings)
    score, classification = ScoringEngine.calculate_attack_surface_score(profile)
    profile.attack_surface_score = score
    profile.classification = classification
    analyzer.save_profiles(handle.path, profile)

    console.print("---")
    console.print("ATTACK SURFACE ANALYSIS COMPLETE\n")
    console.print("Target:")
    console.print(target)
    console.print("\nAttack Surface Score:")
    console.print(f"{score}/100 — {classification}")
    console.print("\nWAF:")
    console.print(f"{'✓ ' + profile.waf.vendor if profile.waf.detected else '✗ Not Detected'} (Confidence: {profile.waf.confidence}%)")
    console.print("\nCDN:")
    console.print(f"{'✓ ' + profile.cdn.vendor if profile.cdn.detected else '✗ Not Detected'} (Confidence: {profile.cdn.confidence}%)")
    console.print("\nHosting:")
    console.print(f"{'✓ ' + profile.hosting.provider if profile.hosting.detected else '✗ Not Identified'} (Confidence: {profile.hosting.confidence}%)")
    console.print("\nDNS Records:")
    console.print(str(len(profile.dns.records)))
    dns_issues = []
    if profile.dns.spf_missing: dns_issues.append("SPF missing")
    if profile.dns.dmarc_missing: dns_issues.append("DMARC missing")
    if profile.dns.dkim_missing: dns_issues.append("DKIM missing")
    console.print(f"Issues: {', '.join(dns_issues) if dns_issues else 'None'}")
    console.print("\nOpen Ports:")
    console.print(', '.join(str(p) for p in profile.open_ports) if profile.open_ports else 'None')
    console.print("\nTechnologies:")
    console.print(str(len(profile.technologies)))
    console.print("\nProfiles Saved:")
    console.print("  attack_surface_profile.json, waf_profile.json, cdn_profile.json, hosting_profile.json, dns_profile.json")
    console.print("---")


@analyze_app.command("risk", help="Calcula e exibe o Risk Score consolidado do projeto.")
def cmd_analyze_risk(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Calcula o Risk Score consolidado com base em findings, CVEs, exposição e superfície de ataque."""
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

    from ghostmirror.modules.intelligence.scoring import ScoringEngine, classify_score
    from ghostmirror.modules.intelligence.risk_matrix import RiskMatrixGenerator

    import json

    def load_json(path):
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    as_profile = load_json(handle.path / "profiles" / "attack_surface_profile.json") or {}
    cve_data = load_json(handle.path / "profiles" / "vulnerability_profile.json") or {}

    cve_matches = cve_data.get("matches", [])
    cve_count = len(cve_matches)
    exploit_available = any(c.get("matched_cve", {}).get("exploit_available", False) for c in cve_matches)
    kev_count = sum(1 for c in cve_matches if c.get("matched_cve", {}).get("kev_listed", False))

    all_findings = []
    for fname in ["headers", "ssl", "nmap", "fingerprint"]:
        fdata = load_json(handle.path / "findings" / f"{fname}.json")
        if fdata and "findings" in fdata:
            all_findings.extend(fdata["findings"])

    critical_count = sum(1 for f in all_findings if f.get("severity", "").upper() == "CRITICAL")
    high_count = sum(1 for f in all_findings if f.get("severity", "").upper() == "HIGH")
    medium_count = sum(1 for f in all_findings if f.get("severity", "").upper() == "MEDIUM")

    attack_surface_score = as_profile.get("attack_surface_score", 0)
    open_ports = as_profile.get("open_ports", [])
    waf_detected = as_profile.get("waf", {}).get("detected", False)
    cdn_detected = as_profile.get("cdn", {}).get("detected", False)

    risk_score, risk_level = ScoringEngine.calculate_risk_score(
        attack_surface_score=attack_surface_score,
        findings_count=len(all_findings),
        critical_findings=critical_count,
        high_findings=high_count,
        medium_findings=medium_count,
        cve_count=cve_count,
        exploit_available=exploit_available,
        kev_listed=kev_count > 0,
    )

    security_score, _ = ScoringEngine.overall_security_score(
        attack_surface_score=attack_surface_score,
        risk_score=risk_score,
    )

    risk_matrix = RiskMatrixGenerator.generate(
        attack_surface_score=attack_surface_score,
        critical_findings=critical_count,
        high_findings=high_count,
        medium_findings=medium_count,
        total_findings=len(all_findings),
        cve_count=cve_count,
        exploit_available=exploit_available,
        kev_count=kev_count,
        open_ports_count=len(open_ports),
        waf_detected=waf_detected,
        cdn_detected=cdn_detected,
    )

    matrix_path = handle.path / "profiles" / "risk_matrix.json"
    matrix_path.parent.mkdir(parents=True, exist_ok=True)
    with open(matrix_path, "w", encoding="utf-8") as f:
        json.dump(risk_matrix.model_dump(mode="json"), f, indent=2)

    console.print("---")
    console.print("RISK ANALYSIS COMPLETE\n")
    console.print("Target:")
    target = as_profile.get("target", cve_data.get("target", "Unknown"))
    console.print(target)
    console.print("\n--- Summary Scores ---")
    console.print(f"Attack Surface Score: {attack_surface_score}/100 — {classify_score(attack_surface_score)}")
    console.print(f"Risk Score: {risk_score}/100 — {risk_level}")
    console.print(f"Security Score: {security_score}/100 — {classify_score(security_score)}")
    console.print("\n--- Risk Matrix ---")
    console.print(f"Likelihood: {risk_matrix.likelihood.score}/100 — {risk_matrix.likelihood.level}")
    console.print(f"Impact: {risk_matrix.impact.score}/100 — {risk_matrix.impact.level}")
    console.print(f"Exploitability: {risk_matrix.exploitability.score}/100 — {risk_matrix.exploitability.level}")
    console.print(f"Exposure: {risk_matrix.exposure.score}/100 — {risk_matrix.exposure.level}")
    console.print(f"Business Risk: {risk_matrix.business_risk.score}/100 — {risk_matrix.business_risk.level}")
    console.print(f"\nOverall Risk Level: [bold]{risk_matrix.overall_level}[/]")
    console.print("\n--- Findings Summary ---")
    console.print(f"Total: {len(all_findings)} | Critical: {critical_count} | High: {high_count} | Medium: {medium_count}")
    console.print(f"CVEs: {cve_count} | Exploit Available: {'Yes' if exploit_available else 'No'} | KEV: {kev_count}")
    console.print("---")


@analyze_app.command("attack-paths", help="Modela possíveis caminhos de ataque baseados em inteligência correlacionada.")
def cmd_analyze_attack_paths(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
    show_all: bool = typer.Option(False, "--all", "-a", help="Exibe todos os passos e mitigações"),
) -> None:
    """Modela possíveis caminhos de ataque sem executar exploração. Usa dados correlacionados de tecnologia, CVEs e OWASP."""
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

    from ghostmirror.modules.intelligence.attack_paths import AttackPathEngine

    engine = AttackPathEngine()
    try:
        with console.status("[bold green]Modelando Attack Paths..."):
            paths = engine.generate_paths(handle.path)
    except Exception as exc:
        console.print(f"[bold red]Erro ao modelar attack paths:[/] {exc}")
        raise typer.Exit(code=1)

    # Save attack paths
    import json
    paths_file = handle.path / "profiles" / "attack_paths.json"
    paths_file.parent.mkdir(parents=True, exist_ok=True)
    with open(paths_file, "w", encoding="utf-8") as f:
        json.dump([p.model_dump(mode="json") for p in paths], f, indent=2, ensure_ascii=False)

    console.print("---")
    console.print("ATTACK PATHS MODELED\n")
    console.print(f"Total Paths: {len(paths)}")
    console.print()

    for ap in paths:
        from rich.table import Table
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
        table.add_column("Step", style="green")
        table.add_column("Label")
        table.add_column("Detail")
        for step in ap.steps:
            table.add_row(str(step.order), step.label, step.detail or "")
        console.print(f"[bold]Path #{ap.path_id}: {ap.title}[/]")
        console.print(f"  Risk: {ap.risk_score}/100 ({ap.risk_level}) | Likelihood: {ap.likelihood} | Impact: {ap.impact}")
        console.print(f"  {ap.description}")
        console.print(table)
        if show_all and ap.mitigations:
            console.print("  [bold cyan]Mitigations:[/]")
            for m in ap.mitigations:
                console.print(f"    • {m}")
        console.print()

    if not paths or (len(paths) == 1 and paths[0].title == "No attack paths identified"):
        console.print("[yellow]No actionable attack paths could be modeled. More intelligence data may be needed.[/]")

    console.print(f"\n[green]✓ Attack paths saved to: {paths_file}[/]")
    console.print("---")


# --------------------------------------------------------------------------- #
# Advanced Vulnerability Intelligence sub-commands
# --------------------------------------------------------------------------- #
@analyze_app.command("vulnerabilities", help="Advanced Vulnerability Intelligence Engine - enriquece, correlaciona e prioriza CVEs.")
def cmd_analyze_vulnerabilities(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Executa o Advanced Vulnerability Intelligence: enriquecimento de CVEs, EPSS, KEV, Exploit Intelligence, Attack Correlation e Priorização."""
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

    from ghostmirror.modules.vulnerability_intelligence.engine import AdvancedVulnerabilityEngine

    engine = AdvancedVulnerabilityEngine()
    try:
        with console.status("[bold green]Executando Advanced Vulnerability Intelligence..."):
            report = engine.analyze_project(handle.path)
    except Exception as exc:
        console.print(f"[bold red]Erro durante Advanced Vulnerability Intelligence:[/] {exc}")
        raise typer.Exit(code=1)

    console.print("---")
    console.print("ADVANCED VULNERABILITY INTELLIGENCE COMPLETE\n")
    console.print("Overall Score:")
    console.print(f"{report.overall_score}/100 — {report.risk_level}")
    console.print("\nTotal CVEs:")
    console.print(str(report.total_cves))
    console.print("\nCritical Priorities:")
    console.print(str(report.critical_priorities))
    console.print("\nHigh Priorities:")
    console.print(str(report.high_priorities))
    console.print("\nKEV Count:")
    console.print(str(report.kev_count))
    console.print("\nPublic Exploits:")
    console.print(str(report.public_exploits))
    console.print("\nEPSS Distribution:")
    for cls, count in sorted(report.epss_distribution.items()):
        console.print(f"  {cls}: {count}")
    console.print("\nTop 3 Priorities:")
    for p in report.priorities[:3]:
        console.print(f"  #{p.priority} — {p.cve} ({p.enriched.product}) — Score: {p.risk_score}")
        console.print(f"    Reason: {p.reason}")
    console.print("\nAttack Opportunities:")
    console.print(str(len(report.attack_opportunities)))
    console.print("\nQuick Wins:")
    console.print(str(len(report.quick_wins)))
    console.print("---")


@analyze_app.command("kev", help="Known Exploited Vulnerabilities (CISA KEV) analysis.")
def cmd_analyze_kev(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Analisa CVEs contra o catálogo CISA Known Exploited Vulnerabilities."""
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

    from ghostmirror.modules.vulnerability_intelligence.engine import AdvancedVulnerabilityEngine

    engine = AdvancedVulnerabilityEngine()
    try:
        with console.status("[bold green]Executando KEV Analysis..."):
            results = engine.analyze_kev_only(handle.path)
    except Exception as exc:
        console.print(f"[bold red]Erro durante KEV analysis:[/] {exc}")
        raise typer.Exit(code=1)

    console.print("---")
    console.print("KEV ANALYSIS COMPLETE\n")
    kev_true = [r for r in results if r.kev]
    console.print(f"Total CVEs analyzed: {len(results)}")
    console.print(f"KEV listed: {len(kev_true)}")
    console.print("\nKEV Findings:")
    for r in kev_true:
        console.print(f"  - {r.cve} ({r.vendor_project}/{r.product})")
        if r.ransomware_usage:
            console.print("    [red]⚠ Ransomware Usage Confirmed[/]")
        console.print(f"    Added: {r.date_added}")
    console.print("---")


@analyze_app.command("epss", help="EPSS (Exploit Prediction Scoring System) analysis.")
def cmd_analyze_epss(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Analisa CVEs com o Exploit Prediction Scoring System."""
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

    from ghostmirror.modules.vulnerability_intelligence.engine import AdvancedVulnerabilityEngine

    engine = AdvancedVulnerabilityEngine()
    try:
        with console.status("[bold green]Executando EPSS Analysis..."):
            results = engine.analyze_epss_only(handle.path)
    except Exception as exc:
        console.print(f"[bold red]Erro durante EPSS analysis:[/] {exc}")
        raise typer.Exit(code=1)

    console.print("---")
    console.print("EPSS ANALYSIS COMPLETE\n")
    console.print(f"Total CVEs analyzed: {len(results)}")
    dist: dict[str, int] = {}
    for r in results:
        dist[r.classification] = dist.get(r.classification, 0) + 1
    console.print("\nEPSS Distribution:")
    for cls in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "VERY_LOW"]:
        count = dist.get(cls, 0)
        console.print(f"  {cls}: {count}")
    console.print("\nTop EPSS Scores:")
    sorted_results = sorted(results, key=lambda r: r.epss_score, reverse=True)
    for r in sorted_results[:5]:
        console.print(f"  {r.cve}: {r.epss_score:.5f} (p{r.percentile:.1f}) — {r.classification}")
    console.print("---")


@analyze_app.command("exploits", help="Exploit Intelligence analysis - weaponization and public exploit availability.")
def cmd_analyze_exploits(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Analisa a disponibilidade de exploits públicos, módulos Metasploit e templates Nuclei para CVEs."""
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

    from ghostmirror.modules.vulnerability_intelligence.engine import AdvancedVulnerabilityEngine

    engine = AdvancedVulnerabilityEngine()
    try:
        with console.status("[bold green]Executando Exploit Intelligence Analysis..."):
            results = engine.analyze_exploits_only(handle.path)
    except Exception as exc:
        console.print(f"[bold red]Erro durante Exploit Intelligence:[/] {exc}")
        raise typer.Exit(code=1)

    console.print("---")
    console.print("EXPLOIT INTELLIGENCE COMPLETE\n")
    console.print(f"Total CVEs analyzed: {len(results)}")
    public = sum(1 for r in results if r.public_exploit)
    metasploit = sum(1 for r in results if r.metasploit)
    nuclei = sum(1 for r in results if r.nuclei_template)
    console.print(f"Public Exploits: {public}")
    console.print(f"Metasploit Modules: {metasploit}")
    console.print(f"Nuclei Templates: {nuclei}")
    console.print("\nWeaponization Distribution:")
    dist: dict[str, int] = {}
    for r in results:
        dist[r.weaponization_level.value] = dist.get(r.weaponization_level.value, 0) + 1
    for wl in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]:
        count = dist.get(wl, 0)
        console.print(f"  {wl}: {count}")
    console.print("\nTop Exploit Risks:")
    for r in results:
        if r.weaponization_level.value in ("CRITICAL", "HIGH"):
            console.print(f"  {r.cve} — {r.weaponization_level.value} — Sources: {', '.join(r.exploit_sources)}")
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
# Web Intelligence sub-app
# --------------------------------------------------------------------------- #
web_app = typer.Typer(help="Web Vulnerability Intelligence Engine.")
app.add_typer(web_app, name="web")


@web_app.callback(invoke_without_command=True)
def cmd_web_main(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
    target: str = typer.Option(None, "--target", "-t", help="URL alvo para análise web"),
) -> None:
    """Executa o Web Intelligence Engine completo no projeto."""
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

    from ghostmirror.modules.web_intelligence.engine import WebIntelligenceEngine

    engine = WebIntelligenceEngine()
    try:
        with console.status("[bold green]Executando Web Intelligence Engine...[/]"):
            report = engine.analyze_project(handle.path, target_url=target)
    except Exception as exc:
        console.print(f"[bold red]Erro durante Web Intelligence:[/] {exc}")
        raise typer.Exit(code=1)

    console.print("---")
    console.print("WEB INTELLIGENCE COMPLETE\n")
    console.print(f"Target: {report.target}")
    console.print(f"\nEndpoints: [bold]{report.total_endpoints}[/]")
    console.print(f"Parameters: [bold]{report.total_parameters}[/]")
    console.print(f"Indicators: [bold]{report.total_indicators}[/]")
    console.print(f"Opportunities: [bold]{report.total_opportunities}[/]")
    console.print(f"\nExposure: [bold]{report.overall_score}[/] — {report.risk_level}")

    if report.auth_profile:
        ap = report.auth_profile
        console.print("\nAuth Endpoints:")
        console.print(f"  Login: {len(ap.get('login_endpoints', []))}")
        console.print(f"  Register: {len(ap.get('register_endpoints', []))}")
        console.print(f"  Admin: {len(ap.get('admin_endpoints', []))}")
        console.print(f"  MFA: {len(ap.get('mfa_endpoints', []))}")

    if report.opportunities:
        console.print(f"\nTop 3 Opportunities:")
        for o in report.opportunities[:3]:
            color = "red" if o.classification == "CRITICAL" else "orange1" if o.classification == "HIGH" else "yellow"
            console.print(f"  [{color}]{o.classification}[/] {o.title} — Score: {o.score}/100")

    console.print("\nSaved Profiles:")
    console.print("  profiles/web_intelligence/")
    console.print("---")


@web_app.command("endpoints", help="Exibe o inventário de endpoints descobertos.")
def cmd_web_endpoints(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Exibe o inventário de endpoints web descobertos."""
    app_ctx: AppContext = ctx.obj
    handle = _resolve_project(app_ctx, project)
    import json
    path = handle.path / "profiles" / "web_intelligence" / "endpoint_inventory.json"
    if not path.exists():
        console.print("[yellow]Execute 'ghostmirror web' primeiro.[/]")
        raise typer.Exit(code=1)
    with open(path, "r", encoding="utf-8") as f:
        endpoints = json.load(f)

    table = Table(box=box.ROUNDED, header_style="bold cyan", title="Endpoint Inventory")
    table.add_column("URL", style="green")
    table.add_column("Status")
    table.add_column("Params")
    table.add_column("Forms")
    table.add_column("Type")
    for ep in endpoints[:50]:
        ep_type = "API" if ep.get("is_api") else "Auth" if ep.get("is_auth") else "Admin" if ep.get("is_admin") else "Static" if ep.get("is_static") else "Page"
        table.add_row(
            ep.get("url", "")[:80],
            str(ep.get("status_code", 0)),
            str(len(ep.get("params", []))),
            str(len(ep.get("forms", []))),
            ep_type,
        )
    console.print(table)
    console.print(f"\nTotal: {len(endpoints)} endpoints")


@web_app.command("parameters", help="Exibe o inventário de parâmetros descobertos.")
def cmd_web_parameters(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Exibe o inventário de parâmetros web descobertos."""
    app_ctx: AppContext = ctx.obj
    handle = _resolve_project(app_ctx, project)
    import json
    path = handle.path / "profiles" / "web_intelligence" / "parameter_inventory.json"
    if not path.exists():
        console.print("[yellow]Execute 'ghostmirror web' primeiro.[/]")
        raise typer.Exit(code=1)
    with open(path, "r", encoding="utf-8") as f:
        params = json.load(f)

    table = Table(box=box.ROUNDED, header_style="bold cyan", title="Parameter Inventory")
    table.add_column("Parameter", style="green")
    table.add_column("Type")
    table.add_column("Sensitivity")
    table.add_column("Locations")
    for p in params:
        sens = p.get("sensitivity", "none")
        color = "red" if sens in ("critical", "high") else "yellow" if sens == "medium" else "cyan"
        table.add_row(
            p.get("name", ""),
            p.get("param_type", "query"),
            f"[{color}]{sens}[/]",
            str(len(p.get("locations", []))),
        )
    console.print(table)
    console.print(f"\nTotal: {len(params)} parameters")


@web_app.command("auth", help="Exibe o perfil de autenticação descoberto.")
def cmd_web_auth(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Exibe o perfil de autenticação."""
    app_ctx: AppContext = ctx.obj
    handle = _resolve_project(app_ctx, project)
    import json
    path = handle.path / "profiles" / "web_intelligence" / "auth_profile.json"
    if not path.exists():
        console.print("[yellow]Execute 'ghostmirror web' primeiro.[/]")
        raise typer.Exit(code=1)
    with open(path, "r", encoding="utf-8") as f:
        auth = json.load(f)

    console.print(f"\n[bold cyan]Auth Profile[/]\n")
    console.print(f"Login: [green]{'Yes' if auth.get('has_login') else 'No'}[/] ({len(auth.get('login_endpoints', []))})")
    console.print(f"Register: [green]{'Yes' if auth.get('has_register') else 'No'}[/] ({len(auth.get('register_endpoints', []))})")
    console.print(f"Reset Password: [green]{'Yes' if auth.get('has_reset_password') else 'No'}[/] ({len(auth.get('reset_password_endpoints', []))})")
    console.print(f"Admin: [green]{'Yes' if auth.get('has_admin') else 'No'}[/] ({len(auth.get('admin_endpoints', []))})")
    console.print(f"MFA: [green]{'Yes' if auth.get('has_mfa') else 'No'}[/] ({len(auth.get('mfa_endpoints', []))})")
    console.print(f"\nTotal Auth Endpoints: {auth.get('total_auth_endpoints', 0)}")

    if auth.get("admin_endpoints"):
        console.print("\n[bold orange1]Admin Endpoints:[/]")
        for url in auth["admin_endpoints"]:
            console.print(f"  - {url}")


@web_app.command("js", help="Exibe a inteligência coletada de arquivos JavaScript.")
def cmd_web_js(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Exibe a inteligência de JavaScript."""
    app_ctx: AppContext = ctx.obj
    handle = _resolve_project(app_ctx, project)
    import json
    path = handle.path / "profiles" / "web_intelligence" / "js_intelligence.json"
    if not path.exists():
        console.print("[yellow]Execute 'ghostmirror web' primeiro.[/]")
        raise typer.Exit(code=1)
    with open(path, "r", encoding="utf-8") as f:
        js = json.load(f)

    console.print(f"\n[bold cyan]JS Intelligence[/]\n")
    console.print(f"Scripts Analyzed: {js.get('scripts_analyzed', 0)}")
    console.print(f"Endpoints Found: {len(js.get('endpoints_discovered', []))}")
    console.print(f"Secrets Found: {len(js.get('secrets_found', []))}")
    console.print(f"Internal URLs: {len(js.get('internal_urls', []))}")
    console.print(f"Interesting Comments: {len(js.get('interesting_comments', []))}")
    console.print(f"Internal Routes: {len(js.get('internal_routes', []))}")

    if js.get("secrets_found"):
        console.print("\n[bold red]⚠ Potential Secrets Found![/]")
        for secret in js["secrets_found"][:10]:
            console.print(f"  - {secret[:80]}")

    if js.get("internal_urls"):
        console.print("\n[bold orange1]Internal URLs Found:[/]")
        for url in js["internal_urls"][:10]:
            console.print(f"  - {url}")


@web_app.command("opportunities", help="Exibe a matriz de oportunidades de ataque.")
def cmd_web_opportunities(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Exibe a matriz de oportunidades de ataque."""
    app_ctx: AppContext = ctx.obj
    handle = _resolve_project(app_ctx, project)
    import json
    path = handle.path / "profiles" / "web_intelligence" / "opportunity_scores.json"
    if not path.exists():
        console.print("[yellow]Execute 'ghostmirror web' primeiro.[/]")
        raise typer.Exit(code=1)
    with open(path, "r", encoding="utf-8") as f:
        opportunities = json.load(f)

    console.print(f"\n[bold cyan]Opportunity Matrix[/]\n")
    if not opportunities:
        console.print("[yellow]No opportunities identified.[/]")
        return

    table = Table(box=box.ROUNDED, header_style="bold cyan", title="Attack Opportunities")
    table.add_column("Score", justify="right")
    table.add_column("Classification")
    table.add_column("Title")
    table.add_column("Endpoint")
    for opp in opportunities:
        score = opp.get("score", 0)
        color = "red" if score >= 76 else "orange1" if score >= 51 else "yellow" if score >= 26 else "cyan"
        table.add_row(
            f"[{color}]{score}[/]",
            f"[{color}]{opp.get('classification', 'LOW')}[/]",
            opp.get("title", "")[:50],
            opp.get("endpoint", "")[:60],
        )
    console.print(table)

    critical = [o for o in opportunities if o.get("classification") == "CRITICAL"]
    high = [o for o in opportunities if o.get("classification") == "HIGH"]
    console.print(f"\nCritical: {len(critical)} | High: {len(high)} | Total: {len(opportunities)}")


# Also add as analyze sub-command
@analyze_app.command("web", help="Web Intelligence Engine - análise passiva de vulnerabilidades web.")
def cmd_analyze_web(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
    target: str = typer.Option(None, "--target", "-t", help="URL alvo"),
) -> None:
    """Executa o Web Intelligence Engine."""
    ctx.invoke(cmd_web_main, ctx=ctx, project=project, target=target)


@analyze_app.command("api", help="API Security Intelligence — análise passiva de superfície de APIs.")
def cmd_analyze_api(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
    target: str = typer.Option(None, "--target", "-t", help="URL alvo"),
) -> None:
    """Executa o API Security Intelligence Engine."""
    ctx.invoke(cmd_api_main, ctx=ctx, project=project, target=target)


# --------------------------------------------------------------------------- #
# API Security Intelligence sub-app
# --------------------------------------------------------------------------- #
api_app = typer.Typer(help="API Security Intelligence: descoberta, análise e correlação de APIs.")
app.add_typer(api_app, name="api")


@api_app.callback(invoke_without_command=True)
def cmd_api_main(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
    target: str = typer.Option(None, "--target", "-t", help="URL alvo para análise de APIs"),
) -> None:
    """Executa o API Security Intelligence Engine completo no projeto."""
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

    from ghostmirror.modules.api_security.engine import APISecurityEngine

    engine = APISecurityEngine()
    try:
        with console.status("[bold green]Executando API Security Intelligence Engine...[/]"):
            report = engine.analyze_project(handle.path, target_url=target)
    except Exception as exc:
        console.print(f"[bold red]Erro durante API Security Intelligence:[/] {exc}")
        raise typer.Exit(code=1)

    console.print("---")
    console.print("API SECURITY INTELLIGENCE COMPLETE\n")
    console.print(f"Target: {report.target}")
    console.print(f"\nAPI Inventory: [bold]{report.api_inventory.get('total_endpoints', 0)}[/] endpoints")
    console.print(f"Swagger/OpenAPI: {'[green]Detected[/]' if report.swagger_profile and report.swagger_profile.get('detected') else '[dim]Not detected[/]'}")
    console.print(f"GraphQL: {'[green]Detected[/]' if report.graphql_profile and report.graphql_profile.get('detected') else '[dim]Not detected[/]'}")
    console.print(f"JWT: {'[green]Detected[/]' if report.jwt_profile and report.jwt_profile.get('detected') else '[dim]Not detected[/]'}")
    console.print(f"OAuth: {'[green]Detected[/]' if report.oauth_profile and report.oauth_profile.get('detected') else '[dim]Not detected[/]'}")
    console.print(f"Objects Mapped: [bold]{len(report.object_inventory)}[/]")
    console.print(f"\nBOLA Indicators: [bold]{len(report.bola_indicators)}[/]")
    console.print(f"BFLA Indicators: [bold]{len(report.bfla_indicators)}[/]")
    console.print(f"Mass Assignment: [bold]{len(report.mass_assignment_indicators)}[/]")
    console.print(f"Opportunities: [bold]{len(report.opportunities)}[/]")
    console.print(f"\nOverall Score: [bold]{report.overall_score}/100[/] — {report.risk_level}")

    if report.recommendations:
        console.print(f"\nTop Recommendations:")
        for rec in report.recommendations[:5]:
            console.print(f"  • {rec}")

    console.print("\nSaved Profiles:")
    console.print("  profiles/api_security/")
    console.print("---")


@api_app.command("inventory", help="Consolida o inventário de APIs descobertas por todas as fontes.")
def cmd_api_inventory(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Exibe o inventário consolidado de APIs."""
    app_ctx: AppContext = ctx.obj
    handle = _resolve_project(app_ctx, project)
    from ghostmirror.modules.api_security.api_inventory import APIInventory
    inventory = APIInventory()
    profile = inventory.consolidate(handle.path)

    table = Table(box=box.ROUNDED, header_style="bold cyan", title=f"API Inventory ({profile.total_endpoints})")
    table.add_column("Method")
    table.add_column("Path")
    table.add_column("Auth")
    table.add_column("Source")
    table.add_column("Confidence")
    for ep in profile.endpoints[:50]:
        auth = "[green]Yes[/]" if ep.get("auth_required") else "[dim]No[/]"
        table.add_row(
            ep.get("method", "GET"),
            ep.get("path", "")[:80],
            auth,
            ep.get("source", ""),
            ep.get("confidence", ""),
        )
    console.print(table)
    console.print(f"\nTotal: {profile.total_endpoints} endpoints")
    console.print(f"Methods: {profile.total_methods}")
    console.print(f"Sources: {profile.total_sources}")
    console.print(f"Auth Required: {profile.auth_required_count}")


@api_app.command("graphql", help="GraphQL Discovery — detecta endpoints e frameworks GraphQL.")
def cmd_api_graphql(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Executa GraphQL Discovery e Intelligence."""
    app_ctx: AppContext = ctx.obj
    handle = _resolve_project(app_ctx, project)
    from ghostmirror.modules.api_security.engine import APISecurityEngine
    engine = APISecurityEngine()
    report = engine.analyze_project(handle.path)

    if not report.graphql_profile or not report.graphql_profile.get("detected"):
        console.print("[yellow]Nenhum endpoint GraphQL detectado.[/]")
        return

    gql = report.graphql_profile
    console.print("---")
    console.print("GRAPHQL DISCOVERY RESULTS\n")
    console.print(f"Endpoints: {', '.join(gql.get('endpoints', []))}")
    console.print(f"Frameworks: {', '.join(gql.get('frameworks', [])) or 'None'}")

    intel = gql.get("intelligence", {})
    if intel:
        console.print(f"\nIntrospection: {'[red]Detected[/]' if intel.get('has_introspection') else '[green]Not detected[/]'}")
        console.print(f"Playground: {'[red]Detected[/]' if intel.get('has_playground') else '[green]Not detected[/]'}")
        console.print(f"GraphiQL: {'[red]Detected[/]' if intel.get('has_graphiql') else '[green]Not detected[/]'}")
        console.print(f"Exposure Level: [bold]{intel.get('exposure_level', 'LOW')}[/]")


@api_app.command("jwt", help="JWT Intelligence — detecta e analisa tokens JWT (redigido).")
def cmd_api_jwt(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Executa JWT Intelligence."""
    app_ctx: AppContext = ctx.obj
    handle = _resolve_project(app_ctx, project)
    from ghostmirror.modules.api_security.engine import APISecurityEngine
    engine = APISecurityEngine()
    report = engine.analyze_project(handle.path)

    if not report.jwt_profile or not report.jwt_profile.get("detected"):
        console.print("[yellow]Nenhum token JWT detectado.[/]")
        return

    jwt = report.jwt_profile
    console.print("---")
    console.print("JWT INTELLIGENCE RESULTS\n")
    console.print(f"Tokens Found: [bold]{jwt.get('total_tokens_found', 0)}[/]")
    console.print(f"Algorithms: {', '.join(jwt.get('algorithms', [])) or 'None'}")
    console.print(f"Has 'kid': {'Yes' if jwt.get('has_kid') else 'No'}")
    console.print(f"Has 'exp': {'Yes' if jwt.get('has_exp') else '[red]No (missing)[/]'}")
    if jwt.get("has_none_alg_indicator"):
        console.print("[red]WARNING: 'none' algorithm detected![/]")
    if jwt.get("weak_algorithms"):
        console.print(f"[yellow]Weak algorithms: {', '.join(jwt['weak_algorithms'])}[/]")
    if jwt.get("redacted_tokens"):
        console.print("\nRedacted tokens (first 3):")
        for t in jwt["redacted_tokens"][:3]:
            console.print(f"  {t}")


@api_app.command("oauth", help="OAuth/OIDC Intelligence — detecta provedores e endpoints de autorização.")
def cmd_api_oauth(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Executa OAuth Intelligence."""
    app_ctx: AppContext = ctx.obj
    handle = _resolve_project(app_ctx, project)
    from ghostmirror.modules.api_security.engine import APISecurityEngine
    engine = APISecurityEngine()
    report = engine.analyze_project(handle.path)

    if not report.oauth_profile or not report.oauth_profile.get("detected"):
        console.print("[yellow]Nenhum provedor OAuth/OIDC detectado.[/]")
        return

    oa = report.oauth_profile
    console.print("---")
    console.print("OAUTH/OIDC INTELLIGENCE RESULTS\n")
    console.print(f"Providers: {', '.join(oa.get('providers', [])) or 'None'}")
    console.print(f"Authorize Endpoint: {'Yes' if oa.get('has_authorize') else 'No'}")
    console.print(f"Token Endpoint: {'Yes' if oa.get('has_token') else 'No'}")
    console.print(f"UserInfo Endpoint: {'Yes' if oa.get('has_userinfo') else 'No'}")
    console.print(f"JWKS Endpoint: {'Yes' if oa.get('has_jwks') else 'No'}")
    endpoints = oa.get("endpoints", {})
    for etype, epaths in endpoints.items():
        console.print(f"\n{etype.upper()}:")
        for p in epaths[:5]:
            console.print(f"  {p}")


@api_app.command("opportunities", help="Exibe a matriz de oportunidades de API Security.")
def cmd_api_opportunities(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Exibe a API Opportunity Matrix."""
    app_ctx: AppContext = ctx.obj
    handle = _resolve_project(app_ctx, project)

    import json
    path = handle.path / "profiles" / "api_security" / "api_opportunities.json"
    if not path.exists():
        console.print("[yellow]Execute 'ghostmirror api' ou 'ghostmirror analyze api' primeiro.[/]")
        raise typer.Exit(code=1)

    with open(path, "r", encoding="utf-8") as f:
        opportunities = json.load(f)

    if not opportunities:
        console.print("[yellow]Nenhuma oportunidade identificada.[/]")
        return

    table = Table(box=box.ROUNDED, header_style="bold cyan", title=f"API Opportunity Matrix ({len(opportunities)})")
    table.add_column("Score", justify="right")
    table.add_column("Classification")
    table.add_column("Type")
    table.add_column("Title")
    for opp in opportunities[:20]:
        score = opp.get("score", 0)
        cls = opp.get("classification", "LOW")
        color = "red" if cls == "CRITICAL" else "orange1" if cls == "HIGH" else "yellow" if cls == "MEDIUM" else "green"
        table.add_row(
            str(score),
            f"[{color}]{cls}[/]",
            opp.get("type", ""),
            opp.get("title", "")[:80],
        )
    console.print(table)

    critical = [o for o in opportunities if o.get("classification") == "CRITICAL"]
    high = [o for o in opportunities if o.get("classification") == "HIGH"]
    console.print(f"\nCritical: {len(critical)} | High: {len(high)} | Total: {len(opportunities)}")


def _resolve_project(app_ctx: AppContext, project: str | None) -> ProjectHandle:
    """Helper to resolve a project slug or prompt the user."""
    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado.[/]")
            raise typer.Exit(code=1)
        _render_projects_table(handles)
        project = Prompt.ask("Selecione o projeto pelo slug").strip()
        if not project:
            console.print("[bold red]Slug do projeto obrigatório.[/]")
            raise typer.Exit(code=1)
    try:
        return app_ctx.projects.open_project(project)
    except Exception as exc:
        console.print(f"[bold red]Erro ao abrir o projeto:[/] {exc}")
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
    table.add_column("URL")
    for e in entries:
        status = "[green]✓ Rodando[/]" if e["running"] else "[dim]Parado[/]"
        table.add_row(e["id"], e["name"], status, str(e["port"]), e.get("url", "—"))
    console.print(table)


@lab_app.command("health", help="Executa verificação de saúde de 5 pontos em um laboratório.")
def cmd_lab_health(
    lab_id: str = typer.Argument(..., help="ID do laboratório (ex: juice-shop)"),
) -> None:
    from ghostmirror.modules.lab import LabManager, LabHealth

    manager = LabManager()
    try:
        health: LabHealth = manager.health(lab_id)
        from ghostmirror.modules.lab.health import LabHealth
        health_obj: LabHealth = health
        results = health_obj.check_all()
        all_ok = all(results.values())

        table = Table(
            box=box.ROUNDED,
            header_style="bold cyan",
            title=f"Health Check: {lab_id}",
            show_header=True,
        )
        table.add_column("Verificação", style="cyan")
        table.add_column("Status", justify="center")
        for check_name, passed in results.items():
            status = "[green]✓ OK[/]" if passed else "[red]✗ FALHA[/]"
            table.add_row(check_name, status)
        console.print(table)

        if all_ok:
            console.print(f"\n[bold green]✓ Health: OK[/]")
        else:
            console.print(f"\n[bold red]✗ Health: FALHA[/] — {sum(1 for v in results.values() if not v)} check(s) com problema")
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


# --------------------------------------------------------------------------- #
# Bug Bounty Mode sub-app
# --------------------------------------------------------------------------- #
bounty_app = typer.Typer(help="Bug Bounty Mode: reconhecimento avançado de aplicações modernas/SPAs.")
app.add_typer(bounty_app, name="bounty")


@bounty_app.callback(invoke_without_command=True)
def cmd_bounty_callback(ctx: typer.Context) -> None:
    """Bug Bounty Mode entry point - lists all available bug bounty commands."""
    if ctx.invoked_subcommand is not None:
        return
    console.print(Panel.fit(
        "[bold cyan]Bug Bounty Mode[/]\n\n"
        "Comandos disponíveis:\n"
        "  [green]crawl[/]     Headless crawler (descobre rotas SPA)\n"
        "  [green]js[/]        JS Bundle Intelligence\n"
        "  [green]apis[/]      API Discovery\n"
        "  [green]secrets[/]   Secrets Discovery\n"
        "  [green]report[/]    Gera relatório Bug Bounty\n"
        "  [green]scan[/]      Executa Bug Bounty completo\n\n"
        "Use [bold]ghostmirror bounty <comando> --help[/] para detalhes.",
        border_style="cyan",
    ))


@bounty_app.command("crawl", help="Headless crawler: descobre rotas SPA, links e forms renderizados.")
def cmd_bounty_crawl(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="URL alvo (ex: https://example.com)"),
    max_pages: int = typer.Option(10, "--max-pages", help="Máximo de páginas a crawlear"),
    max_depth: int = typer.Option(2, "--max-depth", help="Profundidade máxima do crawl"),
    timeout: int = typer.Option(30, "--timeout", help="Timeout em segundos por página"),
) -> None:
    ctx = _resolve_context(ctx)
    try:
        from ghostmirror.modules.bug_bounty.headless_crawler import HeadlessCrawler
        from ghostmirror.modules.bug_bounty.scope_guard import BountyScopeGuard

        crawler = HeadlessCrawler(max_pages=max_pages, max_depth=max_depth, timeout=timeout)
        guard = None
        if ctx and ctx.active_project:
            guard = BountyScopeGuard(project_path=ctx.active_project.path)

        with console.status("[bold cyan]Crawleando alvo com headless browser...[/]"):
            routes = crawler.crawl(target, guard)

        if not routes:
            console.print("[yellow]Nenhuma rota descoberta.[/]")
            return

        table = Table(box=box.ROUNDED, header_style="bold cyan", title=f"Rotas Descobertas ({len(routes)})")
        table.add_column("URL", style="green")
        table.add_column("Status")
        table.add_column("Title")
        table.add_column("Tipo")
        for r in routes:
            status_color = "green" if r.status == 200 else ("yellow" if r.status < 400 else "red")
            table.add_row(r.url, f"[{status_color}]{r.status}[/]", r.title[:60], r.route_type)
        console.print(table)
    except Exception as exc:
        if "Playwright" in str(exc):
            console.print("[yellow]Playwright não está instalado. Execute:[/]")
            console.print("  [bold]pip install playwright[/]")
            console.print("  [bold]python -m playwright install chromium[/]")
        else:
            console.print(f"[bold red]Erro:[/] {exc}")
            raise typer.Exit(code=1)


@bounty_app.command("js", help="JS Bundle Intelligence: analisa bundles JS em busca de rotas, endpoints e segredos.")
def cmd_bounty_js(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="URL alvo"),
) -> None:
    ctx = _resolve_context(ctx)
    try:
        from ghostmirror.modules.bug_bounty.js_bundle_analyzer import JSBundleAnalyzer

        analyzer = JSBundleAnalyzer()

        js_urls = _collect_js_urls(target)
        if not js_urls:
            console.print("[yellow]Nenhum bundle JS encontrado.[/]")
            return

        with console.status("[bold cyan]Analisando bundles JS...[/]"):
            profiles = analyzer.analyze(js_urls)

        if not profiles:
            console.print("[yellow]Nenhuma informação extraída dos bundles JS.[/]")
            return

        total_endpoints = len(analyzer.get_all_endpoints(profiles))
        total_routes = len(analyzer.get_all_routes(profiles))
        total_secrets = sum(len(p.secrets) for p in profiles)
        total_comments = sum(len(p.comments) for p in profiles)

        console.print(f"[bold green]JS Bundle Intelligence[/]\n")
        console.print(f"  Bundles analisados: {len(profiles)}")
        console.print(f"  Endpoints descobertos: {total_endpoints}")
        console.print(f"  Rotas frontend: {total_routes}")
        console.print(f"  Segredos potenciais: {total_secrets}")
        console.print(f"  Comentários interessantes: {total_comments}")

        if total_endpoints > 0:
            table = Table(box=box.ROUNDED, header_style="bold cyan", title="Endpoints nos Bundles")
            table.add_column("Endpoint")
            eps = list(set(analyzer.get_all_endpoints(profiles)))
            for ep in sorted(eps)[:30]:
                table.add_row(ep)
            console.print(table)

    except Exception as exc:
        console.print(f"[bold red]Erro:[/] {exc}")
        raise typer.Exit(code=1)


@bounty_app.command("apis", help="API Discovery: descobre endpoints de API combinando múltiplas fontes.")
def cmd_bounty_apis(
    ctx: typer.Context,
) -> None:
    ctx = _resolve_context(ctx)
    if not ctx or not ctx.active_project:
        console.print("[yellow]Nenhum projeto ativo. Use 'ghostmirror open <slug>' primeiro.[/]")
        raise typer.Exit(code=1)

    try:
        from ghostmirror.modules.bug_bounty.api_discovery import APIDiscovery

        discovery = APIDiscovery()
        apis = discovery.combine()

        if not apis:
            console.print("[yellow]Nenhuma API descoberta.[/]")
            return

        table = Table(box=box.ROUNDED, header_style="bold cyan", title=f"API Inventory ({len(apis)})")
        table.add_column("Método")
        table.add_column("URL")
        table.add_column("Fonte")
        table.add_column("Confiança")
        for api in apis:
            table.add_row(api.method, api.url, api.source, api.confidence)
        console.print(table)
    except Exception as exc:
        console.print(f"[bold red]Erro:[/] {exc}")
        raise typer.Exit(code=1)


@bounty_app.command("secrets", help="Secrets Discovery: busca segredos expostos em HTML e JS (redigido).")
def cmd_bounty_secrets(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="URL alvo"),
) -> None:
    ctx = _resolve_context(ctx)
    try:
        import httpx
        from ghostmirror.modules.bug_bounty.secrets_discovery import SecretsDiscovery

        with console.status("[bold cyan]Buscando segredos..."):
            resp = httpx.get(target, timeout=15.0, verify=False)
            html = resp.text
            js_urls = _collect_js_urls(target)
            js_content = ""
            for js_url in js_urls:
                try:
                    js_resp = httpx.get(js_url, timeout=10.0, verify=False)
                    js_content += js_resp.text + "\n"
                except Exception:
                    pass

            discovery = SecretsDiscovery()
            secrets = discovery.scan(html, js_content, target)

        if not secrets:
            console.print("[green]Nenhum segredo potencial encontrado.[/]")
            return

        table = Table(box=box.ROUNDED, header_style="bold cyan", title=f"Segredos Potenciais ({len(secrets)})")
        table.add_column("Tipo")
        table.add_column("Valor (Redigido)")
        table.add_column("Severidade")
        table.add_column("Local")
        for s in secrets:
            sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "green"}.get(s.severity, "white")
            table.add_row(s.type, s.redacted_snippet, f"[{sev_color}]{s.severity.upper()}[/]", s.location)
        console.print(table)
    except Exception as exc:
        console.print(f"[bold red]Erro:[/] {exc}")
        raise typer.Exit(code=1)


@bounty_app.command("report", help="Gera relatório Bug Bounty com todas as descobertas.")
def cmd_bounty_report(
    ctx: typer.Context,
) -> None:
    ctx = _resolve_context(ctx)
    if not ctx or not ctx.active_project:
        console.print("[yellow]Nenhum projeto ativo. Use 'ghostmirror open <slug>' primeiro.[/]")
        raise typer.Exit(code=1)

    try:
        from ghostmirror.modules.bug_bounty.engine import BugBountyEngine

        engine = BugBountyEngine(profile="bounty")
        with console.status("[bold cyan]Gerando relatório Bug Bounty..."):
            result = engine.analyze_project(ctx.active_project.path)

        if result.get("status") == "skipped":
            console.print(f"[yellow]Bug Bounty Mode: {result.get('reason', 'Skipped')}[/]")
            return

        report_data = result.get("report", {})
        score = report_data.get("overall_score", 0)
        level = report_data.get("risk_level", "INFO")

        score_color = "green" if score <= 20 else ("yellow" if score <= 40 else ("red" if score <= 70 else "red"))
        console.print(f"\n[bold]Bug Bounty Report[/]")
        console.print(f"  Score: [bold {score_color}]{score}/100 ({level})[/]")
        console.print(f"  Rotas: {report_data.get('total_routes', 0)}")
        console.print(f"  APIs: {report_data.get('total_apis', 0)}")
        console.print(f"  Bundles JS: {report_data.get('total_bundles', 0)}")
        console.print(f"  Segredos: {report_data.get('total_secrets', 0)}")
        console.print(f"  Oportunidades: {report_data.get('total_opportunities', 0)}")
        console.print(f"  Subdomínios: {report_data.get('total_subdomains', 0)}")

        recs = report_data.get("recommendations", [])
        if recs:
            console.print("\n[bold cyan]Recomendações:[/]")
            for rec in recs:
                console.print(f"  • {rec}")

        console.print(f"\n[dim]Relatório salvo em: profiles/bug_bounty/bug_bounty_report.json[/]")
    except Exception as exc:
        console.print(f"[bold red]Erro:[/] {exc}")
        raise typer.Exit(code=1)


@bounty_app.command("scan", help="Executa Bug Bounty completo (crawl + JS + APIs + secrets + report).")
def cmd_bounty_scan(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="URL alvo (ex: https://example.com)"),
    profile: str = typer.Option("bounty", "--profile", help="Perfil de reconhecimento (lite, standard, deep, bounty)"),
) -> None:
    ctx = _resolve_context(ctx)
    try:
        from ghostmirror.modules.bug_bounty.engine import BugBountyEngine

        engine = BugBountyEngine(profile=profile)
        with console.status("[bold cyan]Executando Bug Bounty Scan..."):
            result = engine.analyze_project(
                ctx.active_project.path if ctx and ctx.active_project else ctx.config.projects_dir,
                target,
            )

        if result.get("status") == "skipped":
            console.print(f"[yellow]Bug Bounty: {result.get('reason', 'Skipped')}[/]")
            return

        report_data = result.get("report", {})
        score = report_data.get("overall_score", 0)
        level = report_data.get("risk_level", "INFO")

        score_color = "green" if score <= 20 else ("yellow" if score <= 40 else ("red" if score <= 70 else "red"))
        console.print(f"\n[bold green]✓ Bug Bounty Scan concluído[/]")
        console.print(f"  Score: [bold {score_color}]{score}/100 ({level})[/]")
        console.print(f"  Rotas: {report_data.get('total_routes', 0)}")
        console.print(f"  APIs: {report_data.get('total_apis', 0)}")
        console.print(f"  Segredos: {report_data.get('total_secrets', 0)}")
        console.print(f"  Oportunidades: {report_data.get('total_opportunities', 0)}")

        opps = result.get("opportunities", [])
        if opps:
            table = Table(box=box.ROUNDED, header_style="bold cyan", title="Oportunidades")
            table.add_column("Título")
            table.add_column("Score")
            table.add_column("Severidade")
            table.add_column("Tipo")
            for o in sorted(opps, key=lambda x: x.get("score", 0), reverse=True)[:10]:
                sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(
                    o.get("severity", "LOW"), "white"
                )
                table.add_row(
                    o.get("title", "")[:60],
                    str(o.get("score", 0)),
                    f"[{sev_color}]{o.get('severity', 'LOW')}[/]",
                    o.get("type", ""),
                )
            console.print(table)
    except Exception as exc:
        if "Playwright" in str(exc):
            console.print("[yellow]Playwright não está instalado. Execute:[/]")
            console.print("  [bold]pip install playwright[/]")
            console.print("  [bold]python -m playwright install chromium[/]")
        else:
            console.print(f"[bold red]Erro:[/] {exc}")
            raise typer.Exit(code=1)


def _collect_js_urls(target: str) -> list[str]:
    import httpx
    import re
    from urllib.parse import urljoin

    js_urls = []
    try:
        resp = httpx.get(target, timeout=15.0, verify=False)
        script_pattern = re.compile(r'<script\s[^>]*src=["\'](.*?)["\']', re.IGNORECASE)
        for match in script_pattern.findall(resp.text):
            absolute = urljoin(target, match.strip())
            if absolute not in js_urls:
                js_urls.append(absolute)
    except Exception:
        pass
    return js_urls


def _resolve_context(ctx: typer.Context) -> AppContext | None:
    """Resolve AppContext from Typer context if available."""
    return ctx.parent.obj if ctx.parent and hasattr(ctx.parent, "obj") else getattr(ctx, "obj", None)


# --------------------------------------------------------------------------- #
# Findings Intelligence sub-app
# --------------------------------------------------------------------------- #
findings_app = typer.Typer(help="Finding Intelligence Engine: enriquece, prioriza e analisa findings.")
app.add_typer(findings_app, name="findings")


@findings_app.command("intelligence", help="Executa o Finding Intelligence Engine para enriquecer todos os findings.")
def cmd_findings_intelligence(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    app_ctx: AppContext = ctx.obj

    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado.[/]")
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

    from ghostmirror.modules.finding_intelligence.engine import FindingIntelligenceEngine

    engine = FindingIntelligenceEngine()
    try:
        with console.status("[bold green]Executando Finding Intelligence Engine..."):
            report = engine.analyze_project(handle.path)
    except Exception as exc:
        console.print(f"[bold red]Erro durante Finding Intelligence:[/] {exc}")
        raise typer.Exit(code=1)

    console.print("---")
    console.print("FINDING INTELLIGENCE COMPLETE\n")
    console.print(f"Total Findings: [bold]{report.total_findings}[/]")
    console.print(f"Enriched: [bold]{report.total_enriched}[/]")
    console.print(f"\nPriority Distribution:")
    for p in ["P1", "P2", "P3", "P4", "P5"]:
        count = report.priority_counts.get(p, 0)
        color = "red" if p == "P1" else "orange1" if p == "P2" else "yellow" if p == "P3" else "cyan" if p == "P4" else "dim"
        console.print(f"  {p}: [{color}]{count}[/]")
    console.print(f"\nKEV Count: [bold]{report.kev_count}[/]")
    console.print(f"Exploit Count: [bold]{report.exploit_count}[/]")
    console.print(f"\nQuick Wins: [bold]{len(report.quick_wins)}[/]")
    console.print(f"\nTop Finding: {report.top_findings[0].title if report.top_findings else 'N/A'}")
    console.print("---")


@findings_app.command("priority", help="Exibe a matriz de prioridades dos findings enriquecidos.")
def cmd_findings_priority(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    app_ctx: AppContext = ctx.obj

    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado.[/]")
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

    import json
    report_path = handle.path / "profiles" / "finding_intelligence_report.json"
    if not report_path.exists():
        console.print("[yellow]Execute 'ghostmirror findings intelligence' primeiro.[/]")
        raise typer.Exit(code=1)

    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    matrix = report.get("priority_matrix", {})
    console.print("\n[bold cyan]Priority Matrix[/]\n")
    table = Table(box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Priority", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Status")
    for p in ["P1", "P2", "P3", "P4", "P5"]:
        count = matrix.get(p, 0)
        color = "red" if p == "P1" else "orange1" if p == "P2" else "yellow" if p == "P3" else "green" if p == "P4" else "dim"
        status = "🔴 Crítico" if p == "P1" else "🟠 Alto" if p == "P2" else "🟡 Médio" if p == "P3" else "🟢 Baixo" if p == "P4" else "⚪ Info"
        table.add_row(f"[{color}]{p}[/]", str(count), status)
    console.print(table)

    total = sum(matrix.values())
    console.print(f"\nTotal: [bold]{total}[/] findings classified")


@findings_app.command("top10", help="Exibe o Top 10 Findings ordenados por prioridade.")
def cmd_findings_top10(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    app_ctx: AppContext = ctx.obj

    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado.[/]")
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

    import json
    top_path = handle.path / "profiles" / "top_findings.json"
    if not top_path.exists():
        console.print("[yellow]Execute 'ghostmirror findings intelligence' primeiro.[/]")
        raise typer.Exit(code=1)

    with open(top_path, "r", encoding="utf-8") as f:
        top = json.load(f)

    console.print("\n[bold cyan]Top 10 Findings[/bold cyan]\n")
    for i, finding in enumerate(top, 1):
        sev = finding.get("severity", "INFO").upper()
        sev_color = "red" if sev == "CRITICAL" else "orange1" if sev == "HIGH" else "yellow" if sev == "MEDIUM" else "cyan"
        priority = finding.get("priority", "P5")
        p_color = "red" if priority == "P1" else "orange1" if priority == "P2" else "yellow" if priority == "P3" else "dim"
        console.print(f"#{i} [{sev_color}][{sev}][/] [{p_color}]{priority}[/] — {finding.get('title', '?')}")
        console.print(f"   Asset: {finding.get('affected_asset', '—')} | Component: {finding.get('affected_component', '—')}")
        console.print(f"   Confidence: {finding.get('confidence', 'LOW')} | Likelihood: {finding.get('likelihood', '—')} | Exploitability: {finding.get('exploitability', '—')}")
        if finding.get("recommendation"):
            console.print(f"   → {finding['recommendation'][:120]}")
        console.print()


@findings_app.command("quick-wins", help="Lista correções rápidas identificadas.")
def cmd_findings_quick_wins(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    app_ctx: AppContext = ctx.obj

    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado.[/]")
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

    import json
    qw_path = handle.path / "profiles" / "quick_wins.json"
    if not qw_path.exists():
        console.print("[yellow]Execute 'ghostmirror findings intelligence' primeiro.[/]")
        raise typer.Exit(code=1)

    with open(qw_path, "r", encoding="utf-8") as f:
        wins = json.load(f)

    if not wins:
        console.print("[green]Nenhum quick win identificado.[/]")
        return

    console.print(f"\n[bold cyan]Quick Wins ({len(wins)} encontrados)[/bold cyan]\n")
    for i, win in enumerate(wins, 1):
        console.print(f"{i}. {win.get('title', '?')}")
        console.print(f"   Severity: {win.get('severity', 'INFO')} | Priority: {win.get('priority', 'P5')}")
        if win.get("recommendation"):
            console.print(f"   → {win['recommendation'][:180]}")
        console.print()


# --------------------------------------------------------------------------- #
# Bug Bounty sub-app
# --------------------------------------------------------------------------- #
bounty_app = typer.Typer(help="Bug Bounty Mode — Headless crawling, JS intelligence, API discovery, secrets, recon.")
app.add_typer(bounty_app, name="bounty")


@bounty_app.command("scan", help="Executa o Bug Bounty Engine completo (crawl + JS + APIs + secrets + recon).")
def cmd_bounty_scan(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
    profile: str = typer.Option("bounty", "--profile", help="Perfil de recon (lite, standard, deep, bounty)"),
) -> None:
    app_ctx: AppContext = ctx.obj
    handle = _resolve_project(app_ctx, project)
    scope = app_ctx.projects.read_scope(handle)
    target = (scope.targets.urls[0] if scope.targets.urls else "") or handle.metadata.domain or (scope.targets.domains[0] if scope.targets.domains else "")
    if not target:
        console.print("[bold red]Nenhum alvo cadastrado no projeto.[/]")
        raise typer.Exit(code=1)

    from ghostmirror.modules.bug_bounty.engine import BugBountyEngine
    engine = BugBountyEngine(profile=profile)
    try:
        with console.status(f"[bold green]Executando Bug Bounty ({profile.upper()})..."):
            result = engine.analyze_project(handle.path, target)
        if result.get("status") == "skipped":
            console.print(f"[yellow]Bug Bounty pulado: {result.get('reason', '')}[/]")
            return
        console.print("[bold green]Bug Bounty Scan concluído![/]")
        console.print(f"Rotas: {len(result.get('routes', []))}")
        console.print(f"APIs: {len(result.get('apis', []))}")
        console.print(f"Segredos: {len(result.get('secrets', []))}")
        console.print(f"Oportunidades: {result.get('findings_generated', 0)}")
        console.print(f"Score: {result.get('overall_score', 0)}/100 — {result.get('risk_level', 'INFO')}")
    except Exception as exc:
        console.print(f"[bold red]Erro no Bug Bounty Scan:[/] {exc}")
        raise typer.Exit(code=1)


@bounty_app.command("crawl", help="Executa apenas o headless crawler para descobrir rotas SPA.")
def cmd_bounty_crawl(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
    max_pages: int = typer.Option(10, "--max-pages", help="Máximo de páginas para crawlear"),
    max_depth: int = typer.Option(2, "--max-depth", help="Profundidade máxima do crawl"),
) -> None:
    app_ctx: AppContext = ctx.obj
    handle = _resolve_project(app_ctx, project)
    scope = app_ctx.projects.read_scope(handle)
    target = (scope.targets.urls[0] if scope.targets.urls else "") or handle.metadata.domain or (scope.targets.domains[0] if scope.targets.domains else "")
    if not target:
        console.print("[bold red]Nenhum alvo cadastrado.[/]")
        raise typer.Exit(code=1)

    from ghostmirror.modules.bug_bounty.headless_crawler import HeadlessCrawler
    from ghostmirror.modules.bug_bounty.scope_guard import BountyScopeGuard
    scope_guard = BountyScopeGuard(handle.path, max_pages=max_pages, max_depth=max_depth, timeout=30)
    scope_guard.load_scope()
    target_url = target if target.startswith("http") else f"https://{target}"
    crawler = HeadlessCrawler(max_pages=max_pages, max_depth=max_depth)
    try:
        with console.status("[bold green]Crawleando com headless browser..."):
            routes = crawler.crawl(target_url, scope_guard)
        console.print(f"[bold green]Crawl concluído! {len(routes)} rotas encontradas.[/]")
        table = Table(box=box.ROUNDED, header_style="bold cyan", title="Headless Routes")
        table.add_column("URL")
        table.add_column("Status")
        table.add_column("Title")
        table.add_column("Type")
        for r in routes[:25]:
            table.add_row(r.url[:80], str(r.status), r.title[:50], r.route_type)
        console.print(table)
        if len(routes) > 25:
            console.print(f"[dim]Mostrando 25 de {len(routes)} rotas[/]")
    except Exception as exc:
        console.print(f"[bold red]Erro no crawl:[/] {exc}")
        raise typer.Exit(code=1)


@bounty_app.command("js", help="Analisa bundles JavaScript em busca de endpoints, secrets e rotas.")
def cmd_bounty_js(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    app_ctx: AppContext = ctx.obj
    handle = _resolve_project(app_ctx, project)
    scope = app_ctx.projects.read_scope(handle)
    target = (scope.targets.urls[0] if scope.targets.urls else "") or handle.metadata.domain or (scope.targets.domains[0] if scope.targets.domains else "")
    if not target:
        console.print("[bold red]Nenhum alvo cadastrado.[/]")
        raise typer.Exit(code=1)

    from ghostmirror.modules.bug_bounty.js_bundle_analyzer import JSBundleAnalyzer
    analyzer = JSBundleAnalyzer()
    target_url = target if target.startswith("http") else f"https://{target}"
    import httpx, re
    from urllib.parse import urljoin
    js_urls = []
    try:
        resp = httpx.get(target_url, timeout=15.0, verify=False,
                         headers={"User-Agent": "GhostMirror-BugBounty/1.0"})
        if resp.status_code == 200:
            for match in re.finditer(r'<script\s[^>]*src=["\'](.*?)["\']', resp.text, re.IGNORECASE):
                js_urls.append(urljoin(target_url, match.group(1).strip()))
    except Exception as exc:
        console.print(f"[yellow]Aviso ao buscar HTML: {exc}[/]")

    if not js_urls:
        console.print("[yellow]Nenhum script encontrado no HTML.[/]")
        return

    with console.status(f"[bold green]Analisando {len(js_urls)} bundles JavaScript..."):
        profiles = analyzer.analyze(js_urls)

    if not profiles:
        console.print("[yellow]Nenhum bundle pôde ser analisado.[/]")
        return

    console.print(f"[bold green]{len(profiles)} bundles analisados![/]")
    all_endpoints = set()
    all_secrets = set()
    all_routes = set()
    for p in profiles:
        all_endpoints.update(p.endpoints)
        all_secrets.update(p.secrets)
        all_routes.update(p.routes)
        if p.source_map_present:
            console.print(f"  [yellow]⚠ Source map presente: {p.source_map_url}[/]")

    console.print(f"\nEndpoints: [bold]{len(all_endpoints)}[/]")
    for ep in sorted(all_endpoints)[:20]:
        console.print(f"  - {ep}")
    if len(all_endpoints) > 20:
        console.print(f"  ... e mais {len(all_endpoints) - 20}")

    if all_secrets:
        console.print(f"\n[red]⚠ Secrets encontrados: {len(all_secrets)}[/]")
        for s in sorted(all_secrets)[:10]:
            console.print(f"  - {s[:60]}")

    if all_routes:
        console.print(f"\nRotas frontend: {len(all_routes)}")
        for r in sorted(all_routes)[:15]:
            console.print(f"  - {r}")


@bounty_app.command("apis", help="Exibe o inventário de APIs descobertas pelo Bug Bounty.")
def cmd_bounty_apis(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    app_ctx: AppContext = ctx.obj
    handle = _resolve_project(app_ctx, project)
    import json
    path = handle.path / "profiles" / "bug_bounty" / "api_inventory.json"
    if not path.exists():
        console.print("[yellow]Execute 'ghostmirror bounty scan' primeiro.[/]")
        raise typer.Exit(code=1)
    with open(path, "r", encoding="utf-8") as f:
        apis = json.load(f)
    console.print(f"\n[bold cyan]API Inventory ({len(apis)} endpoints)[/]\n")
    table = Table(box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Method")
    table.add_column("URL")
    table.add_column("Source")
    table.add_column("Confidence")
    for a in apis[:30]:
        table.add_row(
            a.get("method", "GET"),
            a.get("url", "")[:80],
            a.get("source", ""),
            a.get("confidence", ""),
        )
    console.print(table)
    if len(apis) > 30:
        console.print(f"[dim]Mostrando 30 de {len(apis)} APIs[/]")


@bounty_app.command("secrets", help="Escaneia por secrets expostos em HTML e JS.")
def cmd_bounty_secrets(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    app_ctx: AppContext = ctx.obj
    handle = _resolve_project(app_ctx, project)
    import json
    path = handle.path / "profiles" / "bug_bounty" / "secrets_discovery.json"
    if not path.exists():
        console.print("[yellow]Execute 'ghostmirror bounty scan' primeiro.[/]")
        raise typer.Exit(code=1)
    with open(path, "r", encoding="utf-8") as f:
        secrets = json.load(f)
    if not secrets:
        console.print("[green]Nenhum secret encontrado.[/]")
        return
    console.print(f"\n[bold red]⚠ Secrets encontrados: {len(secrets)}[/]\n")
    table = Table(box=box.ROUNDED, header_style="bold cyan")
    table.add_column("Type")
    table.add_column("Redacted Value")
    table.add_column("Severity")
    table.add_column("Location")
    for s in secrets:
        sev_color = "red" if s.get("severity", "").upper() in ("CRITICAL", "HIGH") else "yellow"
        table.add_row(
            s.get("type", ""),
            f"[green]{s.get('redacted_snippet', '')}[/]",
            f"[{sev_color}]{s.get('severity', '').upper()}[/]",
            s.get("location", "")[:60],
        )
    console.print(table)


@bounty_app.command("report", help="Exibe o relatório completo do Bug Bounty Mode.")
def cmd_bounty_report(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    app_ctx: AppContext = ctx.obj
    handle = _resolve_project(app_ctx, project)
    import json
    path = handle.path / "profiles" / "bug_bounty" / "bug_bounty_report.json"
    if not path.exists():
        console.print("[yellow]Execute 'ghostmirror bounty scan' primeiro.[/]")
        raise typer.Exit(code=1)
    with open(path, "r", encoding="utf-8") as f:
        report = json.load(f)

    console.print(f"\n[bold cyan]Bug Bounty Report[/]")
    console.print(f"Target: [green]{report.get('target', '?')}[/]")
    console.print(f"Score: {report.get('overall_score', 0)}/100 — {report.get('risk_level', 'INFO')}")
    console.print(f"\nSummary:")
    console.print(f"  Routes: {report.get('total_routes', 0)}")
    console.print(f"  APIs: {report.get('total_apis', 0)}")
    console.print(f"  Bundles: {report.get('total_bundles', 0)}")
    console.print(f"  Secrets: {report.get('total_secrets', 0)}")
    console.print(f"  Subdomains: {report.get('total_subdomains', 0)}")
    console.print(f"  Opportunities: {report.get('total_opportunities', 0)}")

    opps = report.get("opportunities", [])
    if opps:
        console.print(f"\n[bold]Opportunity Matrix ({len(opps)}):[/]")
        table = Table(box=box.ROUNDED, header_style="bold cyan")
        table.add_column("Score")
        table.add_column("Severity")
        table.add_column("Title")
        table.add_column("Type")
        for o in sorted(opps, key=lambda x: x.get("score", 0), reverse=True)[:10]:
            sev = o.get("severity", "LOW")
            sev_color = "red" if sev in ("CRITICAL", "HIGH") else "yellow"
            table.add_row(
                str(o.get("score", 0)),
                f"[{sev_color}]{sev}[/]",
                o.get("title", "")[:60],
                o.get("type", ""),
            )
        console.print(table)

    recs = report.get("recommendations", [])
    if recs:
        console.print(f"\n[bold]Recommendations:[/]")
        for r in recs:
            console.print(f"  • {r}")


# --------------------------------------------------------------------------- #
# Zero-Day Hypothesis Engine sub-app
# --------------------------------------------------------------------------- #
zeroday_app = typer.Typer(help="Zero-Day Hypothesis Engine: detecta anomalias, gera hipóteses de vulnerabilidades e prioriza pesquisa.")
app.add_typer(zeroday_app, name="zero-day")


@zeroday_app.command("run", help="Executa o Zero-Day Hypothesis Engine completo.")
def cmd_zeroday_run(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    app_ctx: AppContext = ctx.obj

    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado.[/]")
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

    from ghostmirror.modules.zero_day.engine import ZeroDayEngine

    engine = ZeroDayEngine()
    try:
        with console.status("[bold green]Executando Zero-Day Hypothesis Engine..."):
            report = engine.analyze_project(handle.path)
    except Exception as exc:
        console.print(f"[bold red]Erro durante Zero-Day Engine:[/] {exc}")
        raise typer.Exit(code=1)

    console.print("---")
    console.print("[bold cyan]ZERO-DAY HYPOTHESIS ENGINE — COMPLETE[/]\n")

    score_color = "red" if report.risk_level in ("CRITICAL", "HIGH") else "yellow" if report.risk_level == "MEDIUM" else "green"
    console.print(f"Overall Score: [{score_color}]{report.overall_score}/100 ({report.risk_level})[/]")
    console.print(f"Total Signals: [bold]{report.total_signals}[/]")
    console.print(f"Total Hypotheses: [bold]{report.total_hypotheses}[/]")
    console.print(f"Total Opportunities: [bold]{report.total_opportunities}[/]")
    console.print(f"Total Attack Chains: [bold]{report.total_attack_chains}[/]")
    console.print(f"Research Queue Size: [bold]{len(report.research_queue)}[/]")

    if report.hypotheses:
        console.print("\n[bold]Top Hypotheses:[/]")
        for h in report.hypotheses[:5]:
            conf_color = "green" if h.get("confidence") == "VERY_HIGH" else "cyan" if h.get("confidence") == "HIGH" else "yellow"
            console.print(f"  [{conf_color}][{h.get('confidence')}][/] {h.get('title', '')}")

    if report.attack_chains:
        console.print("\n[bold]Attack Chains:[/]")
        for ac in report.attack_chains:
            console.print(f"  • {ac.get('title', '')}")

    console.print(f"\nReport saved to: [dim]{handle.path / 'profiles' / 'zero_day' / 'zero_day_report.json'}[/]")
    console.print("---")


@zeroday_app.command("anomalies", help="Exibe anomalias detectadas no projeto.")
def cmd_zeroday_anomalies(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    app_ctx: AppContext = ctx.obj
    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado.[/]")
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

    import json
    report_path = handle.path / "profiles" / "zero_day" / "anomalies.json"
    if not report_path.exists():
        console.print("[yellow]Execute 'ghostmirror zero-day run' primeiro.[/]")
        raise typer.Exit(code=1)
    with open(report_path, "r", encoding="utf-8") as f:
        anomalies = json.load(f)

    if not anomalies:
        console.print("[green]Nenhuma anomalia detectada.[/]")
        return

    table = Table(box=box.ROUNDED, header_style="bold cyan", title="Anomalies")
    table.add_column("Severity")
    table.add_column("Confidence")
    table.add_column("Title")
    table.add_column("Endpoint")
    for a in anomalies:
        sev = a.get("severity", "LOW")
        sev_color = "red" if sev == "CRITICAL" else "orange1" if sev == "HIGH" else "yellow"
        conf_color = "green" if a.get("confidence") == "HIGH" else "cyan"
        table.add_row(
            f"[{sev_color}]{sev}[/]",
            f"[{conf_color}]{a.get('confidence', 'LOW')}[/]",
            a.get("title", "")[:60],
            a.get("endpoint", "")[:40],
        )
    console.print(table)
    console.print(f"\nTotal: [bold]{len(anomalies)}[/] anomalies")


@zeroday_app.command("attack-chains", help="Exibe attack chains do projeto.")
def cmd_zeroday_attack_chains(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    app_ctx: AppContext = ctx.obj
    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado.[/]")
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

    import json
    chains_path = handle.path / "profiles" / "zero_day" / "attack_chains.json"
    if not chains_path.exists():
        console.print("[yellow]Execute 'ghostmirror zero-day run' primeiro.[/]")
        raise typer.Exit(code=1)
    with open(chains_path, "r", encoding="utf-8") as f:
        chains = json.load(f)

    if not chains:
        console.print("[green]Nenhum attack chain detectado.[/]")
        return

    for i, c in enumerate(chains, 1):
        sev = c.get("severity", "LOW")
        sev_color = "red" if sev == "CRITICAL" else "orange1" if sev == "HIGH" else "yellow"
        console.print(f"\n[bold]#{i}[/] [{sev_color}][{sev}][/] {c.get('title', '')}")
        console.print(f"  Confidence: {c.get('confidence', 'LOW')} | Score: {c.get('score', 0)}")
        console.print(f"  {c.get('description', '')}")
        if c.get("components"):
            console.print(f"  Components: {', '.join(c['components'])}")
        if c.get("recommendation"):
            console.print(f"  → {c['recommendation']}")


@zeroday_app.command("hypotheses", help="Exibe hipóteses de vulnerabilidade geradas.")
def cmd_zeroday_hypotheses(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    app_ctx: AppContext = ctx.obj
    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado.[/]")
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

    import json
    hyp_path = handle.path / "profiles" / "zero_day" / "hypotheses.json"
    if not hyp_path.exists():
        console.print("[yellow]Execute 'ghostmirror zero-day run' primeiro.[/]")
        raise typer.Exit(code=1)
    with open(hyp_path, "r", encoding="utf-8") as f:
        hypotheses = json.load(f)

    if not hypotheses:
        console.print("[green]Nenhuma hipótese gerada.[/]")
        return

    for i, h in enumerate(hypotheses, 1):
        conf = h.get("confidence", "LOW")
        conf_color = "green" if conf == "VERY_HIGH" else "cyan" if conf == "HIGH" else "yellow"
        imp = h.get("impact", "LOW")
        imp_color = "red" if imp == "CRITICAL" else "orange1" if imp == "HIGH" else "yellow"
        console.print(f"\n[bold]#{i}[/] {h.get('title', '')}")
        console.print(f"  Confidence: [{conf_color}]{conf}[/] | Impact: [{imp_color}]{imp}[/] | Score: {h.get('score', 0)}")
        console.print(f"  Type: {h.get('hypothesis_type', '')}")
        if h.get("reasoning"):
            console.print(f"  {h['reasoning'][:200]}")
        if h.get("recommendation"):
            console.print(f"  → {h['recommendation']}")


@zeroday_app.command("research", help="Exibe a fila de pesquisa priorizada.")
def cmd_zeroday_research(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    app_ctx: AppContext = ctx.obj
    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado.[/]")
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

    import json
    queue_path = handle.path / "profiles" / "zero_day" / "research_queue.json"
    if not queue_path.exists():
        console.print("[yellow]Execute 'ghostmirror zero-day run' primeiro.[/]")
        raise typer.Exit(code=1)
    with open(queue_path, "r", encoding="utf-8") as f:
        queue = json.load(f)

    if not queue:
        console.print("[green]Fila de pesquisa vazia.[/]")
        return

    table = Table(box=box.ROUNDED, header_style="bold cyan", title="Research Queue")
    table.add_column("#")
    table.add_column("Type")
    table.add_column("Priority")
    table.add_column("Confidence")
    table.add_column("Title")
    for i, item in enumerate(queue, 1):
        prio = item.get("priority", "LOW")
        prio_color = "red" if prio == "CRITICAL" else "orange1" if prio == "HIGH" else "yellow"
        conf_color = "green" if item.get("confidence") == "VERY_HIGH" else "cyan" if item.get("confidence") == "HIGH" else "yellow"
        table.add_row(
            str(i),
            item.get("type", ""),
            f"[{prio_color}]{prio}[/]",
            f"[{conf_color}]{item.get('confidence', 'LOW')}[/]",
            item.get("title", "")[:70],
        )
    console.print(table)
    console.print(f"\nTotal: [bold]{len(queue)}[/] research items")


# --------------------------------------------------------------------------- #
# Add analyze zero-day command
# --------------------------------------------------------------------------- #
@analyze_app.command("zero-day", help="Zero-Day Hypothesis Engine — gera hipóteses e anomalias.")
def cmd_analyze_zeroday(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Executa o Zero-Day Hypothesis Engine no projeto."""
    from ghostmirror.modules.zero_day.engine import ZeroDayEngine
    app_ctx: AppContext = ctx.obj

    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado.[/]")
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

    engine = ZeroDayEngine()
    try:
        with console.status("[bold green]Executando Zero-Day Hypothesis Engine..."):
            report = engine.analyze_project(handle.path)
    except Exception as exc:
        console.print(f"[bold red]Erro durante Zero-Day Engine:[/] {exc}")
        raise typer.Exit(code=1)

    console.print("---")
    console.print("ZERO-DAY HYPOTHESIS ENGINE — COMPLETE\n")
    score_color = "red" if report.risk_level in ("CRITICAL", "HIGH") else "yellow" if report.risk_level == "MEDIUM" else "green"
    console.print(f"Overall Score: [{score_color}]{report.overall_score}/100 ({report.risk_level})[/]")
    console.print(f"Signals: [bold]{report.total_signals}[/] | Hypotheses: [bold]{report.total_hypotheses}[/] | Opportunities: [bold]{report.total_opportunities}[/] | Attack Chains: [bold]{report.total_attack_chains}[/]")
    console.print(f"Research Queue: [bold]{len(report.research_queue)}[/] items")
    console.print("---")


# --------------------------------------------------------------------------- #
# Add analyze findings command
# --------------------------------------------------------------------------- #
@analyze_app.command("findings", help="Finding Intelligence Engine - enriquece todos os findings do projeto.")
def cmd_analyze_findings(
    ctx: typer.Context,
    project: str = typer.Option(None, "--project", "-p", help="Slug do projeto"),
) -> None:
    """Executa o Finding Intelligence Engine para enriquecer todos os findings existentes."""
    from ghostmirror.modules.finding_intelligence.engine import FindingIntelligenceEngine
    app_ctx: AppContext = ctx.obj

    if not project:
        handles = app_ctx.projects.list_projects()
        if not handles:
            console.print("[bold red]Nenhum projeto encontrado.[/]")
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

    engine = FindingIntelligenceEngine()
    try:
        with console.status("[bold green]Executando Finding Intelligence Engine..."):
            report = engine.analyze_project(handle.path)
    except Exception as exc:
        console.print(f"[bold red]Erro durante Finding Intelligence:[/] {exc}")
        raise typer.Exit(code=1)

    console.print("---")
    console.print("FINDING INTELLIGENCE COMPLETE\n")
    console.print(f"Total Findings: [bold]{report.total_findings}[/]")
    console.print(f"Enriched: [bold]{report.total_enriched}[/]")
    console.print(f"\nPriority Distribution:")
    for p in ["P1", "P2", "P3", "P4", "P5"]:
        count = report.priority_counts.get(p, 0)
        color = "red" if p == "P1" else "orange1" if p == "P2" else "yellow" if p == "P3" else "green" if p == "P4" else "dim"
        console.print(f"  {p}: [{color}]{count}[/]")
    console.print(f"\nKEV Count: [bold]{report.kev_count}[/]")
    console.print(f"Exploit Count: [bold]{report.exploit_count}[/]")
    console.print(f"\nQuick Wins: [bold]{len(report.quick_wins)}[/]")
    console.print("---")


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








