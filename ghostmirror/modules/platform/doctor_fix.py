"""Doctor Fix — assisted mode to repair common platform issues."""

from __future__ import annotations

import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from ghostmirror.core.config_manager import ConfigManager
from ghostmirror.modules.platform.dependency_checker import DependencyChecker
from ghostmirror.modules.platform.diagnostics import PlatformDiagnostics

console = Console()

INSTALL_COMMANDS: dict[str, str] = {
    "nmap": "sudo apt install nmap",
    "whatweb": "sudo apt install whatweb",
    "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "weasyprint": "pip install weasyprint",
    "docker": "curl -fsSL https://get.docker.com | sh",
}


def run_doctor_fix(config: ConfigManager) -> bool:
    """Run diagnostics and offer to fix detected issues interactively.

    Returns True if all issues were resolved (or user skipped all).
    """
    diagnostics = PlatformDiagnostics(config)
    results = diagnostics.run_diagnostics()

    console.print("[bold cyan]👻 GhostMirror Doctor — Modo Reparo[/]\n")

    issues: list[dict[str, str]] = []

    env = results.get("environment", {})
    fs = results.get("filesystem", {})

    if not env.get("in_virtual_env"):
        issues.append({
            "type": "warning",
            "item": "Virtual Environment",
            "detail": "Não ativo (recomendado)",
            "fix": "",
        })

    if not fs.get("projects"):
        issues.append({
            "type": "error",
            "item": "Diretório de projetos",
            "detail": "Não encontrado ou sem permissão",
            "fix": "mkdir -p projects",
        })

    if not fs.get("logs"):
        issues.append({
            "type": "error",
            "item": "Diretório de logs",
            "detail": "Não encontrado ou sem permissão",
            "fix": "mkdir -p logs",
        })

    if not fs.get("reports"):
        issues.append({
            "type": "error",
            "item": "Diretório de relatórios",
            "detail": "Não encontrado ou sem permissão",
            "fix": "mkdir -p reports",
        })

    binaries = results.get("binaries", {})
    for binary, available in binaries.items():
        if not available:
            cmd = INSTALL_COMMANDS.get(binary, "")
            issues.append({
                "type": "error",
                "item": binary.capitalize(),
                "detail": "Não encontrado",
                "fix": cmd,
            })

    if not results.get("docker_daemon_running"):
        if binaries.get("docker"):
            issues.append({
                "type": "error",
                "item": "Docker Daemon",
                "detail": "Instalado mas não está rodando",
                "fix": "sudo systemctl start docker",
            })

    libraries = results.get("libraries", {})
    for lib, available in libraries.items():
        if not available:
            issues.append({
                "type": "error",
                "item": f"Python: {lib}",
                "detail": "Biblioteca não encontrada",
                "fix": f"pip install {lib}",
            })

    if not issues:
        console.print(Panel(
            Text("Nenhum problema encontrado. Sistema está pronto.", style="bold green"),
            border_style="green",
            title="✅",
        ))
        return True

    table = Table(box=None, show_header=False)
    table.add_column("Item", style="cyan", width=20)
    table.add_column("Problema", style="yellow", width=40)
    for issue in issues:
        icon = "[yellow]![/]" if issue["type"] == "warning" else "[red]✗[/]"
        table.add_row(f"{icon} {issue['item']}", issue["detail"])

    console.print(table)
    console.print()

    for issue in issues:
        if not issue["fix"]:
            continue
        if issue["type"] != "error":
            continue

        console.print(
            Panel(
                Text.from_markup(
                    f"[yellow]Problema:[/] {issue['item']} — {issue['detail']}\n\n"
                    f"[green]Comando sugerido:[/]\n"
                    f"  [bold]{issue['fix']}[/]"
                ),
                border_style="yellow",
                title="Sugestão de Correção",
            )
        )

        fix_now = Confirm.ask(f"   Tentar corrigir {issue['item']}?", default=False)
        if fix_now:
            _apply_fix(issue["item"], issue["fix"])

    console.print()
    console.print("[bold]Diagnóstico concluído. Execute 'ghostmirror doctor' para verificar.[/]")
    return True


def _apply_fix(item: str, command: str) -> None:
    """Attempt to apply a fix command, with error handling."""
    import subprocess

    if not command:
        console.print(f"[yellow]Nenhum comando disponível para {item}. Instale manualmente.[/]")
        return

    try:
        console.print(f"[dim]Executando: {command}[/]")
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            console.print(f"[green]✓ {item} corrigido![/]")
        else:
            console.print(f"[red]✗ Falha ao corrigir {item}:[/]")
            console.print(f"  {result.stderr.strip()[:200]}")
    except subprocess.TimeoutExpired:
        console.print(f"[red]✗ Timeout ao corrigir {item}[/]")
    except Exception as exc:
        console.print(f"[red]✗ Erro: {exc}[/]")
