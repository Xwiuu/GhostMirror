"""User-friendly error display — never show raw tracebacks to the user."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from ghostmirror.core.exceptions import (
    OutOfScopeError,
    ProjectError,
    ReportGenerationError,
    ToolNotFoundError,
    ToolTimeoutError,
)
from ghostmirror.core.logger import get_logger

console = Console()
logger = get_logger()

INSTALL_SUGGESTIONS: dict[str, str] = {
    "whatweb": "sudo apt install whatweb",
    "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "nmap": "sudo apt install nmap",
    "docker": "https://docs.docker.com/get-docker/",
    "weasyprint": "pip install weasyprint",
    "ghostmirror-rs": "cd ghostmirror-rs && cargo build --release",
}


def _log_traceback(exc: BaseException) -> None:
    """Log full traceback to errors.log only."""
    tb_lines = traceback.format_exception(type(exc), exc, exc.__traceback__)
    logger.error("TRACEBACK:\n{}", "".join(tb_lines))


def _find_tool_name(exc: BaseException) -> str | None:
    """Try to extract the tool name from an exception message."""
    msg = str(exc).lower()
    for tool in INSTALL_SUGGESTIONS:
        if tool in msg:
            return tool
    return None


def handle_error(exc: BaseException, context: str = "") -> None:
    """Display a user-friendly error message and log the full traceback."""
    _log_traceback(exc)

    if isinstance(exc, ToolNotFoundError):
        tool_name = _find_tool_name(exc)
        if tool_name and tool_name in INSTALL_SUGGESTIONS:
            console.print(
                Panel(
                    Text.from_markup(
                        f"[red]❌ {tool_name.capitalize()} não encontrado[/]\n\n"
                        f"[yellow]Instalação sugerida:[/]\n"
                        f"  [bold]{INSTALL_SUGGESTIONS[tool_name]}[/]\n\n"
                        f"[dim]Detalhes completos em: logs/errors.log[/]"
                    ),
                    border_style="red",
                    title="Dependência Ausente",
                )
            )
        else:
            console.print(
                Panel(
                    Text.from_markup(
                        f"[red]❌ Ferramenta não encontrada[/]\n\n"
                        f"[yellow]Mensagem:[/] {exc}\n\n"
                        f"[dim]Detalhes completos em: logs/errors.log[/]"
                    ),
                    border_style="red",
                    title="Erro",
                )
            )

    elif isinstance(exc, OutOfScopeError):
        console.print(
            Panel(
                Text.from_markup(
                    f"[red]❌ Alvo fora do escopo[/]\n\n"
                    f"[yellow]{exc}[/]\n\n"
                    f"[dim]Verifique o arquivo scope.yaml do projeto.[/]"
                ),
                border_style="red",
                title="Escopo",
            )
        )

    elif isinstance(exc, ToolTimeoutError):
        console.print(
            Panel(
                Text.from_markup(
                    f"[red]❌ Tempo limite excedido[/]\n\n"
                    f"[yellow]{exc}[/]\n\n"
                    f"[dim]Detalhes completos em: logs/errors.log[/]"
                ),
                border_style="red",
                title="Timeout",
            )
        )

    elif isinstance(exc, ProjectError):
        console.print(
            Panel(
                Text.from_markup(
                    f"[red]❌ Erro no projeto[/]\n\n"
                    f"[yellow]{exc}[/]"
                ),
                border_style="red",
                title="Projeto",
            )
        )

    elif isinstance(exc, ReportGenerationError):
        console.print(
            Panel(
                Text.from_markup(
                    f"[red]❌ Erro ao gerar relatório[/]\n\n"
                    f"[yellow]{exc}[/]\n\n"
                    f"[dim]Detalhes completos em: logs/errors.log[/]"
                ),
                border_style="red",
                title="Relatório",
            )
        )

    elif isinstance(exc, KeyboardInterrupt):
        console.print("\n[yellow]⚠ Operação cancelada pelo usuário.[/]")

    elif isinstance(exc, FileNotFoundError):
        console.print(
            Panel(
                Text.from_markup(
                    f"[red]❌ Arquivo não encontrado[/]\n\n"
                    f"[yellow]{exc}[/]"
                ),
                border_style="red",
                title="Arquivo",
            )
        )

    else:
        msg = str(exc) if str(exc) else type(exc).__name__
        ctx = f" ({context})" if context else ""
        console.print(
            Panel(
                Text.from_markup(
                    f"[red]❌ Erro inesperado{ctx}[/]\n\n"
                    f"[yellow]{msg}[/]\n\n"
                    f"[dim]Detalhes completos em: logs/errors.log[/]"
                ),
                border_style="red",
                title="Erro",
            )
        )
