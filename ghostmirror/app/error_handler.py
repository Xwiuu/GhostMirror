"""User-friendly error display — never show raw tracebacks to the user."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from ghostmirror.core.exceptions import (
    InvalidConfigurationError,
    OutOfScopeError,
    ProjectError,
    ReportGenerationError,
    ScannerError,
    ToolError,
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


def present_error(exc: BaseException, context: str = "") -> None:
    """Display a user-friendly error message and log the full traceback.

    NUNCA mostra traceback para o usuário. Sempre loga o traceback completo
    em errors.log para diagnóstico.
    """
    _log_traceback(exc)

    if isinstance(exc, ToolNotFoundError):
        tool_name = _find_tool_name(exc)
        if tool_name and tool_name in INSTALL_SUGGESTIONS:
            console.print(
                Panel(
                    Text.from_markup(
                        f"[red]\u274c {tool_name.capitalize()} n\u00e3o encontrado[/]\n\n"
                        f"[yellow]Instala\u00e7\u00e3o sugerida:[/]\n"
                        f"  [bold]{INSTALL_SUGGESTIONS[tool_name]}[/]\n\n"
                        f"[dim]Detalhes completos em: logs/errors.log[/]"
                    ),
                    border_style="red",
                    title="Depend\u00eancia Ausente",
                )
            )
        else:
            console.print(
                Panel(
                    Text.from_markup(
                        f"[red]\u274c Ferramenta n\u00e3o encontrada[/]\n\n"
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
                    f"[red]\u274c Alvo fora do escopo[/]\n\n"
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
                    f"[red]\u274c Tempo limite excedido[/]\n\n"
                    f"[yellow]{exc}[/]\n\n"
                    f"[dim]Detalhes completos em: logs/errors.log[/]"
                ),
                border_style="red",
                title="Timeout",
            )
        )

    elif isinstance(exc, InvalidConfigurationError):
        console.print(
            Panel(
                Text.from_markup(
                    f"[red]\u274c Erro de configura\u00e7\u00e3o[/]\n\n"
                    f"[yellow]{exc}[/]\n\n"
                    f"[dim]Verifique seus arquivos de configura\u00e7\u00e3o.[/]"
                ),
                border_style="red",
                title="Configura\u00e7\u00e3o",
            )
        )

    elif isinstance(exc, ProjectError):
        console.print(
            Panel(
                Text.from_markup(
                    f"[red]\u274c Erro no projeto[/]\n\n"
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
                    f"[red]\u274c Erro ao gerar relat\u00f3rio[/]\n\n"
                    f"[yellow]{exc}[/]\n\n"
                    f"[dim]Detalhes completos em: logs/errors.log[/]"
                ),
                border_style="red",
                title="Relat\u00f3rio",
            )
        )

    elif isinstance(exc, ScannerError):
        console.print(
            Panel(
                Text.from_markup(
                    f"[red]\u274c Erro no scanner[/]\n\n"
                    f"[yellow]{exc}[/]\n\n"
                    f"[dim]Detalhes completos em: logs/errors.log[/]"
                ),
                border_style="red",
                title="Scanner",
            )
        )

    elif isinstance(exc, ToolError):
        console.print(
            Panel(
                Text.from_markup(
                    f"[red]\u274c Erro na ferramenta externa[/]\n\n"
                    f"[yellow]{exc}[/]\n\n"
                    f"[dim]Detalhes completos em: logs/errors.log[/]"
                ),
                border_style="red",
                title="Ferramenta",
            )
        )

    elif isinstance(exc, FileNotFoundError):
        console.print(
            Panel(
                Text.from_markup(
                    f"[red]\u274c Arquivo n\u00e3o encontrado[/]\n\n"
                    f"[yellow]{exc}[/]\n\n"
                    f"[dim]Verifique se o arquivo necess\u00e1rio existe.[/]"
                ),
                border_style="red",
                title="Arquivo",
            )
        )

    elif isinstance(exc, KeyboardInterrupt):
        console.print("\n[yellow]\u26a0 Opera\u00e7\u00e3o cancelada pelo usu\u00e1rio.[/]")

    elif isinstance(exc, ValueError):
        msg = str(exc) if str(exc) else "Valor inv\u00e1lido"
        console.print(
            Panel(
                Text.from_markup(
                    f"[red]\u274c Valor inv\u00e1lido[/]\n\n"
                    f"[yellow]{msg}[/]\n\n"
                    f"[dim]Verifique os par\u00e2metros fornecidos.[/]"
                ),
                border_style="red",
                title="Par\u00e2metro",
            )
        )

    else:
        msg = str(exc) if str(exc) else type(exc).__name__
        ctx = f" ({context})" if context else ""
        console.print(
            Panel(
                Text.from_markup(
                    f"[red]\u274c Erro inesperado{ctx}[/]\n\n"
                    f"[yellow]{msg}[/]\n\n"
                    f"[dim]Detalhes completos em: logs/errors.log[/]"
                ),
                border_style="red",
                title="Erro",
            )
        )


def handle_error(exc: BaseException, context: str = "") -> None:
    """Legacy wrapper — delegates to present_error."""
    present_error(exc, context)
