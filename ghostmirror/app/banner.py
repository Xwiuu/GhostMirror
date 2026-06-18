"""GhostMirror visual identity — banner and ASCII art for the CLI."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from ghostmirror import __version__

console = Console()


GHOST_ASCII = """
     ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
    ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
    ██║  ███╗███████║██║   ██║███████╗   ██║
    ██║   ██║██╔══██║██║   ██║╚════██║   ██║
    ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║
     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
"""


def render_banner() -> None:
    """Render the main GhostMirror banner."""
    banner_text = Text()
    banner_text.append("\n")
    banner_text.append("👻 ", style="bold cyan")
    banner_text.append("GHOSTMIRROR", style="bold bright_white")
    banner_text.append("\n")
    banner_text.append("   ", style="dim")
    banner_text.append("Offensive Security Platform", style="cyan")
    banner_text.append(f"  v{__version__}", style="dim")
    banner_text.append("\n")

    console.print(
        Panel(
            banner_text,
            border_style="cyan",
            padding=(1, 2),
            subtitle="Internal Pentest Automation",
            subtitle_align="right",
        )
    )


def render_compact_banner() -> None:
    """Render a compact one-line banner for sub-screens."""
    text = Text()
    text.append("👻 ", style="bold cyan")
    text.append("GhostMirror", style="bold bright_white")
    text.append("  Offensive Security Platform", style="cyan dim")
    console.print(text)
