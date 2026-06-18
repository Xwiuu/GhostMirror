"""Real-time progress dashboard for scan execution using Rich."""

from __future__ import annotations

import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Generator, Iterator

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from ghostmirror.app.banner import render_compact_banner
from ghostmirror.modules.orchestrator.execution_context import ExecutionStatus

console = Console()

MODULE_LABELS: dict[str, str] = {
    "headers": "Headers",
    "ssl": "SSL/TLS",
    "nmap": "Nmap",
    "fingerprint": "Fingerprint",
    "technology_intelligence": "Tech Intel",
    "cve_intelligence": "CVE Intel",
    "nuclei": "Nuclei",
    "owasp": "OWASP",
    "payloads": "Payloads",
    "report": "Report",
}


class ProgressDashboard:
    """Live-updating dashboard that displays scan progress with Rich."""

    def __init__(self, modules: list[str], target: str, profile: str) -> None:
        self.modules = modules
        self.target = target
        self.profile = profile
        self._module_status: dict[str, str] = {}
        self._module_progress: dict[str, float] = {}
        self._start_time: datetime = datetime.now()
        self._current_module: str | None = None

    def set_module_status(self, module: str, status: str, progress: float = 100.0) -> None:
        """Update the status of a specific module."""
        self._module_status[module] = status
        self._module_progress[module] = progress

    def set_current_module(self, module: str) -> None:
        """Mark which module is currently executing."""
        self._current_module = module

    def _render(self) -> Layout:
        """Render the live dashboard layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=2),
        )

        header_text = Text()
        header_text.append("👻 ", style="bold cyan")
        header_text.append(f"GhostMirror Scan  •  {self.target}", style="bold white")
        header_text.append(f"  [{self.profile.upper()}]", style="dim")
        layout["header"].update(header_text)

        progress_table = Table.grid(padding=(0, 2))
        progress_table.add_column("Module", style="cyan", width=16)
        progress_table.add_column("Progress", width=50)
        progress_table.add_column("Status", width=12)

        for module in self.modules:
            label = MODULE_LABELS.get(module, module)
            status = self._module_status.get(module, "pending")
            pct = self._module_progress.get(module, 0.0)

            if module == self._current_module:
                label = f">> {label}"

            if status == "completed":
                status_text = "[bold green]✓ Done[/]"
            elif status == "failed":
                status_text = "[bold red]✗ Failed[/]"
            elif status == "skipped":
                status_text = "[yellow]⤵ Skipped[/]"
            elif module == self._current_module:
                status_text = "[cyan]⟳ Running[/]"
            else:
                status_text = "[dim]⏳ Pending[/]"

            bar_width = int(pct / 2)
            bar = "█" * bar_width + "░" * (50 - bar_width)
            bar_colored = f"[green]{bar}[/]"

            progress_table.add_row(label, bar_colored, status_text)

        layout["body"].update(progress_table)

        elapsed = datetime.now() - self._start_time
        elapsed_str = str(elapsed).split(".")[0]
        footer_text = Text(f"\nTempo: {elapsed_str}", style="bold yellow")
        layout["footer"].update(footer_text)

        return layout

    @contextmanager
    def live_display(self) -> Generator[ProgressDashboard, None, None]:
        """Context manager that shows the live dashboard during scan execution."""
        with Live(self._render(), console=console, refresh_per_second=4, transient=True) as live:
            try:
                yield self
            finally:
                live.update(self._render())

    def update_display(self) -> None:
        """Force a refresh of the display (used with live_display)."""
        pass


@contextmanager
def scan_progress(
    modules: list[str], target: str, profile: str
) -> Iterator[ProgressDashboard]:
    """Convenience context manager for the progress dashboard."""
    dashboard = ProgressDashboard(modules, target, profile)
    with dashboard.live_display():
        yield dashboard
