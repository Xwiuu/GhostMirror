"""Health Check Engine to run quick validation checks and output summary tables."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ghostmirror.core.config_manager import ConfigManager
from ghostmirror.modules.platform.diagnostics import PlatformDiagnostics

console = Console()


class HealthCheckEngine:
    """Performs quick health verification on tools, folders and files, displaying a table result."""

    def __init__(self, config: ConfigManager) -> None:
        self.config = config
        self.diagnostics = PlatformDiagnostics(config)

    def run_health_check(self) -> bool:
        """Run health check and output the status table.

        Returns True if health status is HEALTHY.
        """
        results = self.diagnostics.run_diagnostics()

        console.print("[bold cyan]Health Status[/]\n")

        # Table or dots format matching the prompt:
        # Nmap .......... OK
        # Nuclei ........ OK
        # WhatWeb ....... OK
        # Projects ....... OK
        # Templates ...... OK
        # Result: HEALTHY

        # We will use dot columns formatted as standard console lines
        checks = [
            ("Nmap", results["binaries"]["nmap"]),
            ("Nuclei", results["binaries"]["nuclei"]),
            ("WhatWeb", results["binaries"]["whatweb"]),
            ("Projects", results["filesystem"]["projects"]),
        ]

        # Template check: check if nuclei template mapping exists
        template_map_file = Path(__file__).parent.parent.parent / "knowledge" / "cves" / "nuclei_template_map.json"
        templates_ok = template_map_file.exists()
        checks.append(("Templates", templates_ok))

        healthy = True
        for name, ok in checks:
            status = "[green]OK[/]" if ok else "[red]FAIL[/]"
            if not ok:
                healthy = False
            dots = "." * (14 - len(name))
            console.print(f"{name} {dots} {status}")

        console.print("\nResult:")
        if healthy:
            console.print(Panel(Text("HEALTHY", style="bold green", justify="center"), border_style="green"))
        else:
            console.print(Panel(Text("UNHEALTHY", style="bold red", justify="center"), border_style="red"))

        return healthy
