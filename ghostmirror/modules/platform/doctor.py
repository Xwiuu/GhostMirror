"""Doctor Engine to execute and format environment diagnostic reports."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ghostmirror.core.config_manager import ConfigManager
from ghostmirror.modules.platform.diagnostics import PlatformDiagnostics
from ghostmirror.modules.platform.doctor_fix import run_doctor_fix

console = Console()

INSTALL_SUGGESTIONS: dict[str, str] = {
    "nmap": "sudo apt install nmap",
    "whatweb": "sudo apt install whatweb",
    "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "weasyprint": "pip install weasyprint",
    "docker": "https://docs.docker.com/get-docker/",
}


class DoctorEngine:
    """Runs diagnostics and prints system check results to the console."""

    def __init__(self, config: ConfigManager) -> None:
        self.diagnostics = PlatformDiagnostics(config)

    def run_doctor(self) -> bool:
        """Run system diagnostics and display check boxes on stdout.

        Returns True if the system is fully READY.
        """
        results = self.diagnostics.run_diagnostics()

        console.print("[bold cyan]👻 GhostMirror Doctor[/]\n")

        all_ok = True

        # Python Version Check
        py_ver = results["environment"]["python_version"]
        console.print(f"[green]✓[/] Python [dim](v{py_ver})[/]")

        # Virtual Environment
        if results["environment"]["in_virtual_env"]:
            console.print("[green]✓[/] Virtual Environment")
        else:
            console.print("[yellow]![/] Virtual Environment [dim](Recomendado)[/]")

        # Project Directory
        if results["filesystem"]["projects"]:
            console.print("[green]✓[/] Project Directory")
        else:
            console.print("[red]✗[/] Project Directory")
            all_ok = False

        missing_tools: list[str] = []

        # Tools Binaries check + install suggestions
        binaries_to_check = ["nmap", "whatweb", "nuclei", "weasyprint", "docker"]
        for binary in binaries_to_check:
            if results["binaries"][binary]:
                console.print(f"[green]✓[/] {binary.capitalize()}")
            else:
                if binary == "docker":
                    console.print("[yellow]![/] Docker [dim](Opcional)[/]")
                else:
                    console.print(f"[red]✗[/] {binary.capitalize()}")
                    missing_tools.append(binary)
                    all_ok = False

        if missing_tools:
            console.print()
            table = Table(box=None, show_header=False)
            table.add_column("Ferramenta", style="cyan", width=14)
            table.add_column("Instalação", style="yellow")
            for tool in missing_tools:
                cmd = INSTALL_SUGGESTIONS.get(tool, "—")
                table.add_row(f"  {tool}", cmd)
            console.print(table)

        # Scope Engine (Verify that libraries work)
        libraries_ok = all(results["libraries"].values())
        if libraries_ok:
            console.print("[green]✓[/] Scope Engine")
        else:
            console.print("[red]✗[/] Scope Engine [dim](Bibliotecas ausentes)[/]")
            all_ok = False

        # Payload Registry
        try:
            from ghostmirror.modules.payloads.engine import PayloadEngine
            health = PayloadEngine.check_health(Path("."))
            if health["registry_valid"]:
                console.print(f"[green]✓[/] Payload Registry [dim]({health['total_payloads_registered']} payloads)[/]")
            else:
                console.print(f"[red]✗[/] Payload Registry [dim]({health['registry_message']})[/]")
                all_ok = False
            if health["safety_policy_valid"]:
                console.print("[green]✓[/] Payload Safety Policy")
            else:
                console.print(f"[red]✗[/] Payload Safety Policy [dim]({health['safety_policy_message']})[/]")
                all_ok = False
        except Exception:
            console.print("[red]✗[/] Payload Engine")
            all_ok = False

        # Lab Mode checks
        lab_results = results.get("lab", {})
        if lab_results.get("catalog_valid"):
            console.print("[green]✓[/] Lab Catalog")
        else:
            console.print("[yellow]![/] Lab Catalog [dim](Opcional)[/]")
        if lab_results.get("compose_files_present"):
            console.print("[green]✓[/] Lab Compose Files")
        else:
            console.print("[yellow]![/] Lab Compose Files [dim](Opcional)[/]")

        console.print("\n" + "─" * 40)
        console.print()
        if all_ok:
            console.print(Panel(Text(" READY ", style="bold green", justify="center"), border_style="green"))
        else:
            console.print(Panel(Text(" WARNING / UNREADY ", style="bold red", justify="center"), border_style="red"))
            console.print("\n[dim]Dica:[/] Execute [bold]ghostmirror doctor --fix[/] para reparo assistido.")

        return all_ok
