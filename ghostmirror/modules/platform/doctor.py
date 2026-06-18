"""Doctor Engine to execute and format environment diagnostic reports."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from ghostmirror.core.config_manager import ConfigManager
from ghostmirror.modules.platform.diagnostics import PlatformDiagnostics

console = Console()


class DoctorEngine:
    """Runs diagnostics and prints system check results to the console."""

    def __init__(self, config: ConfigManager) -> None:
        self.diagnostics = PlatformDiagnostics(config)

    def run_doctor(self) -> bool:
        """Run system diagnostics and display check boxes on stdout.

        Returns True if the system is fully READY.
        """
        results = self.diagnostics.run_diagnostics()

        console.print("[bold cyan]GhostMirror Doctor[/]\n")

        all_ok = True

        # Python Version Check
        py_ver = results["environment"]["python_version"]
        console.print(f"[green][✓][/] Python (v{py_ver})")

        # Virtual Environment
        if results["environment"]["in_virtual_env"]:
            console.print("[green][✓][/] Virtual Environment")
        else:
            console.print("[yellow][!][/] Virtual Environment (Não ativo — Recomendado)")

        # Project Directory
        if results["filesystem"]["projects"]:
            console.print("[green][✓][/] Project Directory")
        else:
            console.print("[red][✗][/] Project Directory (Erro ao criar/ler)")
            all_ok = False

        # Tools Binaries check
        binaries = ["nmap", "whatweb", "nuclei", "weasyprint", "docker"]
        for binary in binaries:
            if results["binaries"][binary]:
                console.print(f"[green][✓][/] {binary.capitalize()}")
            else:
                # Docker is optional, others are critical or warning
                if binary == "docker":
                    console.print("[yellow][!][/] Docker (Não instalado/parado — Opcional)")
                else:
                    console.print(f"[red][✗][/] {binary.capitalize()} (Não encontrado)")
                    all_ok = False

        # Scope Engine (Verify that libraries work)
        libraries_ok = all(results["libraries"].values())
        if libraries_ok:
            console.print("[green][✓][/] Scope Engine")
        else:
            console.print("[red][✗][/] Scope Engine (Bibliotecas Python ausentes)")
            all_ok = False

        # Payload Registry
        try:
            from ghostmirror.modules.payloads.engine import PayloadEngine
            health = PayloadEngine.check_health(Path("."))
            if health["registry_valid"]:
                console.print(f"[green][✓][/] Payload Registry ({health['total_payloads_registered']} payloads)")
            else:
                console.print(f"[red][✗][/] Payload Registry ({health['registry_message']})")
                all_ok = False
            if health["safety_policy_valid"]:
                console.print("[green][✓][/] Payload Safety Policy")
            else:
                console.print(f"[red][✗][/] Payload Safety Policy ({health['safety_policy_message']})")
                all_ok = False
        except Exception:
            console.print("[red][✗][/] Payload Engine (Módulo não disponível)")
            all_ok = False

        # Lab Mode checks
        lab_results = results.get("lab", {})
        if lab_results.get("catalog_valid"):
            console.print("[green][✓][/] Lab Catalog")
        else:
            console.print("[yellow][!][/] Lab Catalog (Alguns compose files ausentes — opcional)")
        if lab_results.get("compose_files_present"):
            console.print("[green][✓][/] Lab Compose Files")
        else:
            console.print("[yellow][!][/] Lab Compose Files (Alguns arquivos ausentes — opcional)")

        console.print("\nSystem Status:")
        if all_ok:
            console.print(Panel(Text("READY", style="bold green", justify="center"), border_style="green"))
        else:
            console.print(Panel(Text("WARNING / UNREADY", style="bold red", justify="center"), border_style="red"))

        return all_ok
