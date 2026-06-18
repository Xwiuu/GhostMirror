"""Status engine that aggregates project metadata, findings and execution timeline."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghostmirror.core.config_manager import ConfigManager
from ghostmirror.core.project_manager import ProjectManager
from ghostmirror.core.scope_manager import ScopeManager


class StatusEngine:
    """Builds a status snapshot for a given GhostMirror project."""

    def __init__(
        self,
        config: ConfigManager | None = None,
        project_manager: ProjectManager | None = None,
    ) -> None:
        self.config = config or ConfigManager()
        self.scope_manager = ScopeManager()
        self.project_manager = project_manager or ProjectManager(
            config=self.config, scope_manager=self.scope_manager
        )

    def get_status(self, project_slug: str | None = None) -> dict[str, Any]:
        """Return a status dictionary for a project.

        If no slug is provided and there is exactly one project, it is used
        automatically.
        """
        projects = self.project_manager.list_projects()

        if not projects:
            return {"error": "Nenhum projeto encontrado."}

        if project_slug is None:
            if len(projects) == 1:
                handle = projects[0]
            else:
                return {
                    "error": "Múltiplos projetos encontrados. Especifique um slug.",
                    "projects": [h.slug for h in projects],
                }
        else:
            matches = [h for h in projects if h.slug == project_slug]
            if not matches:
                return {"error": f"Projeto '{project_slug}' não encontrado."}
            handle = matches[0]

        meta = handle.metadata
        status: dict[str, Any] = {
            "slug": handle.slug,
            "client": meta.client,
            "project": meta.name,
            "target": meta.domain or "—",
            "status": meta.status.value,
            "created_at": meta.created_at.isoformat() if meta.created_at else None,
            "project_path": str(handle.path),
        }

        timeline_file = handle.path / "execution" / "full_scan_timeline.json"
        if timeline_file.exists():
            try:
                timeline_data = json.loads(timeline_file.read_text(encoding="utf-8"))
                status["last_scan"] = timeline_data.get("finished_at") or timeline_data.get("started_at")
                status["scan_profile"] = timeline_data.get("profile")
                status["scan_target"] = timeline_data.get("target")
                steps = timeline_data.get("steps", [])
                total_findings = sum(s.get("findings_count", 0) or s.get("findings", 0) for s in steps)
                status["last_scan_findings"] = total_findings
            except Exception:
                status["last_scan"] = None
        else:
            status["last_scan"] = None

        findings_dir = handle.path / "findings"
        severity_counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        if findings_dir.is_dir():
            for fpath in findings_dir.iterdir():
                if fpath.suffix != ".json":
                    continue
                try:
                    data = json.loads(fpath.read_text(encoding="utf-8"))
                    stats = data.get("statistics", data.get("stats", {}))
                    if isinstance(stats, dict):
                        for sev in severity_counts:
                            severity_counts[sev] += stats.get(sev, 0)
                except Exception:
                    pass

        status["findings"] = severity_counts
        status["total_findings"] = sum(severity_counts.values())
        return status
