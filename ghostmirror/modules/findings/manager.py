"""Findings manager to persist, load, and list scan results for projects."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.modules.models.finding import ScanResultModel
from ghostmirror.storage.filesystem import FileSystemStorage

logger = get_logger()


class FindingsManager:
    """Manages the persistence of security findings for a specific project.

    Ensures loose coupling: scanners generate results, and this manager is
    responsible for writing/reading them from the project's 'findings' folder.
    """

    FINDINGS_SUBDIR = "findings"

    def __init__(self, project_path: Path) -> None:
        self.project_path = Path(project_path)
        self.findings_dir = self.project_path / self.FINDINGS_SUBDIR

    def save_findings(self, scanner_name: str, scan_result: ScanResultModel) -> Path:
        """Save standard scan results to projects/<slug>/findings/<scanner_name>.json."""
        FileSystemStorage.ensure_dir(self.findings_dir)
        file_path = self.findings_dir / f"{scanner_name.lower()}.json"
        
        # Serialize scan result to JSON
        data = scan_result.model_dump(mode="json")
        FileSystemStorage.write_json(file_path, data)
        
        logger.info(
            "FINDINGS_SAVED scanner={} path={} findings={}",
            scanner_name,
            file_path,
            len(scan_result.findings),
        )
        return file_path

    def load_findings(self, scanner_name: str) -> ScanResultModel:
        """Load and validate scan results from disk."""
        file_path = self.findings_dir / f"{scanner_name.lower()}.json"
        if not file_path.exists():
            raise FileNotFoundError(f"Findings file for {scanner_name!r} not found at {file_path}")
        
        raw_data = FileSystemStorage.read_json(file_path)
        return ScanResultModel.model_validate(raw_data)

    def list_findings(self) -> dict[str, ScanResultModel]:
        """List and return all valid scan results found under the project findings folder."""
        results: dict[str, ScanResultModel] = {}
        if not self.findings_dir.is_dir():
            return results

        # Iterate over all JSON files in the findings directory
        for item in self.findings_dir.glob("*.json"):
            scanner_name = item.stem
            try:
                results[scanner_name] = self.load_findings(scanner_name)
            except Exception as exc:  # noqa: BLE001 - record invalid files but don't halt
                logger.warning(
                    "FINDINGS_CORRUPT path={} error={}",
                    item,
                    exc,
                )
        return results

    def export_all_findings(self, export_path: Path) -> Path:
        """Export all findings from all scanners in the project into a single unified JSON file."""
        findings_dict = self.list_findings()
        export_data = {
            "project_path": str(self.project_path),
            "scans": {name: result.model_dump(mode="json") for name, result in findings_dict.items()}
        }
        FileSystemStorage.write_json(export_path, export_data)
        logger.info("FINDINGS_EXPORTED to={}", export_path)
        return export_path
