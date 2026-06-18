"""Framework-agnostic filesystem persistence helpers.

This is the only layer that talks to the disk directly. Keeping IO isolated here
lets the core managers stay testable and lets us swap the backend later (e.g. an
object store) without touching business logic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


class FileSystemStorage:
    """Stateless collection of low-level filesystem operations."""

    # ------------------------------------------------------------------ #
    # Directories
    # ------------------------------------------------------------------ #
    @staticmethod
    def ensure_dir(path: Path) -> Path:
        """Create ``path`` (and parents) if missing; return it."""

        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def exists(path: Path) -> bool:
        return path.exists()

    @staticmethod
    def list_dirs(path: Path) -> list[Path]:
        """Return sorted immediate sub-directories of ``path`` (empty if absent)."""

        if not path.exists():
            return []
        return sorted(child for child in path.iterdir() if child.is_dir())

    # ------------------------------------------------------------------ #
    # Text
    # ------------------------------------------------------------------ #
    @staticmethod
    def write_text(path: Path, content: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    @staticmethod
    def read_text(path: Path) -> str:
        return path.read_text(encoding="utf-8")

    # ------------------------------------------------------------------ #
    # JSON
    # ------------------------------------------------------------------ #
    @classmethod
    def write_json(cls, path: Path, data: dict[str, Any]) -> Path:
        payload = json.dumps(data, indent=2, ensure_ascii=False, default=str)
        return cls.write_text(path, payload + "\n")

    @classmethod
    def read_json(cls, path: Path) -> dict[str, Any]:
        return json.loads(cls.read_text(path))

    # ------------------------------------------------------------------ #
    # YAML
    # ------------------------------------------------------------------ #
    @classmethod
    def write_yaml(cls, path: Path, data: dict[str, Any]) -> Path:
        payload = yaml.safe_dump(
            data,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        )
        return cls.write_text(path, payload)

    @classmethod
    def read_yaml(cls, path: Path) -> dict[str, Any]:
        return yaml.safe_load(cls.read_text(path)) or {}
