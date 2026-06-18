"""Project lifecycle management.

Responsible for creating, listing, opening and validating engagement projects on
disk. Each project owns an isolated directory tree:

    projects/<client>-<project>/
        scope.yaml
        metadata.json
        logs/
        findings/
        evidence/
        reports/
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ghostmirror.core.config_manager import ConfigManager
from ghostmirror.core.logger import get_logger
from ghostmirror.core.scope_manager import ScopeManager
from ghostmirror.models.project import ProjectModel
from ghostmirror.models.scope import ScopeModel
from ghostmirror.storage.filesystem import FileSystemStorage

logger = get_logger()

#: Sub-directories created inside every project.
PROJECT_SUBDIRS: tuple[str, ...] = (
    "logs",
    "findings",
    "evidence",
    "reports",
    "profiles",
    "execution",
)
METADATA_FILENAME = "metadata.json"
SCOPE_FILENAME = "scope.yaml"


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #
from ghostmirror.core.exceptions import (
    ProjectAlreadyExistsError,
    ProjectError,
    ProjectNotFoundError,
)


# --------------------------------------------------------------------------- #
# Value object
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ProjectHandle:
    """Lightweight reference to a project on disk plus its metadata."""

    slug: str
    path: Path
    metadata: ProjectModel


# --------------------------------------------------------------------------- #
# Manager
# --------------------------------------------------------------------------- #
class ProjectManager:
    """Use-case orchestrator for the project domain."""

    def __init__(
        self,
        config: ConfigManager,
        scope_manager: ScopeManager | None = None,
    ) -> None:
        self.config = config
        self.scope_manager = scope_manager or ScopeManager()

    @property
    def projects_dir(self) -> Path:
        return self.config.projects_dir

    # ------------------------------------------------------------------ #
    # Slug helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def slugify(value: str) -> str:
        """Turn an arbitrary string into a filesystem-safe slug."""

        normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().lower())
        return re.sub(r"-+", "-", normalized).strip("-") or "untitled"

    def build_slug(self, client: str, name: str) -> str:
        return f"{self.slugify(client)}-{self.slugify(name)}"

    # ------------------------------------------------------------------ #
    # Create
    # ------------------------------------------------------------------ #
    def create_project(
        self,
        *,
        client: str,
        name: str,
        domain: str | None = None,
        notes: str | None = None,
    ) -> ProjectHandle:
        """Create the full directory tree, metadata and default scope."""

        slug = self.build_slug(client, name)
        project_path = self.projects_dir / slug

        if project_path.exists():
            logger.warning("PROJECT_EXISTS slug={}", slug)
            raise ProjectAlreadyExistsError(
                f"A project with slug {slug!r} already exists at {project_path}"
            )

        # 1. Directory tree.
        FileSystemStorage.ensure_dir(project_path)
        for subdir in PROJECT_SUBDIRS:
            FileSystemStorage.ensure_dir(project_path / subdir)

        # 2. Metadata.
        metadata = ProjectModel(
            name=name,
            client=client,
            domain=domain,
            notes=notes,
        )
        FileSystemStorage.write_json(
            project_path / METADATA_FILENAME,
            metadata.model_dump(mode="json"),
        )

        # 3. Default scope.
        scope = self.scope_manager.build_default_scope(
            client=client, name=name, domain=domain
        )
        self.scope_manager.write_scope(project_path / SCOPE_FILENAME, scope)

        logger.info(
            "PROJECT_CREATED slug={} uuid={} client={!r} project={!r}",
            slug,
            metadata.uuid,
            client,
            name,
        )
        return ProjectHandle(slug=slug, path=project_path, metadata=metadata)

    # ------------------------------------------------------------------ #
    # Read
    # ------------------------------------------------------------------ #
    def list_projects(self) -> list[ProjectHandle]:
        """Return every valid project found under the projects directory."""

        handles: list[ProjectHandle] = []
        for directory in FileSystemStorage.list_dirs(self.projects_dir):
            metadata_path = directory / METADATA_FILENAME
            if not metadata_path.exists():
                continue
            try:
                metadata = ProjectModel.model_validate(
                    FileSystemStorage.read_json(metadata_path)
                )
            except Exception as exc:  # noqa: BLE001 - skip but record corrupt entries
                logger.warning(
                    "PROJECT_METADATA_INVALID path={} error={}", metadata_path, exc
                )
                continue
            handles.append(
                ProjectHandle(slug=directory.name, path=directory, metadata=metadata)
            )
        return handles

    def open_project(self, slug: str) -> ProjectHandle:
        """Load a project by slug, validating its structure."""

        project_path = self.projects_dir / slug
        if not project_path.exists():
            raise ProjectNotFoundError(f"Project {slug!r} not found at {project_path}")

        metadata_path = project_path / METADATA_FILENAME
        if not metadata_path.exists():
            raise ProjectError(f"Project {slug!r} is missing {METADATA_FILENAME}")

        metadata = ProjectModel.model_validate(
            FileSystemStorage.read_json(metadata_path)
        )

        missing = self.validate_structure(project_path)
        if missing:
            logger.warning("PROJECT_STRUCTURE_INCOMPLETE slug={} missing={}", slug, missing)

        logger.info("PROJECT_OPENED slug={}", slug)
        return ProjectHandle(slug=slug, path=project_path, metadata=metadata)

    def read_scope(self, handle: ProjectHandle) -> ScopeModel:
        """Load and validate the scope for an opened project."""

        return self.scope_manager.load_scope(handle.path / SCOPE_FILENAME)

    # ------------------------------------------------------------------ #
    # Validation
    # ------------------------------------------------------------------ #
    def validate_structure(self, project_path: Path) -> list[str]:
        """Return the list of required entries missing from a project tree."""

        missing: list[str] = []
        for subdir in PROJECT_SUBDIRS:
            if not (project_path / subdir).is_dir():
                missing.append(f"{subdir}/")
        for filename in (METADATA_FILENAME, SCOPE_FILENAME):
            if not (project_path / filename).exists():
                missing.append(filename)
        return missing
