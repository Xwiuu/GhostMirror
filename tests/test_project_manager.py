"""Tests for the project manager."""

from __future__ import annotations

import pytest

from ghostmirror.core.project_manager import (
    METADATA_FILENAME,
    PROJECT_SUBDIRS,
    SCOPE_FILENAME,
    ProjectAlreadyExistsError,
    ProjectManager,
    ProjectNotFoundError,
)


def test_slugify() -> None:
    assert ProjectManager.slugify("Empresa X!!") == "empresa-x"
    assert ProjectManager.slugify("  Auditoria   Externa  ") == "auditoria-externa"
    assert ProjectManager.slugify("***") == "untitled"


def test_create_project_builds_full_structure(project_manager: ProjectManager) -> None:
    handle = project_manager.create_project(
        client="Empresa X",
        name="Auditoria Externa",
        domain="empresa.com.br",
        notes="Janela de testes noturna.",
    )

    assert handle.slug == "empresa-x-auditoria-externa"
    assert handle.path.is_dir()

    for subdir in PROJECT_SUBDIRS:
        assert (handle.path / subdir).is_dir()
    assert (handle.path / METADATA_FILENAME).exists()
    assert (handle.path / SCOPE_FILENAME).exists()

    # Structure validation reports nothing missing.
    assert project_manager.validate_structure(handle.path) == []

    # Metadata round-trips.
    assert handle.metadata.client == "Empresa X"
    assert handle.metadata.domain == "empresa.com.br"


def test_create_duplicate_raises(project_manager: ProjectManager) -> None:
    project_manager.create_project(client="Empresa X", name="Auditoria")
    with pytest.raises(ProjectAlreadyExistsError):
        project_manager.create_project(client="Empresa X", name="Auditoria")


def test_list_and_open_project(project_manager: ProjectManager) -> None:
    project_manager.create_project(
        client="Empresa X", name="Auditoria", domain="empresa.com.br"
    )
    project_manager.create_project(
        client="Empresa Y", name="Interna", domain="empresay.com"
    )

    projects = project_manager.list_projects()
    assert {p.slug for p in projects} == {
        "empresa-x-auditoria",
        "empresa-y-interna",
    }

    handle = project_manager.open_project("empresa-x-auditoria")
    assert handle.metadata.client == "Empresa X"

    scope = project_manager.read_scope(handle)
    assert scope.targets.domains == ["empresa.com.br"]


def test_open_missing_project_raises(project_manager: ProjectManager) -> None:
    with pytest.raises(ProjectNotFoundError):
        project_manager.open_project("does-not-exist")
