"""Unit tests for the Pydantic domain models."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from ghostmirror import __version__
from ghostmirror.models.project import ProjectModel, ProjectStatus
from ghostmirror.models.scope import ScopeModel
from ghostmirror.models.settings import SettingsModel


def test_project_model_defaults() -> None:
    project = ProjectModel(name="Auditoria Externa", client="Empresa X")

    # UUID is a valid uuid4 string.
    uuid.UUID(project.uuid)
    assert project.status is ProjectStatus.ACTIVE
    assert project.ghostmirror_version == __version__
    assert project.created_at.tzinfo is not None  # timezone-aware


def test_project_model_requires_name_and_client() -> None:
    with pytest.raises(ValidationError):
        ProjectModel(name="", client="Empresa X")


def test_scope_model_valid() -> None:
    scope = ScopeModel.model_validate(
        {
            "project": {"client": "Empresa X", "name": "Auditoria"},
            "targets": {"domains": ["Empresa.com.BR"], "ips": ["10.0.0.0/24"]},
            "allowed_tests": {"exploitation": False},
        }
    )
    # Domains are normalized to lowercase.
    assert scope.targets.domains == ["empresa.com.br"]
    assert scope.allowed_tests.recon is True
    assert scope.allowed_tests.exploitation is False


def test_scope_model_rejects_invalid_domain() -> None:
    with pytest.raises(ValidationError):
        ScopeModel.model_validate(
            {
                "project": {"client": "X", "name": "Y"},
                "targets": {"domains": ["not a domain"]},
            }
        )


def test_scope_model_allows_empty_targets_but_not_ready() -> None:
    # An empty target list is structurally valid (project created before
    # targets are known) but is not yet ready for testing.
    scope = ScopeModel.model_validate(
        {
            "project": {"client": "X", "name": "Y"},
            "targets": {"domains": [], "ips": []},
        }
    )
    assert scope.has_targets is False


def test_scope_model_has_targets_true_when_domain_present() -> None:
    scope = ScopeModel.model_validate(
        {
            "project": {"client": "X", "name": "Y"},
            "targets": {"domains": ["example.com"]},
        }
    )
    assert scope.has_targets is True


def test_settings_model_defaults() -> None:
    settings = SettingsModel()
    assert settings.app.name == "GhostMirror"
    assert settings.paths.projects == "./projects"
