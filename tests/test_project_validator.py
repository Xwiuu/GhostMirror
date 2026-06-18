from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from ghostmirror.core.exceptions import (
    ProjectNotFoundError,
    ScopeViolationError,
)
from ghostmirror.modules.platform.project_validator import ProjectValidator


@pytest.fixture()
def validator() -> ProjectValidator:
    return ProjectValidator()


def _make_project(tmp_path: Path, slug: str, with_scope: bool = True, with_meta: bool = True, valid_scope: bool = True) -> Path:
    proj = tmp_path / slug
    proj.mkdir(parents=True, exist_ok=True)
    if with_meta:
        meta = {"client": "Test", "name": slug, "uuid": "abc-123", "status": "active", "created_at": "2026-01-01"}
        (proj / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    if with_scope:
        scope = {"project": {"client": "Test", "name": slug}, "targets": {"domains": ["example.com"]}, "allowed_tests": {"recon": True}}
        if not valid_scope:
            scope["targets"]["domains"] = []
        (proj / "scope.yaml").write_text(yaml.dump(scope), encoding="utf-8")
    return proj


class TestProjectValidator:
    def test_validate_valid_project(self, validator: ProjectValidator, tmp_path: Path):
        proj = _make_project(tmp_path, "valid-proj")
        report = validator.validate_project(proj)
        assert report["exists"] is True
        assert report["metadata_exists"] is True
        assert report["scope_exists"] is True
        assert report["scope_valid"] is True
        assert report["targets_defined"] is True
        assert report["errors"] == []

    def test_validate_project_not_found(self, validator: ProjectValidator, tmp_path: Path):
        with pytest.raises(ProjectNotFoundError):
            validator.validate_project(tmp_path / "nonexistent")

    def test_validate_project_no_meta(self, validator: ProjectValidator, tmp_path: Path):
        proj = _make_project(tmp_path, "no-meta", with_meta=False)
        report = validator.validate_project(proj)
        assert report["exists"] is True
        assert report["metadata_exists"] is False

    def test_validate_project_no_scope(self, validator: ProjectValidator, tmp_path: Path):
        proj = _make_project(tmp_path, "no-scope", with_scope=False)
        with pytest.raises(ScopeViolationError):
            validator.validate_project(proj)

    def test_validate_project_invalid_scope(self, validator: ProjectValidator, tmp_path: Path):
        proj = _make_project(tmp_path, "bad-scope", valid_scope=False)
        with patch.object(validator.scope_manager, "validate_scope", return_value=(False, "Nenhum alvo definido")):
            report = validator.validate_project(proj)
            assert report["scope_valid"] is False

    def test_validate_project_corrupted_meta(self, validator: ProjectValidator, tmp_path: Path):
        proj = _make_project(tmp_path, "corrupt-meta", with_meta=False)
        (proj / "metadata.json").write_text("not json", encoding="utf-8")
        (proj / "scope.yaml").write_text(yaml.dump({"project": {"client": "T", "name": "corrupt-meta"}, "targets": {"domains": ["t.com"]}, "allowed_tests": {"recon": True}}), encoding="utf-8")
        report = validator.validate_project(proj)
        assert report["metadata_exists"] is True
        assert any("corrompido" in e for e in report["errors"])
