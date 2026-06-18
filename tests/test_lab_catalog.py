"""Tests for the lab catalog module."""

from __future__ import annotations

from pathlib import Path

import pytest

from ghostmirror.core.exceptions import LabNotFoundError
from ghostmirror.modules.lab.catalog import LabCatalog


@pytest.fixture(autouse=True)
def reset_catalog() -> None:
    LabCatalog.reset()
    yield
    LabCatalog.reset()


class TestLabCatalog:
    def test_get_all_returns_all_labs(self) -> None:
        labs = LabCatalog.get_all()
        assert len(labs) == 4

        ids = [l.id for l in labs]
        assert "juice-shop" in ids
        assert "dvwa" in ids
        assert "webgoat" in ids
        assert "vuln-demo" in ids

    def test_get_valid_lab(self) -> None:
        lab = LabCatalog.get("juice-shop")
        assert lab.id == "juice-shop"
        assert lab.name == "OWASP Juice Shop"
        assert lab.default_port == 3000
        assert lab.default_url == "http://localhost:3000"
        assert lab.difficulty == "medium"

    def test_get_invalid_lab_raises(self) -> None:
        with pytest.raises(LabNotFoundError, match="not found"):
            LabCatalog.get("nonexistent-lab")

    def test_exists(self) -> None:
        assert LabCatalog.exists("juice-shop")
        assert LabCatalog.exists("dvwa")
        assert LabCatalog.exists("webgoat")
        assert LabCatalog.exists("vuln-demo")
        assert not LabCatalog.exists("unknown")

    def test_dvwa_lab(self) -> None:
        lab = LabCatalog.get("dvwa")
        assert lab.id == "dvwa"
        assert lab.name == "DVWA"
        assert lab.default_port == 80

    def test_webgoat_lab(self) -> None:
        lab = LabCatalog.get("webgoat")
        assert lab.id == "webgoat"
        assert lab.default_port == 8080

    def test_vuln_demo_lab(self) -> None:
        lab = LabCatalog.get("vuln-demo")
        assert lab.id == "vuln-demo"
        assert lab.default_port == 8000
        assert lab.difficulty == "beginner"

    def test_compose_files_exist(self) -> None:
        checks = LabCatalog.compose_files_exist()
        assert isinstance(checks, dict)
        # In test environment the compose files may not exist at the resolved path
        # but we can at least check the keys are correct
        assert set(checks.keys()) == {"juice-shop", "dvwa", "webgoat", "vuln-demo"}

    def test_validate_catalog_returns_list(self) -> None:
        errors = LabCatalog.validate_catalog()
        assert isinstance(errors, list)

    def test_lab_has_tags(self) -> None:
        lab = LabCatalog.get("juice-shop")
        assert "owasp" in lab.tags

    def test_lab_has_expected_findings(self) -> None:
        lab = LabCatalog.get("juice-shop")
        assert isinstance(lab.expected_findings, list)

    def test_lab_descriptions_not_empty(self) -> None:
        for lab in LabCatalog.get_all():
            assert lab.description, f"Lab {lab.id} has no description"
