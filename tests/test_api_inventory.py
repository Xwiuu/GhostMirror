from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghostmirror.models.api_endpoint import APIEndpoint
from ghostmirror.models.api_inventory_profile import APIInventoryProfile
from ghostmirror.modules.api_security.api_inventory import APIInventory


@pytest.fixture
def project_path(tmp_path: Path) -> Path:
    base = tmp_path / "test_project"
    profiles = base / "profiles"
    web_intel = profiles / "web_intelligence"
    bug_bounty = profiles / "bug_bounty"
    evidence = base / "evidence" / "bug_bounty"
    for d in (web_intel, bug_bounty, evidence):
        d.mkdir(parents=True, exist_ok=True)
    return base


def _write_json(path: Path, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def test_empty_consolidation(project_path: Path):
    inv = APIInventory()
    profile = inv.consolidate(project_path)
    assert profile.total_endpoints == 0
    assert profile.total_methods == {}
    assert profile.total_sources == {}


def test_consolidates_from_web_intel(project_path: Path):
    web_intel_file = project_path / "profiles" / "web_intelligence" / "endpoint_inventory.json"
    _write_json(web_intel_file, [
        {"method": "GET", "path": "/api/users", "content_type": "application/json", "auth_required": True, "confidence": "high"},
        {"method": "POST", "path": "/api/login", "content_type": "application/json", "auth_required": False, "confidence": "medium"},
    ])
    inv = APIInventory()
    profile = inv.consolidate(project_path)
    assert profile.total_endpoints == 2
    assert profile.total_methods == {"GET": 1, "POST": 1}
    assert profile.total_sources == {"web_intel": 2}
    assert profile.auth_required_count == 1


def test_dedup_same_endpoint(project_path: Path):
    web_intel_file = project_path / "profiles" / "web_intelligence" / "endpoint_inventory.json"
    bb_file = project_path / "profiles" / "bug_bounty" / "api_inventory.json"
    data = [{"method": "GET", "path": "/api/users"}]
    _write_json(web_intel_file, data)
    _write_json(bb_file, data)
    inv = APIInventory()
    profile = inv.consolidate(project_path)
    assert profile.total_endpoints == 1


def test_consolidates_from_multiple_sources(project_path: Path):
    _write_json(project_path / "profiles" / "web_intelligence" / "endpoint_inventory.json",
                [{"method": "GET", "path": "/api/users"}])
    _write_json(project_path / "profiles" / "bug_bounty" / "api_inventory.json",
                [{"method": "POST", "path": "/api/orders"}])
    _write_json(project_path / "profiles" / "web_intelligence" / "js_intelligence.json",
                {"internal_urls": ["/api/products"]})
    inv = APIInventory()
    profile = inv.consolidate(project_path)
    assert profile.total_endpoints == 3
    assert profile.total_sources.get("web_intel") == 1
    assert profile.total_sources.get("bug_bounty") == 1
    assert profile.total_sources.get("js_intel") == 1


def test_confidence_tracking(project_path: Path):
    _write_json(project_path / "profiles" / "web_intelligence" / "endpoint_inventory.json", [
        {"method": "GET", "path": "/api/users", "confidence": "high"},
        {"method": "GET", "path": "/api/items", "confidence": "low"},
    ])
    inv = APIInventory()
    profile = inv.consolidate(project_path)
    assert profile.total_confidence.get("high") == 1
    assert profile.total_confidence.get("low") == 1


def test_get_endpoints(project_path: Path):
    _write_json(project_path / "profiles" / "web_intelligence" / "endpoint_inventory.json",
                [{"method": "GET", "path": "/api/test"}])
    inv = APIInventory()
    inv.consolidate(project_path)
    endpoints = inv.get_endpoints()
    assert len(endpoints) == 1
    assert isinstance(endpoints[0], APIEndpoint)


def test_json_list_nonexistent(project_path: Path):
    inv = APIInventory()
    result = inv._load_json_list(project_path / "nonexistent.json")
    assert result == []


def test_json_dict_nonexistent(project_path: Path):
    inv = APIInventory()
    result = inv._load_json_dict(project_path / "nonexistent.json")
    assert result is None
