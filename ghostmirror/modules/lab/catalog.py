"""Lab catalog — registry of all supported vulnerable environments."""

from __future__ import annotations

from pathlib import Path

from ghostmirror.models.lab_target import LabTarget

_LABS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "labs"


def _compose_path(filename: str) -> str:
    return str((_LABS_DIR / filename).resolve())


# --------------------------------------------------------------------------- #
# Built-in lab definitions
# --------------------------------------------------------------------------- #
_BUILTIN_LABS: list[LabTarget] = [
    LabTarget(
        id="juice-shop",
        name="OWASP Juice Shop",
        description="OWASP Juice Shop — modern web application with a wide range of vulnerabilities.",
        docker_compose_file=_compose_path("docker-compose.juice-shop.yml"),
        default_url="http://localhost:3000",
        default_port=3000,
        tags=["owasp", "training", "web", "javascript", "nodejs"],
        difficulty="medium",
        expected_findings=[
            "http_headers",
            "fingerprint",
            "owasp_top_10",
            "nuclei",
        ],
    ),
    LabTarget(
        id="dvwa",
        name="DVWA",
        description="Damn Vulnerable Web Application — classic PHP/MySQL vulnerable app.",
        docker_compose_file=_compose_path("docker-compose.dvwa.yml"),
        default_url="http://localhost:80",
        default_port=80,
        tags=["owasp", "training", "web", "php"],
        difficulty="easy",
        expected_findings=[
            "http_headers",
            "fingerprint",
            "owasp_top_10",
            "nuclei",
        ],
    ),
    LabTarget(
        id="webgoat",
        name="WebGoat",
        description="OWASP WebGoat — deliberately insecure web application for security training.",
        docker_compose_file=_compose_path("docker-compose.webgoat.yml"),
        default_url="http://localhost:8080",
        default_port=8080,
        tags=["owasp", "training", "web", "java"],
        difficulty="medium",
        expected_findings=[
            "http_headers",
            "fingerprint",
            "owasp_top_10",
            "nuclei",
        ],
    ),
    LabTarget(
        id="vuln-demo",
        name="GhostMirror Vuln Demo",
        description="GhostMirror proprietary lab — safe indicators for scanner validation without real vulnerabilities.",
        docker_compose_file=_compose_path("docker-compose.vuln-demo.yml"),
        default_url="http://localhost:8000",
        default_port=8000,
        tags=["ghostmirror", "demo", "training", "internal"],
        difficulty="beginner",
        expected_findings=[
            "missing_headers",
            "forms",
            "fingerprint",
        ],
    ),
]


class LabCatalog:
    """Registry and lookup for available lab environments."""

    _labs_by_id: dict[str, LabTarget] = {}

    @classmethod
    def _ensure_loaded(cls) -> None:
        if not cls._labs_by_id:
            cls._labs_by_id = {lab.id: lab for lab in _BUILTIN_LABS}

    @classmethod
    def get_all(cls) -> list[LabTarget]:
        cls._ensure_loaded()
        return list(cls._labs_by_id.values())

    @classmethod
    def get(cls, lab_id: str) -> LabTarget:
        cls._ensure_loaded()
        lab = cls._labs_by_id.get(lab_id)
        if lab is None:
            from ghostmirror.core.exceptions import LabNotFoundError

            raise LabNotFoundError(
                f"Lab {lab_id!r} not found. Available: {', '.join(cls._labs_by_id)}"
            )
        return lab

    @classmethod
    def exists(cls, lab_id: str) -> bool:
        cls._ensure_loaded()
        return lab_id in cls._labs_by_id

    @classmethod
    def compose_files_exist(cls) -> dict[str, bool]:
        cls._ensure_loaded()
        result: dict[str, bool] = {}
        for lab in cls._labs_by_id.values():
            result[lab.id] = Path(lab.docker_compose_file).exists()
        return result

    @classmethod
    def validate_catalog(cls) -> list[str]:
        cls._ensure_loaded()
        errors: list[str] = []
        for lab in cls._labs_by_id.values():
            if not Path(lab.docker_compose_file).exists():
                errors.append(
                    f"Missing compose file for {lab.id}: {lab.docker_compose_file}"
                )
        return errors

    @classmethod
    def reset(cls) -> None:
        cls._labs_by_id = {}
