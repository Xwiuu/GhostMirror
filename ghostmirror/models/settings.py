"""Pydantic models for the global application settings (``config/settings.yaml``)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AppInfo(BaseModel):
    """High-level application identity and runtime environment."""

    name: str = Field(default="GhostMirror", min_length=1)
    version: str = Field(default="1.0-alpha", min_length=1)
    environment: str = Field(default="development", min_length=1)


class PathsConfig(BaseModel):
    """Filesystem locations used by the platform.

    Relative paths are resolved against the GhostMirror home directory by the
    :class:`~ghostmirror.core.config_manager.ConfigManager`.
    """

    projects: str = Field(default="./projects", min_length=1)
    logs: str = Field(default="./logs", min_length=1)
    reports: str = Field(default="./reports", min_length=1)
    findings: str = Field(default="findings", min_length=1)
    profiles: str = Field(default="profiles", min_length=1)
    evidence: str = Field(default="evidence", min_length=1)
    execution: str = Field(default="execution", min_length=1)


class TimeoutsConfig(BaseModel):
    """Timeout values (in seconds) for external tools and scans."""

    nmap: float = Field(default=600.0)
    whatweb: float = Field(default=60.0)
    nuclei: float = Field(default=900.0)
    ssl: float = Field(default=30.0)
    headers: float = Field(default=30.0)


class RateLimitsConfig(BaseModel):
    """Rate limiting and concurrency parameters for scan tools."""

    nmap_threads: int = Field(default=10)
    nuclei_concurrency: int = Field(default=50)


class ProfilesConfig(BaseModel):
    """Step pipeline configurations for each scan profile."""

    lite: list[str] = Field(default_factory=lambda: ["headers", "ssl", "nmap", "fingerprint", "report"])
    standard: list[str] = Field(
        default_factory=lambda: [
            "headers",
            "ssl",
            "nmap",
            "fingerprint",
            "technology_intelligence",
            "cve_intelligence",
            "nuclei",
            "owasp",
            "report",
        ]
    )
    deep: list[str] = Field(
        default_factory=lambda: [
            "headers",
            "ssl",
            "nmap",
            "fingerprint",
            "technology_intelligence",
            "cve_intelligence",
            "nuclei",
            "owasp",
            "report",
        ]
    )


class ReportingConfig(BaseModel):
    """Output generation parameters for security reports."""

    formats: list[str] = Field(default_factory=lambda: ["html", "md", "pdf"])


class LoggingConfig(BaseModel):
    """Platform logging configuration levels."""

    file_level: str = Field(default="INFO")
    console_level: str = Field(default="WARNING")


class SettingsModel(BaseModel):
    """Root settings model, mirroring ``config/default.yaml`` and ``config/settings.yaml``."""

    app: AppInfo = Field(default_factory=AppInfo)
    paths: PathsConfig = Field(default_factory=PathsConfig)
    timeouts: TimeoutsConfig = Field(default_factory=TimeoutsConfig)
    rate_limits: RateLimitsConfig = Field(default_factory=RateLimitsConfig)
    profiles: ProfilesConfig = Field(default_factory=ProfilesConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

