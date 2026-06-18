"""Global configuration management (``config/settings.yaml``)."""

from __future__ import annotations

import os
from pathlib import Path

from ghostmirror.core.logger import get_logger
from ghostmirror.models.settings import SettingsModel
from ghostmirror.storage.filesystem import FileSystemStorage

logger = get_logger()


class ConfigManager:
    """Loads, validates and exposes the global :class:`SettingsModel`.

    The "home" directory (where ``config/``, ``projects/`` … live) is resolved
    from the ``GHOSTMIRROR_HOME`` environment variable, falling back to the
    current working directory. This keeps the platform portable between local
    runs and the Docker container.
    """

    CONFIG_DIRNAME = "config"
    DEFAULT_FILENAME = "default.yaml"
    CONFIG_FILENAME = "settings.yaml"

    def __init__(self, base_dir: Path | str | None = None) -> None:
        self.base_dir: Path = (
            Path(base_dir) if base_dir is not None else self._discover_base_dir()
        ).resolve()
        self.config_path: Path = (
            self.base_dir / self.CONFIG_DIRNAME / self.CONFIG_FILENAME
        )
        self.default_path: Path = (
            self.base_dir / self.CONFIG_DIRNAME / self.DEFAULT_FILENAME
        )
        self._settings: SettingsModel | None = None

    # ------------------------------------------------------------------ #
    # Discovery / loading
    # ------------------------------------------------------------------ #
    @staticmethod
    def _discover_base_dir() -> Path:
        env_home = os.environ.get("GHOSTMIRROR_HOME")
        return Path(env_home) if env_home else Path.cwd()

    def load(self) -> SettingsModel:
        """Load settings from disk, merging defaults with custom overrides."""
        # 1. Ensure default.yaml exists
        if not self.default_path.exists():
            default_settings = SettingsModel()
            FileSystemStorage.write_yaml(self.default_path, default_settings.model_dump())
            logger.info("CONFIG_DEFAULT_CREATED path={}", self.default_path)

        # 2. Load default.yaml
        raw_default = FileSystemStorage.read_yaml(self.default_path)

        # 3. Load settings.yaml if it exists and merge
        if self.config_path.exists():
            raw_settings = FileSystemStorage.read_yaml(self.config_path)
            if raw_settings:
                raw_default = self._deep_merge(raw_default, raw_settings)
            logger.info("CONFIG_LOADED path={} merged_with={}", self.config_path, self.default_path)
        else:
            # Create settings.yaml with minimal override structure on first run
            basic_settings = {"app": {"environment": "development"}}
            FileSystemStorage.write_yaml(self.config_path, basic_settings)
            logger.info("CONFIG_CREATED path={}", self.config_path)
            raw_default = self._deep_merge(raw_default, basic_settings)

        self._settings = SettingsModel.model_validate(raw_default)
        return self._settings

    def _deep_merge(self, dict_a: dict, dict_b: dict) -> dict:
        """Recursively merge dict_b into dict_a."""
        for key, value in dict_b.items():
            if key in dict_a and isinstance(dict_a[key], dict) and isinstance(value, dict):
                self._deep_merge(dict_a[key], value)
            else:
                dict_a[key] = value
        return dict_a

    # ------------------------------------------------------------------ #
    # Accessors
    # ------------------------------------------------------------------ #
    @property
    def settings(self) -> SettingsModel:
        if self._settings is None:
            self.load()
        assert self._settings is not None  # for type-checkers
        return self._settings

    def resolve_path(self, relative: str) -> Path:
        """Resolve a (possibly relative) configured path against ``base_dir``."""

        candidate = Path(relative)
        if candidate.is_absolute():
            return candidate
        return (self.base_dir / candidate).resolve()

    @property
    def projects_dir(self) -> Path:
        return self.resolve_path(self.settings.paths.projects)

    @property
    def logs_dir(self) -> Path:
        return self.resolve_path(self.settings.paths.logs)

    @property
    def reports_dir(self) -> Path:
        return self.resolve_path(self.settings.paths.reports)
