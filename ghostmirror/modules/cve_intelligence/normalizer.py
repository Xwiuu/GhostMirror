"""Technology name normalizer using the aliases database."""

from __future__ import annotations

import json
from pathlib import Path
from ghostmirror.core.logger import get_logger

logger = get_logger()


class TechnologyNormalizer:
    """Standardizes technology names case-insensitively using an alias dictionary."""

    def __init__(self, aliases_path: Path | str) -> None:
        self.aliases: dict[str, str] = {}
        aliases_file = Path(aliases_path)
        if aliases_file.exists():
            try:
                with open(aliases_file, "r", encoding="utf-8") as f:
                    self.aliases = json.load(f)
            except Exception as exc:
                logger.error("Failed to load technology aliases from {}: {}", aliases_file, exc)
        else:
            # Fallback inline mapping if file is missing
            self.aliases = {
                "apache http server": "Apache",
                "apache httpd": "Apache",
                "httpd": "Apache",
                "nginx": "Nginx",
                "wordpress": "WordPress",
                "woocommerce": "WooCommerce",
                "laravel": "Laravel",
                "php": "PHP",
                "openssh": "OpenSSH",
                "ssh": "OpenSSH",
                "redis": "Redis",
                "mongodb": "MongoDB",
                "mysql": "MySQL",
                "postgresql": "PostgreSQL",
                "postgres": "PostgreSQL",
                "apache tomcat": "Tomcat",
                "tomcat": "Tomcat",
                "jquery": "jQuery",
                "drupal": "Drupal",
                "joomla": "Joomla"
            }

    def normalize(self, name: str) -> str:
        """Normalize a technology name to its standard form.

        Parameters
        ----------
        name : str
            The raw technology name detected (e.g. 'apache http server').

        Returns
        -------
        str
            The normalized name (e.g. 'Apache').
        """
        name_clean = name.strip()
        name_lower = name_clean.lower()
        return self.aliases.get(name_lower, name_clean)
