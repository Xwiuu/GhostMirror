"""Parser for WhatWeb JSON output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()


class WhatWebParser:
    """Parser for WhatWeb JSON log format."""

    @staticmethod
    def parse_json_content(content: str) -> list[dict[str, Any]]:
        """Parses raw WhatWeb JSON string into a list of plugin detections.

        Parameters
        ----------
        content : str
            The raw JSON string from WhatWeb.

        Returns
        -------
        list[dict[str, Any]]
            List of detected plugins.
        """
        if not content.strip():
            return []

        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            logger.error("WHATWEB_JSON_PARSE_FAILED error={}", exc)
            raise ValueError(f"Invalid WhatWeb JSON output: {exc}") from exc

        if not isinstance(data, list):
            data = [data]

        detections = []
        for entry in data:
            plugins = entry.get("plugins", {})
            for plugin_name, plugin_data in plugins.items():
                version = None
                if "version" in plugin_data:
                    v_val = plugin_data["version"]
                    if isinstance(v_val, list) and v_val:
                        version = str(v_val[0])
                    elif v_val:
                        version = str(v_val)

                detections.append({
                    "name": plugin_name,
                    "version": version,
                    "raw": plugin_data
                })

        return detections

    @classmethod
    def parse_json_file(cls, filepath: Path | str) -> list[dict[str, Any]]:
        """Reads and parses a WhatWeb JSON output file.

        Parameters
        ----------
        filepath : Path | str
            Path to the JSON file.

        Returns
        -------
        list[dict[str, Any]]
            List of parsed detections.
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"WhatWeb JSON file not found at {path}")

        content = path.read_text(encoding="utf-8")
        return cls.parse_json_content(content)
