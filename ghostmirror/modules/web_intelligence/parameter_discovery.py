from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from ghostmirror.core.logger import get_logger
from ghostmirror.models.parameter_profile import ParameterProfile, ParameterType, ParameterSensitivity
from ghostmirror.models.web_endpoint import WebEndpoint

logger = get_logger()

FORM_INPUT_PATTERN = re.compile(r'<input\s[^>]*name=["\'](.*?)["\']', re.IGNORECASE)
FORM_TEXTAREA_PATTERN = re.compile(r'<textarea\s[^>]*name=["\'](.*?)["\']', re.IGNORECASE)
FORM_SELECT_PATTERN = re.compile(r'<select\s[^>]*name=["\'](.*?)["\']', re.IGNORECASE)


class ParameterDiscovery:
    def __init__(self) -> None:
        self._params: dict[str, ParameterProfile] = {}

    def discover(self, endpoints: list[WebEndpoint]) -> list[ParameterProfile]:
        logger.info("PARAMETER_DISCOVERY_START endpoints={}", len(endpoints))
        self._params.clear()

        for ep in endpoints:
            self._extract_query_params(ep)
            self._extract_form_params(ep)

        profiles = list(self._params.values())
        logger.info("PARAMETER_DISCOVERY_DONE total={}", len(profiles))
        return profiles

    def _extract_query_params(self, ep: WebEndpoint) -> None:
        parsed = urlparse(ep.url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for name, values in qs.items():
            if name not in self._params:
                sensitivity = ParameterProfile.classify_sensitivity(name)
                self._params[name] = ParameterProfile(
                    name=name,
                    param_type=ParameterType.QUERY,
                    sensitivity=sensitivity,
                )
            self._params[name].locations.append(ep.url)
            self._params[name].values_seen.extend(v for v in values if v and v not in self._params[name].values_seen)

    def _extract_form_params(self, ep: WebEndpoint) -> None:
        all_inputs = set()
        for form in ep.forms:
            for inp in form.inputs:
                all_inputs.add(inp)

        html = getattr(ep, "response_body_sample", "")
        if html:
            for match in FORM_INPUT_PATTERN.findall(html):
                all_inputs.add(match.strip())
            for match in FORM_TEXTAREA_PATTERN.findall(html):
                all_inputs.add(match.strip())
            for match in FORM_SELECT_PATTERN.findall(html):
                all_inputs.add(match.strip())

        for name in all_inputs:
            if not name:
                continue
            if name not in self._params:
                sensitivity = ParameterProfile.classify_sensitivity(name)
                self._params[name] = ParameterProfile(
                    name=name,
                    param_type=ParameterType.POST,
                    sensitivity=sensitivity,
                    found_in_form=True,
                )
            else:
                self._params[name].found_in_form = True
            self._params[name].locations.append(ep.url)
