"""Concrete implementation of the HTTP Security Headers Scanner."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from ghostmirror.core.logger import get_logger
from ghostmirror.core.scope_manager import ScopeManager
from ghostmirror.modules.base.scanner import OutOfScopeError, ScannerBase
from ghostmirror.modules.findings.manager import FindingsManager
from ghostmirror.modules.models.finding import (
    FindingModel,
    FindingSeverity,
    ScanResultModel,
)

logger = get_logger()


class HeadersScanner(ScannerBase):
    """HeadersScanner performs a scan of target HTTP response headers.

    Analyzes presence and security configuration of 9 standard HTTP response headers,
    producing categorized findings.
    """

    SCANNER_NAME = "headers"
    SCANNER_VERSION = "0.1.0"

    def get_metadata(self) -> dict[str, Any]:
        """Return HeadersScanner metadata."""
        return {
            "name": self.SCANNER_NAME,
            "version": self.SCANNER_VERSION,
            "description": "HTTP Security Headers Auditor",
        }

    def run(self) -> ScanResultModel:
        """Audit HTTP security headers for the target.

        Validates scope first, then performs the HTTP check.
        """
        from ghostmirror.modules.platform.logger import log_audit

        logger.info("SCAN_STARTED scanner={} target={}", self.SCANNER_NAME, self.target)
        log_audit(
            event="scan iniciado",
            project=self.project_path.name,
            scanner=self.SCANNER_NAME,
            result="pendente",
        )
        started_at = datetime.now(timezone.utc)

        # 1. Validate Target Scope
        try:
            self.validate_scope()
        except OutOfScopeError as exc:
            logger.error("SCAN_BLOCKED scanner={} target={} reason={}", self.SCANNER_NAME, self.target, exc)
            log_audit(
                event="scan finalizado",
                project=self.project_path.name,
                scanner=self.SCANNER_NAME,
                result="bloqueado",
            )
            raise

        # 2. Run Scan Execution
        findings: list[FindingModel] = []
        status = "failed"
        resolved_url = ""

        # Prepend HTTPS schema if absent
        url = self.target
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        try:
            # We follow redirects and disable SSL validation (verify=False)
            # so the scan works on internal staging environments and self-signed certificates.
            with httpx.Client(verify=False, follow_redirects=True, timeout=10.0) as client:
                response = client.get(url)
                status = "completed"
                resolved_url = str(response.url)
                findings = self._analyze_headers(response.headers, resolved_url)
        except httpx.HTTPError as exc:
            logger.warning("SCAN_HTTPS_FAILED scanner={} url={} error={}", self.SCANNER_NAME, url, exc)
            
            # Fall back to HTTP if HTTPS failed and the user did not specify the scheme
            if url.startswith("https://") and not self.target.startswith("https://"):
                fallback_url = f"http://{self.target}"
                logger.info("SCAN_FALLBACK scanner={} url={}", self.SCANNER_NAME, fallback_url)
                try:
                    with httpx.Client(verify=False, follow_redirects=True, timeout=10.0) as client:
                        response = client.get(fallback_url)
                        status = "completed"
                        resolved_url = str(response.url)
                        findings = self._analyze_headers(response.headers, resolved_url)
                except httpx.HTTPError as fallback_exc:
                    logger.error(
                        "SCAN_HTTP_FALLBACK_FAILED scanner={} url={} error={}",
                        self.SCANNER_NAME,
                        fallback_url,
                        fallback_exc,
                    )
                    status = "failed"
            else:
                status = "failed"
        except Exception as exc:
            logger.exception("SCAN_UNEXPECTED_ERROR scanner={} error={}", self.SCANNER_NAME, exc)
            status = "failed"

        finished_at = datetime.now(timezone.utc)
        stats = self.calculate_statistics(findings)

        result = ScanResultModel(
            scanner_name=self.SCANNER_NAME,
            target=resolved_url or self.target,
            started_at=started_at,
            finished_at=finished_at,
            status=status,
            findings=findings,
            statistics=stats,
        )

        # 3. Persist Findings on completed scan
        if status == "completed":
            self.save_findings(result)

        logger.info(
            "SCAN_FINISHED scanner={} target={} status={} findings={} elapsed={:.2f}s",
            self.SCANNER_NAME,
            self.target,
            status,
            len(findings),
            (finished_at - started_at).total_seconds(),
        )
        log_audit(
            event="scan finalizado",
            project=self.project_path.name,
            scanner=self.SCANNER_NAME,
            result=status,
        )

        return result

    def _analyze_headers(self, headers: httpx.Headers, resolved_url: str) -> list[FindingModel]:
        """Verify the configuration of the 9 required HTTP security headers."""
        findings: list[FindingModel] = []

        # 1. Content-Security-Policy (CSP)
        csp = headers.get("Content-Security-Policy")
        if not csp:
            findings.append(FindingModel(
                title="Missing Content-Security-Policy Header",
                severity=FindingSeverity.MEDIUM,
                target=resolved_url,
                description="The application does not define a Content-Security-Policy (CSP) header. Without CSP, the application is vulnerable to Cross-Site Scripting (XSS) and data injection attacks.",
                recommendation="Implement a robust Content-Security-Policy. Start with a restrictive policy like `default-src 'self'` and allow resources as needed.",
                evidence="Content-Security-Policy header is absent."
            ))
        else:
            val_lower = csp.lower()
            unsafe_directives = []
            if "'unsafe-inline'" in val_lower:
                unsafe_directives.append("'unsafe-inline'")
            if "'unsafe-eval'" in val_lower:
                unsafe_directives.append("'unsafe-eval'")
            if "*" in val_lower:
                unsafe_directives.append("wildcard '*'")

            if unsafe_directives:
                findings.append(FindingModel(
                    title="Misconfigured Content-Security-Policy Header",
                    severity=FindingSeverity.LOW,
                    target=resolved_url,
                    description=f"The Content-Security-Policy header is configured with potentially unsafe directives: {', '.join(unsafe_directives)}.",
                    recommendation="Review and restrict the Content-Security-Policy directives. Avoid using 'unsafe-inline' or wildcard '*' sources. Use nonces or hashes instead.",
                    evidence=f"Content-Security-Policy: {csp}"
                ))

        # 2. Strict-Transport-Security (HSTS)
        hsts = headers.get("Strict-Transport-Security")
        if not hsts:
            findings.append(FindingModel(
                title="Missing Strict-Transport-Security Header",
                severity=FindingSeverity.LOW,
                target=resolved_url,
                description="The HTTP Strict Transport Security (HSTS) header is missing. This allows connections to fallback to insecure HTTP, exposing the application to man-in-the-middle (MITM) and credential sniffing attacks.",
                recommendation="Implement HSTS on your web server by adding the `Strict-Transport-Security` header to all HTTPS responses.",
                evidence="Strict-Transport-Security header is absent."
            ))
        else:
            val_lower = hsts.lower()
            max_age_match = re.search(r"max-age\s*=\s*(\d+)", val_lower)
            misconfigured = False
            reasons = []
            if not max_age_match:
                misconfigured = True
                reasons.append("max-age is missing")
            else:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:
                    misconfigured = True
                    reasons.append(f"max-age ({max_age}) is less than 1 year (31536000 seconds)")
            
            if "includesubdomains" not in val_lower:
                misconfigured = True
                reasons.append("includeSubDomains directive is missing")
                
            if misconfigured:
                findings.append(FindingModel(
                    title="Misconfigured Strict-Transport-Security Header",
                    severity=FindingSeverity.LOW,
                    target=resolved_url,
                    description=f"The Strict-Transport-Security header is misconfigured: {', '.join(reasons)}.",
                    recommendation="Configure the HSTS header with a max-age of at least 31536000 seconds (1 year) and include the includeSubDomains directive.",
                    evidence=f"Strict-Transport-Security: {hsts}"
                ))

        # 3. X-Frame-Options (XFO)
        xfo = headers.get("X-Frame-Options")
        if not xfo:
            findings.append(FindingModel(
                title="Missing X-Frame-Options Header",
                severity=FindingSeverity.MEDIUM,
                target=resolved_url,
                description="The X-Frame-Options header is missing. This allows the page to be framed by external websites, making the application vulnerable to clickjacking attacks.",
                recommendation="Configure the X-Frame-Options header with a value of DENY or SAMEORIGIN.",
                evidence="X-Frame-Options header is absent."
            ))
        else:
            val_upper = xfo.upper().strip()
            if val_upper not in ("DENY", "SAMEORIGIN"):
                findings.append(FindingModel(
                    title="Misconfigured X-Frame-Options Header",
                    severity=FindingSeverity.LOW,
                    target=resolved_url,
                    description=f"The X-Frame-Options header is configured with a non-standard or weak value: {xfo}.",
                    recommendation="Change the X-Frame-Options header to DENY or SAMEORIGIN.",
                    evidence=f"X-Frame-Options: {xfo}"
                ))

        # 4. X-Content-Type-Options (XCTO)
        xcto = headers.get("X-Content-Type-Options")
        if not xcto:
            findings.append(FindingModel(
                title="Missing X-Content-Type-Options Header",
                severity=FindingSeverity.LOW,
                target=resolved_url,
                description="The X-Content-Type-Options header is missing. Without this header, browsers might sniff the MIME type of a response, allowing attackers to execute cross-site scripting (XSS) via uploaded files.",
                recommendation="Configure the X-Content-Type-Options header with the value 'nosniff'.",
                evidence="X-Content-Type-Options header is absent."
            ))
        else:
            val_lower = xcto.lower().strip()
            if val_lower != "nosniff":
                findings.append(FindingModel(
                    title="Misconfigured X-Content-Type-Options Header",
                    severity=FindingSeverity.LOW,
                    target=resolved_url,
                    description=f"The X-Content-Type-Options header is configured with a value other than 'nosniff': {xcto}.",
                    recommendation="Set the X-Content-Type-Options header value to 'nosniff'.",
                    evidence=f"X-Content-Type-Options: {xcto}"
                ))

        # 5. Referrer-Policy
        ref = headers.get("Referrer-Policy")
        if not ref:
            findings.append(FindingModel(
                title="Missing Referrer-Policy Header",
                severity=FindingSeverity.INFO,
                target=resolved_url,
                description="The Referrer-Policy header is missing. Browsers will apply default behaviors which may leak sensitive parameters in URLs to third-party domains.",
                recommendation="Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
                evidence="Referrer-Policy header is absent."
            ))
        else:
            val_lower = ref.lower().strip()
            if val_lower in ("unsafe-url", "no-referrer-when-downgrade"):
                findings.append(FindingModel(
                    title="Misconfigured Referrer-Policy Header",
                    severity=FindingSeverity.INFO,
                    target=resolved_url,
                    description=f"The Referrer-Policy header uses an insecure policy: {ref}.",
                    recommendation="Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
                    evidence=f"Referrer-Policy: {ref}"
                ))

        # 6. Permissions-Policy
        perm = headers.get("Permissions-Policy")
        if not perm:
            findings.append(FindingModel(
                title="Missing Permissions-Policy Header",
                severity=FindingSeverity.INFO,
                target=resolved_url,
                description="The Permissions-Policy header is missing. This header restricts browser features (camera, microphone, geolocation) for security and privacy.",
                recommendation="Configure the Permissions-Policy header to restrict unauthorized browser APIs.",
                evidence="Permissions-Policy header is absent."
            ))

        # 7. Cross-Origin-Resource-Policy (CORP)
        corp = headers.get("Cross-Origin-Resource-Policy")
        if not corp:
            findings.append(FindingModel(
                title="Missing Cross-Origin-Resource-Policy Header",
                severity=FindingSeverity.INFO,
                target=resolved_url,
                description="The Cross-Origin-Resource-Policy (CORP) header is missing. This allows other domains to read resource contents, exposing the application to cross-origin data leaks.",
                recommendation="Implement Cross-Origin-Resource-Policy with a value of 'same-origin' or 'same-site'.",
                evidence="Cross-Origin-Resource-Policy header is absent."
            ))
        else:
            val_lower = corp.lower().strip()
            if val_lower not in ("same-site", "same-origin", "cross-origin"):
                findings.append(FindingModel(
                    title="Misconfigured Cross-Origin-Resource-Policy Header",
                    severity=FindingSeverity.INFO,
                    target=resolved_url,
                    description=f"The Cross-Origin-Resource-Policy header has an invalid value: {corp}.",
                    recommendation="Set CORP to 'same-origin', 'same-site', or 'cross-origin'.",
                    evidence=f"Cross-Origin-Resource-Policy: {corp}"
                ))

        # 8. Cross-Origin-Embedder-Policy (COEP)
        coep = headers.get("Cross-Origin-Embedder-Policy")
        if not coep:
            findings.append(FindingModel(
                title="Missing Cross-Origin-Embedder-Policy Header",
                severity=FindingSeverity.INFO,
                target=resolved_url,
                description="The Cross-Origin-Embedder-Policy (COEP) header is missing. Without COEP, the application cannot enforce cross-origin isolation.",
                recommendation="Implement Cross-Origin-Embedder-Policy set to 'require-corp' or 'credentialless'.",
                evidence="Cross-Origin-Embedder-Policy header is absent."
            ))
        else:
            val_lower = coep.lower().strip()
            if val_lower not in ("require-corp", "credentialless"):
                findings.append(FindingModel(
                    title="Misconfigured Cross-Origin-Embedder-Policy Header",
                    severity=FindingSeverity.INFO,
                    target=resolved_url,
                    description=f"The Cross-Origin-Embedder-Policy header has an invalid value: {coep}.",
                    recommendation="Set COEP to 'require-corp' or 'credentialless'.",
                    evidence=f"Cross-Origin-Embedder-Policy: {coep}"
                ))

        # 9. Cross-Origin-Opener-Policy (COOP)
        coop = headers.get("Cross-Origin-Opener-Policy")
        if not coop:
            findings.append(FindingModel(
                title="Missing Cross-Origin-Opener-Policy Header",
                severity=FindingSeverity.INFO,
                target=resolved_url,
                description="The Cross-Origin-Opener-Policy (COOP) header is missing. COOP helps isolate the application from potential cross-origin window exploits.",
                recommendation="Implement Cross-Origin-Opener-Policy set to 'same-origin'.",
                evidence="Cross-Origin-Opener-Policy header is absent."
            ))
        else:
            val_lower = coop.lower().strip()
            if val_lower == "unsafe-none" or val_lower not in ("same-origin", "same-origin-allow-popups", "unsafe-none"):
                findings.append(FindingModel(
                    title="Misconfigured Cross-Origin-Opener-Policy Header",
                    severity=FindingSeverity.INFO,
                    target=resolved_url,
                    description=f"The Cross-Origin-Opener-Policy header has an insecure or invalid value: {coop}.",
                    recommendation="Set COOP to 'same-origin' or 'same-origin-allow-popups'.",
                    evidence=f"Cross-Origin-Opener-Policy: {coop}"
                ))

        return findings
