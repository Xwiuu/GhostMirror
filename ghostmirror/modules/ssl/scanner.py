"""Concrete implementation of the SSL/TLS Security Scanner."""

from __future__ import annotations

import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from ghostmirror.core.logger import get_logger
from ghostmirror.modules.base.scanner import OutOfScopeError, ScannerBase
from ghostmirror.modules.models.finding import (
    FindingModel,
    FindingSeverity,
    ScanResultModel,
)

logger = get_logger()


def check_hostname_match(target_host: str, cert: x509.Certificate) -> bool:
    """Validate whether the requested hostname matches the certificate's CN or SANs.

    Supports wildcard hostnames and IP addresses.
    """
    target_host = target_host.lower().strip()

    # Check if target is an IP address
    is_ip = False
    try:
        target_ip = ipaddress.ip_address(target_host)
        is_ip = True
    except ValueError:
        pass

    # Extract Subject Alternative Names (SANs)
    dns_names: list[str] = []
    ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for val in san_ext.value:
            if isinstance(val, x509.DNSName):
                dns_names.append(val.value.lower().strip())
            elif isinstance(val, x509.IPAddress):
                ip_addresses.append(val.value)
    except Exception:
        pass

    # Fallback to Common Name if no SANs are defined
    if not dns_names and not ip_addresses:
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            dns_names.append(str(cn_attrs[0].value).lower().strip())

    if is_ip:
        for ip in ip_addresses:
            if ip == target_ip:
                return True
        return False
    else:
        for pattern in dns_names:
            if pattern == target_host:
                return True
            if pattern.startswith("*."):
                suffix = pattern[2:]
                parts = target_host.split(".", 1)
                if len(parts) == 2 and parts[1] == suffix and parts[0] != "":
                    return True
        return False


class SSLScanner(ScannerBase):
    """SSLScanner audits the SSL/TLS configuration of a target HTTPS host.

    It retrieves the remote certificate, extracts metadata, checks for cryptographic
    and trust vulnerabilities, probes supported TLS versions, and returns a detailed ScanResult.
    """

    SCANNER_NAME = "ssl"
    SCANNER_VERSION = "0.1.0"

    def get_metadata(self) -> dict[str, Any]:
        """Return SSLScanner metadata."""
        return {
            "name": self.SCANNER_NAME,
            "version": self.SCANNER_VERSION,
            "description": "SSL/TLS Configuration and Certificate Auditor",
        }

    def _get_connection_host_and_port(self) -> tuple[str, int]:
        """Parse host and port from target string. Defaults port to 443."""
        target_lower = self.target.lower()
        url_to_parse = self.target
        if not target_lower.startswith(("http://", "https://")):
            url_to_parse = f"https://{self.target}"

        from urllib.parse import urlparse
        try:
            parsed = urlparse(url_to_parse)
            host = parsed.hostname
            port = parsed.port
            if not host:
                cleaned = self.target.strip()
                if ":" in cleaned:
                    parts = cleaned.split(":")
                    if parts[-1].isdigit():
                        return ":".join(parts[:-1]), int(parts[-1])
                return cleaned, 443
            return host, port if port is not None else 443
        except Exception:
            return self.target, 443

    def _fetch_der_certificate(self, host: str, port: int) -> tuple[bytes, bool]:
        """Fetch DER-encoded certificate from target.

        Returns (der_bytes, chain_valid).
        """
        # Try verified connection first (verifies trust, expiry, hostname match)
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5.0) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    der_bytes = ssock.getpeercert(binary_form=True)
                    if der_bytes:
                        return der_bytes, True
        except Exception as exc:
            logger.info("SSL_VERIFY_FAILED target={} host={} error={}", self.target, host, exc)

        # Fallback to unverified connection to fetch the certificate bytes
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5.0) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    der_bytes = ssock.getpeercert(binary_form=True)
                    if der_bytes:
                        return der_bytes, False
        except Exception as exc:
            logger.error("SSL_CONNECTION_FAILED target={} host={} error={}", self.target, host, exc)
            raise ConnectionError(f"Could not connect to {host}:{port}: {exc}") from exc

        raise ConnectionError(f"Could not retrieve certificate from {host}:{port}")

    def _probe_tls_version(self, host: str, port: int, version_constant: Any) -> bool:
        """Attempt connection restricted to a specific TLS version."""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version_constant
            context.maximum_version = version_constant
            with socket.create_connection((host, port), timeout=3.0) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return bool(ssock.version())
        except Exception:
            return False

    def run(self) -> ScanResultModel:
        """Run the SSL/TLS scan on the target."""
        from ghostmirror.modules.platform.logger import log_audit

        logger.info("SCAN_STARTED scanner={} target={}", self.SCANNER_NAME, self.target)
        log_audit(
            event="scan iniciado",
            project=self.project_path.name,
            scanner=self.SCANNER_NAME,
            result="pendente",
        )
        started_at = datetime.now(timezone.utc)

        # 1. Validate Scope
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

        findings: list[FindingModel] = []
        status = "failed"
        certificate_summary = None

        # 2. Execute Scan
        try:
            host, port = self._get_connection_host_and_port()
            
            # Fetch Certificate
            der_bytes, chain_valid = self._fetch_der_certificate(host, port)
            
            # Probe TLS versions
            supported_tls = []
            versions_to_check = [
                ("TLSv1.0", ssl.TLSVersion.TLSv1),
                ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
                ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
            ]
            for label, ver_const in versions_to_check:
                if self._probe_tls_version(host, port, ver_const):
                    supported_tls.append(label)

            # Analyze cert and generate findings
            findings = self._analyze_certificate(der_bytes, chain_valid, host, supported_tls)
            
            # Build summary
            cert = x509.load_der_x509_certificate(der_bytes)
            try:
                not_after = cert.not_valid_after_utc
            except AttributeError:
                not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
            
            now = datetime.now(timezone.utc)
            days_until_expiration = (not_after - now).days

            def get_common_name(name) -> str:
                cn_attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
                if cn_attrs:
                    return str(cn_attrs[0].value)
                return name.rfc4514_string()

            certificate_summary = {
                "issuer": get_common_name(cert.issuer),
                "subject": get_common_name(cert.subject),
                "expires_in_days": days_until_expiration,
                "expires_at": not_after.strftime("%Y-%m-%d"),
                "tls_versions": supported_tls,
            }
            status = "completed"

            # Log key details
            logger.info("SSL_SCAN_DETAILS issuer={} expiration={} findings={}",
                        certificate_summary["issuer"], not_after.isoformat(), len(findings))

        except Exception as exc:
            logger.error("SCAN_UNEXPECTED_ERROR scanner={} error={}", self.SCANNER_NAME, exc)
            status = "failed"

        finished_at = datetime.now(timezone.utc)
        stats = self.calculate_statistics(findings)

        result = ScanResultModel(
            scanner_name=self.SCANNER_NAME,
            target=self.target,
            started_at=started_at,
            finished_at=finished_at,
            status=status,
            findings=findings,
            statistics=stats,
            certificate_summary=certificate_summary,
        )

        # 3. Save Findings
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

    def _analyze_certificate(
        self,
        der_bytes: bytes,
        chain_valid: bool,
        host: str,
        supported_tls: list[str],
    ) -> list[FindingModel]:
        """Verify certificate contents and environment capabilities, returning findings."""
        findings: list[FindingModel] = []
        now = datetime.now(timezone.utc)

        cert = x509.load_der_x509_certificate(der_bytes)

        # Extracted dates
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

        days_until_expiration = (not_after - now).days
        evidence_dates = f"Not Before: {not_before.isoformat()}\nNot After: {not_after.isoformat()}\nCurrent Time: {now.isoformat()}"

        # 1. Expiration Checks
        if not_after < now:
            findings.append(FindingModel(
                title="Expired SSL Certificate",
                severity=FindingSeverity.CRITICAL,
                target=self.target,
                description=f"The SSL/TLS certificate for {self.target} expired on {not_after.isoformat()}.",
                recommendation="Renew the SSL/TLS certificate immediately with a trusted Certificate Authority.",
                evidence=evidence_dates,
            ))
        elif days_until_expiration < 7:
            findings.append(FindingModel(
                title="Certificate Expiring Soon",
                severity=FindingSeverity.HIGH,
                target=self.target,
                description=f"The SSL/TLS certificate for {self.target} expires in {days_until_expiration} days (on {not_after.isoformat()}).",
                recommendation="Renew the SSL/TLS certificate immediately to prevent service disruption.",
                evidence=evidence_dates,
            ))
        elif days_until_expiration < 15:
            findings.append(FindingModel(
                title="Certificate Expiring Soon",
                severity=FindingSeverity.MEDIUM,
                target=self.target,
                description=f"The SSL/TLS certificate for {self.target} expires in {days_until_expiration} days (on {not_after.isoformat()}).",
                recommendation="Renew the SSL/TLS certificate soon to avoid potential outage.",
                evidence=evidence_dates,
            ))
        elif days_until_expiration < 30:
            findings.append(FindingModel(
                title="Certificate Expiring Soon",
                severity=FindingSeverity.LOW,
                target=self.target,
                description=f"The SSL/TLS certificate for {self.target} expires in {days_until_expiration} days (on {not_after.isoformat()}).",
                recommendation="Plan the renewal of the SSL/TLS certificate.",
                evidence=evidence_dates,
            ))

        # 2. Self-Signed Check
        is_self_signed = cert.issuer == cert.subject
        if is_self_signed:
            findings.append(FindingModel(
                title="Self-Signed Certificate",
                severity=FindingSeverity.HIGH,
                target=self.target,
                description=f"The SSL/TLS certificate for {self.target} is self-signed. Issuer and Subject are identical: '{cert.issuer.rfc4514_string()}'. Self-signed certificates are not trusted by browsers by default, exposing users to MITM attacks.",
                recommendation="Replace the self-signed certificate with one issued by a trusted Certificate Authority (e.g. Let's Encrypt).",
                evidence=f"Issuer: {cert.issuer.rfc4514_string()}\nSubject: {cert.subject.rfc4514_string()}",
            ))

        # 3. Hostname Mismatch Check
        hostname_matched = check_hostname_match(host, cert)
        if not hostname_matched:
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            cn = str(cn_attrs[0].value) if cn_attrs else "None"
            sans: list[str] = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for dns_name in san_ext.value.get_values_for_type(x509.DNSName):
                    sans.append(dns_name)
                for ip_addr in san_ext.value.get_values_for_type(x509.IPAddress):
                    sans.append(str(ip_addr))
            except Exception:
                pass
            evidence_mismatch = f"Requested Host: {host}\nSubject Common Name: {cn}\nSANs: {', '.join(sans) if sans else 'None'}"
            findings.append(FindingModel(
                title="Hostname Validation Failure",
                severity=FindingSeverity.HIGH,
                target=self.target,
                description=f"The requested host '{host}' does not match the Subject Common Name or Subject Alternative Names (SANs) in the SSL/TLS certificate.",
                recommendation="Configure the certificate to include the correct hostname or update the service configuration to use a valid in-scope domain.",
                evidence=evidence_mismatch,
            ))

        # 4. TLS Version Check
        for ver in supported_tls:
            if ver == "TLSv1.0":
                findings.append(FindingModel(
                    title="Weak TLS Version Enabled",
                    severity=FindingSeverity.HIGH,
                    target=self.target,
                    description="The server supports TLS 1.0, which is obsolete and contains cryptographic vulnerabilities (e.g., BEAST).",
                    recommendation="Disable TLS 1.0 on the server configuration. Enforce TLS 1.2 and TLS 1.3.",
                    evidence="TLS 1.0 connection handshake succeeded.",
                ))
            elif ver == "TLSv1.1":
                findings.append(FindingModel(
                    title="Weak TLS Version Enabled",
                    severity=FindingSeverity.MEDIUM,
                    target=self.target,
                    description="The server supports TLS 1.1, which is outdated and deprecated.",
                    recommendation="Disable TLS 1.1 on the server configuration. Enforce TLS 1.2 and TLS 1.3.",
                    evidence="TLS 1.1 connection handshake succeeded.",
                ))
            elif ver == "TLSv1.2":
                findings.append(FindingModel(
                    title="TLS Version Supported",
                    severity=FindingSeverity.INFO,
                    target=self.target,
                    description="The server supports TLS 1.2, which is currently considered secure.",
                    recommendation="Maintain support for TLS 1.2 while encouraging clients to transition to TLS 1.3.",
                    evidence="TLS 1.2 connection handshake succeeded.",
                ))
            elif ver == "TLSv1.3":
                findings.append(FindingModel(
                    title="TLS Version Supported",
                    severity=FindingSeverity.INFO,
                    target=self.target,
                    description="The server supports TLS 1.3, which is the latest and most secure TLS version.",
                    recommendation="Maintain TLS 1.3 enabled as the preferred secure protocol version.",
                    evidence="TLS 1.3 connection handshake succeeded.",
                ))

        # 5. Weak Signature Algorithms Check
        try:
            hash_algo = cert.signature_hash_algorithm
        except Exception:
            hash_algo = None

        sig_name = ""
        try:
            sig_name = cert.signature_algorithm_oid._name.lower()
        except Exception:
            pass

        if (hash_algo and isinstance(hash_algo, hashes.MD5)) or "md5" in sig_name:
            findings.append(FindingModel(
                title="Weak Signature Algorithm",
                severity=FindingSeverity.HIGH,
                target=self.target,
                description=f"The certificate signature algorithm ({sig_name or 'MD5'}) uses MD5, which is cryptographically broken and vulnerable to collision attacks.",
                recommendation="Replace the certificate with one using a modern signature algorithm like SHA-256.",
                evidence=f"Signature Algorithm: {sig_name or 'MD5'}",
            ))
        elif (hash_algo and isinstance(hash_algo, hashes.SHA1)) or "sha1" in sig_name or "sha-1" in sig_name:
            findings.append(FindingModel(
                title="Weak Signature Algorithm",
                severity=FindingSeverity.MEDIUM,
                target=self.target,
                description=f"The certificate signature algorithm ({sig_name or 'SHA-1'}) uses SHA-1, which is outdated and no longer secure.",
                recommendation="Replace the certificate with one using a modern signature algorithm like SHA-256.",
                evidence=f"Signature Algorithm: {sig_name or 'SHA-1'}",
            ))

        # 6. Key Size Check
        pub_key = cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            if pub_key.key_size < 2048:
                findings.append(FindingModel(
                    title="Weak RSA Key Length",
                    severity=FindingSeverity.HIGH,
                    target=self.target,
                    description=f"The certificate uses a weak RSA key size of {pub_key.key_size} bits. Key sizes below 2048 bits are vulnerable to brute-force factorization.",
                    recommendation="Generate a new key pair with a size of at least 2048 bits (4096 bits recommended).",
                    evidence=f"RSA Key Size: {pub_key.key_size} bits",
                ))
            else:
                findings.append(FindingModel(
                    title="RSA Key Length Info",
                    severity=FindingSeverity.INFO,
                    target=self.target,
                    description=f"The certificate uses an RSA key size of {pub_key.key_size} bits.",
                    recommendation="Maintain key size at 2048 bits or higher.",
                    evidence=f"RSA Key Size: {pub_key.key_size} bits",
                ))
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            findings.append(FindingModel(
                title="ECC Key Supported",
                severity=FindingSeverity.INFO,
                target=self.target,
                description=f"The certificate uses an Elliptic Curve (ECC) key of curve {pub_key.curve.name} ({pub_key.curve.key_size} bits). ECC is modern and secure.",
                recommendation="ECC keys are recommended for optimal performance and security.",
                evidence=f"ECC Key: Curve {pub_key.curve.name}, {pub_key.curve.key_size} bits",
            ))

        # 7. Certificate Chain / Trust Issues (if verification failed but not self-signed)
        if not chain_valid and not is_self_signed:
            findings.append(FindingModel(
                title="Certificate Chain Validation Failure",
                severity=FindingSeverity.HIGH,
                target=self.target,
                description=f"The certificate chain for {self.target} failed validation. This could indicate an untrusted root CA, a missing intermediate certificate, or incorrect installation.",
                recommendation="Install all required intermediate certificates on the web server and ensure the certificate is signed by a trusted root CA.",
                evidence="Standard TLS handshake validation failed.",
            ))

        return findings
