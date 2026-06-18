"""Unit tests for the SSLScanner."""

from __future__ import annotations

import ipaddress
import socket
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from ghostmirror.core.scope_manager import ScopeManager
from ghostmirror.modules.base.scanner import OutOfScopeError
from ghostmirror.modules.ssl.scanner import SSLScanner, check_hostname_match


# --------------------------------------------------------------------------- #
# Certificate Generation Helper
# --------------------------------------------------------------------------- #
def generate_test_cert(
    subject_cn: str,
    issuer_cn: str,
    days_valid: int = 365,
    key_size: int = 2048,
    signature_hash=hashes.SHA256(),
    sans: list[str] | None = None,
    not_before: datetime | None = None,
) -> bytes:
    """Generate a mock DER-encoded certificate for unit testing."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    if not not_before:
        not_before = datetime.now(timezone.utc) - timedelta(days=1)
    not_after = not_before + timedelta(days=days_valid)

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(public_key)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)

    if sans:
        san_list = []
        for san in sans:
            try:
                ip = ipaddress.ip_address(san)
                san_list.append(x509.IPAddress(ip))
            except ValueError:
                san_list.append(x509.DNSName(san))
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )

    cert = builder.sign(private_key, signature_hash)
    return cert.public_bytes(serialization.Encoding.DER)


# --------------------------------------------------------------------------- #
# Mock SSL Socket and Connections
# --------------------------------------------------------------------------- #
class MockSSLSocket:
    def __init__(self, der_bytes: bytes, tls_version: str = "TLSv1.3"):
        self.der_bytes = der_bytes
        self._tls_version = tls_version

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def getpeercert(self, binary_form: bool = False):
        if binary_form:
            return self.der_bytes
        return None

    def version(self):
        return self._tls_version


# --------------------------------------------------------------------------- #
# Unit Tests
# --------------------------------------------------------------------------- #
def test_hostname_matching() -> None:
    # 1. Test normal DNS matching
    cert_bytes = generate_test_cert("example.com", "CA", sans=["example.com", "www.example.com"])
    cert = x509.load_der_x509_certificate(cert_bytes)
    assert check_hostname_match("example.com", cert) is True
    assert check_hostname_match("www.example.com", cert) is True
    assert check_hostname_match("other.com", cert) is False

    # 2. Test wildcard matching
    cert_bytes_wildcard = generate_test_cert("*.example.com", "CA", sans=["*.example.com"])
    cert_wildcard = x509.load_der_x509_certificate(cert_bytes_wildcard)
    assert check_hostname_match("sub.example.com", cert_wildcard) is True
    assert check_hostname_match("foo.example.com", cert_wildcard) is True
    assert check_hostname_match("example.com", cert_wildcard) is False
    assert check_hostname_match("foo.bar.example.com", cert_wildcard) is False

    # 3. Test IP matching
    cert_bytes_ip = generate_test_cert("192.168.1.1", "CA", sans=["192.168.1.1"])
    cert_ip = x509.load_der_x509_certificate(cert_bytes_ip)
    assert check_hostname_match("192.168.1.1", cert_ip) is True
    assert check_hostname_match("192.168.1.2", cert_ip) is False


def test_ssl_scanner_valid_cert(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = SSLScanner(tmp_path, "example.com", scope_manager)

    cert_bytes = generate_test_cert("example.com", "Trusted CA", days_valid=100)

    # Mock success on first connection
    mock_sock = MagicMock()
    mock_ssl_sock = MockSSLSocket(cert_bytes, "TLSv1.3")

    with patch("socket.create_connection", return_value=mock_sock), \
         patch("ssl.create_default_context") as mock_def_context:
        
        # Configure wrap_socket to return our mock SSL socket
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssl_sock
        mock_def_context.return_value = mock_ctx

        # We also mock _probe_tls_version to simulate TLS 1.2 and 1.3 support
        with patch.object(SSLScanner, "_probe_tls_version", side_effect=lambda h, p, v: v in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)):
            result = scanner.run()

    assert result.status == "completed"
    # No severity higher than INFO (RSA key length info, TLS 1.2 and TLS 1.3 info findings)
    assert result.statistics["critical"] == 0
    assert result.statistics["high"] == 0
    assert result.statistics["medium"] == 0
    assert result.statistics["low"] == 0
    assert result.certificate_summary is not None
    assert result.certificate_summary["issuer"] == "Trusted CA"
    assert result.certificate_summary["subject"] == "example.com"
    assert result.certificate_summary["expires_in_days"] >= 98
    assert "TLSv1.2" in result.certificate_summary["tls_versions"]
    assert "TLSv1.3" in result.certificate_summary["tls_versions"]


def test_ssl_scanner_expired_cert(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = SSLScanner(tmp_path, "example.com", scope_manager)

    # Expired 10 days ago
    not_before = datetime.now(timezone.utc) - timedelta(days=20)
    cert_bytes = generate_test_cert("example.com", "Trusted CA", days_valid=10, not_before=not_before)

    # First connection fails verification (raises verification error), second succeeds
    mock_sock = MagicMock()
    mock_ssl_sock = MockSSLSocket(cert_bytes, "TLSv1.3")

    with patch("socket.create_connection", return_value=mock_sock), \
         patch("ssl.create_default_context", side_effect=ssl.SSLCertVerificationError("Expired")), \
         patch("ssl.SSLContext") as mock_ssl_context_class:
        
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssl_sock
        mock_ssl_context_class.return_value = mock_ctx

        with patch.object(SSLScanner, "_probe_tls_version", return_value=True):
            result = scanner.run()

    assert result.status == "completed"
    # Finding generated for Expired SSL Certificate (CRITICAL)
    assert result.statistics["critical"] > 0
    expired_findings = [f for f in result.findings if f.title == "Expired SSL Certificate"]
    assert len(expired_findings) == 1


def test_ssl_scanner_self_signed_cert(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = SSLScanner(tmp_path, "example.com", scope_manager)

    # Subject == Issuer
    cert_bytes = generate_test_cert("example.com", "example.com")

    # First connection fails, second succeeds
    mock_sock = MagicMock()
    mock_ssl_sock = MockSSLSocket(cert_bytes, "TLSv1.3")

    with patch("socket.create_connection", return_value=mock_sock), \
         patch("ssl.create_default_context", side_effect=ssl.SSLCertVerificationError("Self-signed")), \
         patch("ssl.SSLContext") as mock_ssl_context_class:
        
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssl_sock
        mock_ssl_context_class.return_value = mock_ctx

        with patch.object(SSLScanner, "_probe_tls_version", return_value=True):
            result = scanner.run()

    assert result.status == "completed"
    # Self-signed Certificate finding is HIGH severity
    assert result.statistics["high"] > 0
    self_signed_findings = [f for f in result.findings if f.title == "Self-Signed Certificate"]
    assert len(self_signed_findings) == 1


def test_ssl_scanner_hostname_mismatch(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = SSLScanner(tmp_path, "example.com", scope_manager)

    # Target is example.com but certificate is for different.com with other.com and 192.168.1.1 in SANs
    cert_bytes = generate_test_cert("different.com", "Trusted CA", sans=["other.com", "192.168.1.1"])

    mock_sock = MagicMock()
    mock_ssl_sock = MockSSLSocket(cert_bytes, "TLSv1.3")

    with patch("socket.create_connection", return_value=mock_sock), \
         patch("ssl.create_default_context", side_effect=ssl.SSLCertVerificationError("Hostname mismatch")), \
         patch("ssl.SSLContext") as mock_ssl_context_class:
        
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssl_sock
        mock_ssl_context_class.return_value = mock_ctx

        with patch.object(SSLScanner, "_probe_tls_version", return_value=True):
            result = scanner.run()

    assert result.status == "completed"
    assert result.statistics["high"] > 0
    mismatch_findings = [f for f in result.findings if f.title == "Hostname Validation Failure"]
    assert len(mismatch_findings) == 1


def test_ssl_scanner_weak_algorithms_and_key(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = SSLScanner(tmp_path, "example.com", scope_manager)

    # 1024-bit RSA key signed with SHA256 (allowed by cryptography)
    cert_bytes = generate_test_cert("example.com", "Trusted CA", key_size=1024, signature_hash=hashes.SHA256())

    # Create proxy mock to override signature algorithm attributes
    real_cert = x509.load_der_x509_certificate(cert_bytes)
    mock_cert = MagicMock(wraps=real_cert)
    
    # Explicitly delegate properties to avoid MagicMock overriding them with new Mock instances
    try:
        mock_cert.not_valid_after_utc = real_cert.not_valid_after_utc
        mock_cert.not_valid_before_utc = real_cert.not_valid_before_utc
    except AttributeError:
        pass
    mock_cert.not_valid_after = real_cert.not_valid_after
    mock_cert.not_valid_before = real_cert.not_valid_before
    mock_cert.issuer = real_cert.issuer
    mock_cert.subject = real_cert.subject
    mock_cert.public_key.return_value = real_cert.public_key()
    mock_cert.extensions = real_cert.extensions
    
    # Mock signature_hash_algorithm to return MD5
    mock_cert.signature_hash_algorithm = hashes.MD5()
    
    # Mock signature_algorithm_oid._name to be "md5WithRSAEncryption"
    mock_oid = MagicMock()
    mock_oid._name = "md5WithRSAEncryption"
    mock_cert.signature_algorithm_oid = mock_oid

    mock_sock = MagicMock()
    mock_ssl_sock = MockSSLSocket(cert_bytes, "TLSv1.3")

    with patch("socket.create_connection", return_value=mock_sock), \
         patch("ssl.create_default_context", return_value=MagicMock()) as mock_def_context, \
         patch("ssl.SSLContext") as mock_ssl_context_class, \
         patch("cryptography.x509.load_der_x509_certificate", return_value=mock_cert):
        
        # Make first wrap_socket return our weak cert (simulate valid chain verification for testing)
        mock_def_context.return_value.wrap_socket.return_value = mock_ssl_sock
        
        with patch.object(SSLScanner, "_probe_tls_version", return_value=True):
            result = scanner.run()

    assert result.status == "completed"
    
    # 1024 bit key -> Weak RSA Key Length (HIGH)
    # MD5 signature -> Weak Signature Algorithm (HIGH)
    assert result.statistics["high"] >= 2
    
    key_findings = [f for f in result.findings if f.title == "Weak RSA Key Length"]
    sig_findings = [f for f in result.findings if f.title == "Weak Signature Algorithm"]
    
    assert len(key_findings) == 1
    assert len(sig_findings) == 1


def test_ssl_scanner_untrusted_chain(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = SSLScanner(tmp_path, "example.com", scope_manager)

    # Normal certificate but not self-signed. First connection fails verification.
    cert_bytes = generate_test_cert("example.com", "Untrusted Root CA")

    mock_sock = MagicMock()
    mock_ssl_sock = MockSSLSocket(cert_bytes, "TLSv1.3")

    with patch("socket.create_connection", return_value=mock_sock), \
         patch("ssl.create_default_context", side_effect=ssl.SSLCertVerificationError("Untrusted chain")), \
         patch("ssl.SSLContext") as mock_ssl_context_class:
        
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssl_sock
        mock_ssl_context_class.return_value = mock_ctx

        with patch.object(SSLScanner, "_probe_tls_version", return_value=True):
            result = scanner.run()

    assert result.status == "completed"
    assert result.statistics["high"] > 0
    chain_findings = [f for f in result.findings if f.title == "Certificate Chain Validation Failure"]
    assert len(chain_findings) == 1


def test_ssl_scanner_tls_version_findings(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = SSLScanner(tmp_path, "example.com", scope_manager)
    cert_bytes = generate_test_cert("example.com", "Trusted CA")

    # Mock probe tls version to support ALL versions (TLS 1.0, 1.1, 1.2, 1.3)
    mock_sock = MagicMock()
    mock_ssl_sock = MockSSLSocket(cert_bytes, "TLSv1.3")

    with patch("socket.create_connection", return_value=mock_sock), \
         patch("ssl.create_default_context") as mock_def_context:
        
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssl_sock
        mock_def_context.return_value = mock_ctx

        # Simulate all TLS versions are supported
        with patch.object(SSLScanner, "_probe_tls_version", return_value=True):
            result = scanner.run()

    assert result.status == "completed"
    
    # TLS 1.0 -> Weak TLS Version Enabled (HIGH)
    # TLS 1.1 -> Weak TLS Version Enabled (MEDIUM)
    assert result.statistics["high"] >= 1
    assert result.statistics["medium"] >= 1
    
    tls_findings = [f for f in result.findings if f.title == "Weak TLS Version Enabled"]
    assert len(tls_findings) == 2


def test_ssl_scanner_connection_failure(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = SSLScanner(tmp_path, "example.com", scope_manager)

    # Simulate connection error on all attempts
    with patch("socket.create_connection", side_effect=socket.error("Offline")):
        result = scanner.run()

    assert result.status == "failed"
    assert len(result.findings) == 0


def test_ssl_scanner_out_of_scope(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = SSLScanner(tmp_path, "google.com", scope_manager)

    with pytest.raises(OutOfScopeError):
        scanner.run()


def test_ssl_scanner_expiration_soon_severities(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    # We will test < 7 days, < 15 days, < 30 days expiration soon logic
    for days, expected_severity in [(5, "HIGH"), (12, "MEDIUM"), (25, "LOW")]:
        scanner = SSLScanner(tmp_path, "example.com", scope_manager)
        cert_bytes = generate_test_cert("example.com", "Trusted CA", days_valid=days)

        mock_sock = MagicMock()
        mock_ssl_sock = MockSSLSocket(cert_bytes, "TLSv1.3")

        with patch("socket.create_connection", return_value=mock_sock), \
             patch("ssl.create_default_context") as mock_def_context:
            
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value = mock_ssl_sock
            mock_def_context.return_value = mock_ctx

            with patch.object(SSLScanner, "_probe_tls_version", return_value=False):
                result = scanner.run()

        # Check for expiring soon finding
        expiring_soon = [f for f in result.findings if f.title == "Certificate Expiring Soon"]
        assert len(expiring_soon) == 1
        assert expiring_soon[0].severity == expected_severity


def generate_test_ecc_cert(
    subject_cn: str,
    issuer_cn: str,
) -> bytes:
    """Generate a mock DER-encoded ECC certificate for unit testing."""
    from cryptography.hazmat.primitives.asymmetric import ec
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    not_before = datetime.now(timezone.utc) - timedelta(days=1)
    not_after = not_before + timedelta(days=365)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(public_key)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)
    cert = builder.sign(private_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def test_ssl_scanner_sha1_signature(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = SSLScanner(tmp_path, "example.com", scope_manager)
    cert_bytes = generate_test_cert("example.com", "Trusted CA")

    # Proxy mock to override signature algorithm attributes
    real_cert = x509.load_der_x509_certificate(cert_bytes)
    mock_cert = MagicMock(wraps=real_cert)
    
    try:
        mock_cert.not_valid_after_utc = real_cert.not_valid_after_utc
        mock_cert.not_valid_before_utc = real_cert.not_valid_before_utc
    except AttributeError:
        pass
    mock_cert.not_valid_after = real_cert.not_valid_after
    mock_cert.not_valid_before = real_cert.not_valid_before
    mock_cert.issuer = real_cert.issuer
    mock_cert.subject = real_cert.subject
    mock_cert.public_key.return_value = real_cert.public_key()
    mock_cert.extensions = real_cert.extensions
    
    # Mock signature_hash_algorithm to return SHA1
    mock_cert.signature_hash_algorithm = hashes.SHA1()
    
    # Mock signature_algorithm_oid._name to be "sha1WithRSAEncryption"
    mock_oid = MagicMock()
    mock_oid._name = "sha1WithRSAEncryption"
    mock_cert.signature_algorithm_oid = mock_oid

    mock_sock = MagicMock()
    mock_ssl_sock = MockSSLSocket(cert_bytes, "TLSv1.3")

    with patch("socket.create_connection", return_value=mock_sock), \
         patch("ssl.create_default_context", return_value=MagicMock()) as mock_def_context, \
         patch("ssl.SSLContext") as mock_ssl_context_class, \
         patch("cryptography.x509.load_der_x509_certificate", return_value=mock_cert):
        
        mock_def_context.return_value.wrap_socket.return_value = mock_ssl_sock
        with patch.object(SSLScanner, "_probe_tls_version", return_value=True):
            result = scanner.run()

    assert result.status == "completed"
    assert result.statistics["medium"] >= 1
    sig_findings = [f for f in result.findings if f.title == "Weak Signature Algorithm"]
    assert len(sig_findings) == 1
    assert sig_findings[0].severity == "MEDIUM"


def test_ssl_scanner_ecc_key(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = SSLScanner(tmp_path, "example.com", scope_manager)
    cert_bytes = generate_test_ecc_cert("example.com", "Trusted CA")

    mock_sock = MagicMock()
    mock_ssl_sock = MockSSLSocket(cert_bytes, "TLSv1.3")

    with patch("socket.create_connection", return_value=mock_sock), \
         patch("ssl.create_default_context", return_value=MagicMock()) as mock_def_context, \
         patch("ssl.SSLContext") as mock_ssl_context_class:
        
        mock_def_context.return_value.wrap_socket.return_value = mock_ssl_sock
        with patch.object(SSLScanner, "_probe_tls_version", return_value=True):
            result = scanner.run()

    assert result.status == "completed"
    ecc_findings = [f for f in result.findings if f.title == "ECC Key Supported"]
    assert len(ecc_findings) == 1


def test_ssl_scanner_date_fallback(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = SSLScanner(tmp_path, "example.com", scope_manager)
    cert_bytes = generate_test_cert("example.com", "Trusted CA")

    real_cert = x509.load_der_x509_certificate(cert_bytes)
    mock_cert = MagicMock(wraps=real_cert)
    
    # Delete the utc attributes to force AttributeError
    if hasattr(mock_cert, "not_valid_after_utc"):
        del mock_cert.not_valid_after_utc
    if hasattr(mock_cert, "not_valid_before_utc"):
        del mock_cert.not_valid_before_utc
        
    # Mocking properties directly so accessing them raises AttributeError
    type(mock_cert).not_valid_after_utc = property(lambda self: getattr(self, "_raise_attr_err")())
    type(mock_cert).not_valid_before_utc = property(lambda self: getattr(self, "_raise_attr_err")())
    mock_cert._raise_attr_err = MagicMock(side_effect=AttributeError)

    mock_cert.not_valid_after = real_cert.not_valid_after
    mock_cert.not_valid_before = real_cert.not_valid_before
    mock_cert.issuer = real_cert.issuer
    mock_cert.subject = real_cert.subject
    mock_cert.public_key.return_value = real_cert.public_key()
    mock_cert.extensions = real_cert.extensions

    mock_sock = MagicMock()
    mock_ssl_sock = MockSSLSocket(cert_bytes, "TLSv1.3")

    with patch("socket.create_connection", return_value=mock_sock), \
         patch("ssl.create_default_context", return_value=MagicMock()) as mock_def_context, \
         patch("ssl.SSLContext") as mock_ssl_context_class, \
         patch("cryptography.x509.load_der_x509_certificate", return_value=mock_cert):
        
        mock_def_context.return_value.wrap_socket.return_value = mock_ssl_sock
        with patch.object(SSLScanner, "_probe_tls_version", return_value=True):
            result = scanner.run()

    assert result.status == "completed"


def test_ssl_scanner_no_common_name(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = SSLScanner(tmp_path, "example.com", scope_manager)
    
    # Generate cert without Common Name
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    not_before = datetime.now(timezone.utc) - timedelta(days=1)
    not_after = not_before + timedelta(days=365)
    
    # Blank subject/issuer CN
    subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "BR")])
    issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "BR")])
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject).issuer_name(issuer).public_key(public_key)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(not_before).not_valid_after(not_after)
    cert = builder.sign(private_key, hashes.SHA256())
    cert_bytes = cert.public_bytes(serialization.Encoding.DER)

    mock_sock = MagicMock()
    mock_ssl_sock = MockSSLSocket(cert_bytes, "TLSv1.3")

    with patch("socket.create_connection", return_value=mock_sock), \
         patch("ssl.create_default_context", return_value=MagicMock()) as mock_def_context, \
         patch("ssl.SSLContext") as mock_ssl_context_class:
        
        mock_def_context.return_value.wrap_socket.return_value = mock_ssl_sock
        with patch.object(SSLScanner, "_probe_tls_version", return_value=True):
            result = scanner.run()

    assert result.status == "completed"
    assert result.certificate_summary is not None
    assert "C=BR" in result.certificate_summary["issuer"]


def test_ssl_scanner_connection_formats(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    cert_bytes = generate_test_cert("example.com", "Trusted CA")
    mock_sock = MagicMock()
    mock_ssl_sock = MockSSLSocket(cert_bytes, "TLSv1.3")

    # Test targets: "http://:8443", "http://:abc", and raising error inside urlparse
    for target in ["http://:8443", "http://:abc"]:
        scanner = SSLScanner(tmp_path, target, scope_manager)
        with patch("socket.create_connection", return_value=mock_sock), \
             patch("ssl.create_default_context", return_value=MagicMock()) as mock_def_context:
            mock_def_context.return_value.wrap_socket.return_value = mock_ssl_sock
            with patch.object(SSLScanner, "_probe_tls_version", return_value=False):
                # We skip scope validation to test port parsing directly
                with patch.object(SSLScanner, "validate_scope"):
                    result = scanner.run()
                    assert result.status in ("completed", "failed")


def test_ssl_scanner_probe_tls_version_direct(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scanner = SSLScanner(tmp_path, "example.com", scope_manager)
    
    # Test connection success
    mock_sock = MagicMock()
    mock_ssl_sock = MockSSLSocket(b"", "TLSv1.3")
    with patch("socket.create_connection", return_value=mock_sock), \
         patch("ssl.SSLContext.wrap_socket", return_value=mock_ssl_sock):
        assert scanner._probe_tls_version("example.com", 443, ssl.TLSVersion.TLSv1_3) is True

    # Test connection exception
    with patch("socket.create_connection", side_effect=socket.error("Offline")):
        assert scanner._probe_tls_version("example.com", 443, ssl.TLSVersion.TLSv1_3) is False


def test_ssl_scanner_fetch_der_cert_getpeercert_none(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scanner = SSLScanner(tmp_path, "example.com", scope_manager)
    
    mock_sock = MagicMock()
    mock_ssl_sock = MagicMock()
    # Return None for getpeercert(binary_form=True)
    mock_ssl_sock.getpeercert.return_value = None
    mock_ssl_sock.__enter__.return_value = mock_ssl_sock

    with patch("socket.create_connection", return_value=mock_sock), \
         patch("ssl.create_default_context") as mock_def_context, \
         patch("ssl.SSLContext") as mock_ssl_context_class:
        
        mock_def_context.return_value.wrap_socket.return_value = mock_ssl_sock
        mock_ssl_context_class.return_value.wrap_socket.return_value = mock_ssl_sock
        
        with pytest.raises(ConnectionError):
            scanner._fetch_der_certificate("example.com", 443)
