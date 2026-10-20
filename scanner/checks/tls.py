from __future__ import annotations

import asyncio
import datetime as dt
import ssl
import urllib.parse
import warnings
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from scanner.checks.common import make_finding
from scanner.core.models import Classification, Confidence, Finding, FindingScope, Severity
from scanner.core.scope import Scope


@dataclass
class TlsObservation:
    findings: list[Finding] = field(default_factory=list)
    inventory: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    handshakes: int = 0


def certificate_findings(url: str, der: bytes, now: dt.datetime | None = None) -> tuple[list[Finding], list[str]]:
    certificate = x509.load_der_x509_certificate(der)
    now = now or dt.datetime.now(dt.UTC)
    findings: list[Finding] = []
    remaining = (certificate.not_valid_after_utc - now).total_seconds() / 86400
    inventory = [f"Certificate valid from: {certificate.not_valid_before_utc.isoformat()}",
                 f"Certificate expires: {certificate.not_valid_after_utc.isoformat()}",
                 f"Certificate issuer: {certificate.issuer.rfc4514_string()}"]

    def add(title: str, severity: Severity, evidence: str, remediation: str) -> None:
        findings.append(make_finding(check="transport.tls", url=url, title=title, severity=severity,
                                    classification=Classification.WEAKNESS, confidence=Confidence.HIGH,
                                    evidence=evidence, remediation=remediation, scope=FindingScope.HOST))

    if remaining <= 0:
        add("TLS certificate has expired", Severity.HIGH, f"Expired at {certificate.not_valid_after_utc.isoformat()}.",
            "Renew and deploy a valid certificate and its full chain.")
    elif remaining <= 30:
        add("TLS certificate expires within 30 days", Severity.LOW, f"Approximately {remaining:.1f} days remain.",
            "Verify automated renewal and monitor certificate expiry.")
    if certificate.not_valid_before_utc > now:
        add("TLS certificate is not yet valid", Severity.HIGH, f"Valid from {certificate.not_valid_before_utc.isoformat()}.",
            "Check system clocks and deploy a currently valid certificate.")
    key = certificate.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        inventory.append(f"Certificate public key: RSA {key.key_size} bits")
        if key.key_size < 2048:
            add("TLS certificate uses a weak RSA key", Severity.HIGH, f"RSA key size is {key.key_size} bits.",
                "Replace the certificate with an RSA key of at least 2048 bits or an appropriate elliptic-curve key.")
    elif isinstance(key, ec.EllipticCurvePublicKey):
        inventory.append(f"Certificate public key: {key.curve.name}")
        if key.key_size < 256:
            add("TLS certificate uses a weak elliptic-curve key", Severity.HIGH, f"Curve size is {key.key_size} bits.",
                "Replace the certificate with a supported modern elliptic-curve key.")
    try:
        algorithm = certificate.signature_hash_algorithm
    except UnsupportedAlgorithm:
        algorithm = None
        inventory.append("Certificate signature hash could not be identified by this scanner")
    if algorithm and algorithm.name.lower() in {"md5", "sha1"}:
        add("TLS certificate uses a weak signature hash", Severity.HIGH, f"Signature hash: {algorithm.name}.",
            "Reissue the certificate with a modern signature algorithm.")
    return findings, inventory


async def inspect_tls(url: str, scope: Scope, timeout: float = 5, legacy: bool = False) -> TlsObservation:
    observation = TlsObservation()
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not scope.is_allowed(url):
        return observation
    host = parsed.hostname
    try:
        port = parsed.port or 443
    except ValueError as exc:
        observation.errors.append(f"TLS inspection could not complete: {exc}")
        return observation
    timeout = max(1.0, min(timeout, 10.0))

    async def connect(context: ssl.SSLContext) -> tuple[bytes, str, str]:
        observation.handshakes += 1
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=host, ssl_handshake_timeout=timeout), timeout + 1,
        )
        try:
            transport = writer.get_extra_info("ssl_object")
            return transport.getpeercert(binary_form=True), transport.version(), str(transport.cipher())
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except (TimeoutError, OSError):
                pass

    def unverified() -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    try:
        try:
            der, version, cipher = await connect(ssl.create_default_context())
            observation.inventory.append("Certificate trust and hostname: verified using the scanner's trust store")
        except ssl.SSLCertVerificationError as exc:
            observation.findings.append(make_finding(
                check="transport.tls", url=url, title="TLS certificate validation failed", severity=Severity.HIGH,
                classification=Classification.WEAKNESS, confidence=Confidence.HIGH,
                evidence=f"Scanner trust store rejected the certificate: {exc.verify_message}.",
                remediation="Verify certificate validity, hostname coverage, and the served chain; account for private trust stores.",
                scope=FindingScope.HOST,
            ))
            der, version, cipher = await connect(unverified())
            observation.inventory.append("Certificate metadata inspected without trust verification after validation failed")
        observation.inventory.extend([f"Negotiated TLS: {version}", f"Negotiated cipher: {cipher}"])
        findings, inventory = certificate_findings(url, der)
        observation.findings.extend(findings)
        observation.inventory.extend(inventory)
    except (OSError, TimeoutError, ValueError) as exc:
        observation.errors.append(f"TLS inspection could not complete: {type(exc).__name__}: {exc}")
        return observation
    if legacy:
        for protocol in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            try:
                context = unverified()
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    context.minimum_version = protocol
                    context.maximum_version = protocol
                context.set_ciphers("DEFAULT:@SECLEVEL=0")
                _, version, _ = await connect(context)
                observation.findings.append(make_finding(
                    check="transport.tls", url=url, title="Server accepts a deprecated TLS protocol", severity=Severity.MEDIUM,
                    classification=Classification.WEAKNESS, confidence=Confidence.HIGH,
                    evidence=f"Successfully negotiated {version}.", remediation="Disable TLS 1.0 and TLS 1.1; use TLS 1.2 or TLS 1.3.",
                    scope=FindingScope.HOST, metadata={"protocol": version}, dedup_key=f"tls-legacy:{host}:{port}:{version}",
                ))
                observation.inventory.append(f"Legacy probe {protocol.name}: negotiated {version}")
            except (OSError, TimeoutError, ValueError):
                observation.inventory.append(f"Legacy probe {protocol.name}: not negotiated; client or server may disallow it")
    return observation
