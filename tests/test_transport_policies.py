import asyncio
import datetime as dt
import ipaddress
import ssl
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from scanner.checks.passive import CookieCheck, HeaderCheck
from scanner.checks.policies import script_policy_risks
from scanner.checks.tls import certificate_findings, inspect_tls
from scanner.core.config import ScanConfig, ScopeConfig
from scanner.core.models import Page, TargetReport
from scanner.core.orchestrator import Scanner
from scanner.core.scope import Scope
from scanner.risk.posture import score_posture
from scanner.browser.playwright_analyzer import PlaywrightAnalyzer
from tests.test_deep_scan import serve
from aiohttp import web
from scanner.cli import async_main
from scanner.reporting.vapt import build_vapt_report, vapt_json_payload


@pytest.mark.parametrize("policy", [
    "default-src 'self'; img-src *; script-src 'self'",
    "script-src 'unsafe-inline' 'nonce-YWJjZGVmZ2hpamtsbW5vcA=='",
    "script-src https: 'nonce-YWJjZGVmZ2hpamtsbW5vcA==' 'strict-dynamic'",
    "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'",
])
def test_csp_does_not_mistake_unrelated_sources_for_script_risk(policy):
    assert script_policy_risks([policy]) == []


def test_csp_intersection_fallback_and_directive_overrides():
    assert script_policy_risks(["default-src *"])
    assert script_policy_risks(["script-src 'unsafe-inline' *", "default-src 'none'"]) == []
    risks = script_policy_risks(["script-src 'none'; script-src-attr 'unsafe-inline'"])
    assert risks == ["unrestricted inline handlers"]


@pytest.mark.asyncio
async def test_cookie_values_do_not_satisfy_flags_or_leak_into_evidence():
    page = Page("https://example.test", "https://example.test", 200,
                {"set-cookie": ["session=secure-httponly-samesite-secret; Path=/"]}, b"")
    findings = await CookieCheck().analyze(page, None)
    assert len(findings) == 1
    assert "secure, httponly, samesite" in findings[0].evidence
    assert "secure-httponly-samesite-secret" not in findings[0].evidence


@pytest.mark.asyncio
async def test_cookie_prefix_and_samesite_rules():
    page = Page("https://example.test", "https://example.test", 200, {"set-cookie": [
        "__Host-session=x; Domain=example.test; Path=/app; HttpOnly; SameSite=None",
        "deleted=; Max-Age=0",
        "good=x; Secure; HttpOnly; SameSite=Lax; Path=/",
    ]}, b"")
    findings = await CookieCheck().analyze(page, None)
    invalid = next(item for item in findings if "incompatible" in item.title)
    assert "SameSite=None requires Secure" in invalid.evidence
    assert "__Host- prefix" in invalid.evidence
    assert all("deleted" not in finding.evidence and "good" not in finding.evidence for finding in findings)


@pytest.mark.asyncio
async def test_hsts_presence_is_not_enough_and_frame_fallback_is_respected():
    page = Page("https://example.test", "https://example.test", 200, {
        "strict-transport-security": ["max-age=0"],
        "content-security-policy": ["default-src 'self'"], "x-frame-options": ["DENY"],
        "x-content-type-options": ["wrong"],
    }, b"")
    findings = await HeaderCheck().analyze(page, None)
    titles = {item.title for item in findings}
    assert "HSTS policy is disabled or invalid" in titles
    assert "X-Content-Type-Options has an invalid value" in titles
    assert "CSP is missing frame-ancestors" not in titles


def make_certificate(days: int, bits: int = 2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=2))
                   .not_valid_after(now + dt.timedelta(days=days))
                   .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                   .sign(key, hashes.SHA256()))
    return key, certificate


@pytest.mark.parametrize("days,expected", [(-1, "TLS certificate has expired"), (7, "TLS certificate expires within 30 days"), (90, None)])
def test_certificate_expiry_thresholds(days, expected):
    _, certificate = make_certificate(days)
    findings, inventory = certificate_findings("https://example.test", certificate.public_bytes(serialization.Encoding.DER))
    assert inventory
    assert (expected in {item.title for item in findings}) if expected else not findings


def test_certificate_weak_key_detection():
    _, certificate = make_certificate(90, bits=1024)
    findings, _ = certificate_findings("https://example.test", certificate.public_bytes(serialization.Encoding.DER))
    assert any(item.title == "TLS certificate uses a weak RSA key" for item in findings)


@pytest.mark.asyncio
async def test_real_tls_handshake_rejects_untrusted_certificate_and_collects_metadata(tmp_path: Path):
    key, certificate = make_certificate(7)
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    async def accept(reader, writer):
        try:
            await reader.read(1)
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(accept, "127.0.0.1", 0, ssl=context)
    async with server:
        port = server.sockets[0].getsockname()[1]
        observation = await inspect_tls(f"https://127.0.0.1:{port}", Scope(ScopeConfig(allowed_hosts=frozenset({"127.0.0.1"}))), timeout=2)
    assert observation.handshakes == 2
    assert not observation.errors
    titles = {item.title for item in observation.findings}
    assert "TLS certificate validation failed" in titles
    assert "TLS certificate expires within 30 days" in titles
    assert any("Negotiated TLS:" in item for item in observation.inventory)


@pytest.mark.asyncio
async def test_tls_out_of_scope_does_not_connect():
    observation = await inspect_tls("https://outside.test", Scope(ScopeConfig(allowed_hosts=frozenset({"example.test"}))))
    assert observation.handshakes == 0 and not observation.findings


@pytest.mark.asyncio
async def test_legacy_tls_reports_only_successful_negotiation(monkeypatch):
    _, certificate = make_certificate(90)
    der = certificate.public_bytes(serialization.Encoding.DER)

    class TlsSession:
        def __init__(self, version):
            self.negotiated = version

        def getpeercert(self, binary_form=False):
            return der

        def version(self):
            return self.negotiated

        def cipher(self):
            return ("TEST", "TLSv1.2", 256)

    class Writer:
        def __init__(self, version):
            self.session = TlsSession(version)

        def get_extra_info(self, name):
            return self.session

        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def connect(*args, **kwargs):
        context = kwargs["ssl"]
        if context.maximum_version == ssl.TLSVersion.TLSv1_1:
            raise ssl.SSLError("Client or server refuses handshake")
        return None, Writer("TLSv1" if context.maximum_version == ssl.TLSVersion.TLSv1 else "TLSv1.3")

    monkeypatch.setattr(asyncio, "open_connection", connect)
    observation = await inspect_tls("https://example.test", Scope(ScopeConfig()), legacy=True)
    legacy = [finding for finding in observation.findings if "deprecated TLS" in finding.title]
    assert len(legacy) == 1 and legacy[0].metadata["protocol"] == "TLSv1"
    assert any("not negotiated" in item for item in observation.inventory)
    assert observation.handshakes == 3


@pytest.mark.asyncio
async def test_rendered_browser_forms_and_unique_screenshot_evidence(tmp_path: Path):
    playwright = pytest.importorskip("playwright.async_api")
    async with playwright.async_playwright() as runtime:
        if not Path(runtime.chromium.executable_path).exists():
            pytest.skip("Chromium is not installed")

    async def handler(request):
        return web.Response(text='''<html><body><script>
            const form = document.createElement('form');
            form.action = '/login'; form.method = 'POST';
            const input = document.createElement('input'); input.type = 'password'; input.name = 'password';
            form.appendChild(input); document.body.appendChild(form);
            </script></body></html>''', content_type="text/html")

    async with serve(handler) as url:
        config = ScanConfig(out_dir=tmp_path, capture_screenshots=True)
        scanner = Scanner(config)
        report = TargetReport(input_url=url)
        first = await scanner._run_browser(url + "/one", report, config)
        second = await PlaywrightAnalyzer(screenshot_dir=tmp_path, capture_screenshots=True).analyze(url + "/two")
    assert first and first.rendered_html
    assert first.screenshot_path != second.screenshot_path
    assert Path(first.screenshot_path).exists() and Path(second.screenshot_path).exists()
    assert any("Password form" in finding.title for finding in report.findings)
    assert report.inventory["dynamic_forms"]


@pytest.mark.asyncio
async def test_discovered_pages_are_recursively_analyzed_and_report_depth_limits():
    async def handler(request):
        pages = {"/": '<script src="/app.js"></script>', "/hidden": '<a href="/child">Child</a>', "/child": '<a href="/grandchild">More</a>'}
        if request.path in pages:
            return web.Response(text=pages[request.path], content_type="text/html")
        if request.path == "/app.js":
            return web.Response(text="fetch('/hidden')", content_type="application/javascript")
        return web.Response(status=404)

    async with serve(handler) as url:
        report = (await Scanner(ScanConfig(max_depth=0, rate_limit_per_second=0, enable_attack_surface_expansion=False)).scan([url]))[0]
        assert url + "/child" in report.inventory["pages"]
        assert report.coverage_status == "completed"
        failed = (await Scanner(ScanConfig(max_requests=1, rate_limit_per_second=0)).scan([url]))[0]
        assert failed.coverage_status == "failed"
        assert score_posture(failed).grade == "n/a"


def test_partial_report_posture_does_not_claim_complete_assessment():
    report = TargetReport(input_url="https://example.test", coverage_status="partial", pages_crawled=1)
    assert score_posture(report).summary.startswith("Partial assessment")


@pytest.mark.asyncio
async def test_failed_cli_assessment_has_nonzero_exit_and_structured_coverage(monkeypatch, tmp_path: Path):
    failed = TargetReport(input_url="https://example.test", coverage_status="failed", errors=["No pages analyzed"])
    failed.inventory["coverage_gaps"] = ["Request limit reached"]

    class FailedScanner:
        def __init__(self, config):
            pass

        async def scan(self, urls):
            return [failed]

    monkeypatch.setattr("scanner.cli.Scanner", FailedScanner)
    result = await async_main(["https://example.test", "--out-dir", str(tmp_path)])
    assert result == 2
    payload = vapt_json_payload(build_vapt_report([failed]), include_internal=True)
    assert payload["assessments"][0]["coverage_status"] == "failed"
    assert payload["assessments"][0]["coverage_gaps"] == ["Request limit reached"]
    assert "No application security posture was established" in payload["executive_summary"]
