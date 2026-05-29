from __future__ import annotations

from dataclasses import dataclass

from scanner.core.models import Finding, TargetReport


@dataclass(frozen=True)
class ComplianceMapping:
    finding_id: str
    finding_title: str
    owasp: tuple[str, ...]
    asvs: tuple[str, ...]
    cwe: tuple[str, ...]
    capec: tuple[str, ...]
    pci_dss: tuple[str, ...]
    soc2: tuple[str, ...]
    iso27001: tuple[str, ...]


def map_finding(finding: Finding) -> ComplianceMapping:
    title = finding.title.lower()
    owasp = []
    asvs = []
    cwe = []
    capec = []
    pci = []
    soc2 = []
    iso = []
    if "cookie" in title or "session" in title:
        owasp.append("A07:2021 Identification and Authentication Failures")
        asvs.append("V3 Session Management")
        cwe.append("CWE-614")
        pci.append("PCI DSS 6.2.4")
    if "content security policy" in title or "reflected" in title:
        owasp.append("A03:2021 Injection")
        asvs.append("V5 Validation, Sanitization and Encoding")
        cwe.append("CWE-79")
        capec.append("CAPEC-63")
    if "strict transport security" in title or "https" in title:
        owasp.append("A02:2021 Cryptographic Failures")
        asvs.append("V9 Communications")
        cwe.append("CWE-319")
        pci.append("PCI DSS 4.2.1")
    if "debug" in title or "diagnostic" in title:
        owasp.append("A05:2021 Security Misconfiguration")
        asvs.append("V14 Configuration")
        cwe.append("CWE-209")
    if "graphql" in title or "api" in finding.url.lower():
        owasp.append("A01:2021 Broken Access Control")
        asvs.append("V4 Access Control")
        cwe.append("CWE-284")
    soc2.append("CC6.6 Logical Access")
    iso.append("A.8.8 Management of technical vulnerabilities")
    return ComplianceMapping(
        finding_id=finding.id,
        finding_title=finding.title,
        owasp=tuple(sorted(set(owasp)) or ("Review required",)),
        asvs=tuple(sorted(set(asvs)) or ("Review required",)),
        cwe=tuple(sorted(set(cwe)) or ("Review required",)),
        capec=tuple(sorted(set(capec)) or ("Review required",)),
        pci_dss=tuple(sorted(set(pci)) or ("Applicability review",)),
        soc2=tuple(sorted(set(soc2))),
        iso27001=tuple(sorted(set(iso))),
    )


def compliance_summary(reports: list[TargetReport]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for report in reports:
        for finding in report.findings:
            mapping = map_finding(finding)
            for item in (*mapping.owasp, *mapping.asvs, *mapping.cwe):
                counts[item] = counts.get(item, 0) + 1
    return dict(sorted(counts.items()))
