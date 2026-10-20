from __future__ import annotations

import re


def parse_csp(policy: str) -> dict[str, tuple[str, ...]]:
    directives: dict[str, tuple[str, ...]] = {}
    for part in policy.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), tuple(tokens[1:]))
    return directives


def script_policy_risks(policies: list[str]) -> list[str]:
    """Evaluate effective script directives and intersect separately enforced policies."""
    combined: set[str] | None = None
    for header in policies:
        for policy in header.split(","):
            directives = parse_csp(policy)
            base = directives.get("script-src", directives.get("default-src"))
            elements = directives.get("script-src-elem", base)
            attributes = directives.get("script-src-attr", base)
            risks: set[str] = set()

            def trusted(tokens: tuple[str, ...] | None) -> bool:
                return bool(tokens and any(re.fullmatch(r"'(?:nonce|sha256|sha384|sha512)-[A-Za-z0-9+/=_-]+'", item) for item in tokens))

            for label, tokens in (("unrestricted inline script elements", elements), ("unrestricted inline handlers", attributes)):
                if tokens is None or ("'unsafe-inline'" in tokens and not trusted(tokens)):
                    risks.add(label)
            if base is None or "'unsafe-eval'" in base:
                risks.add("string-to-code evaluation")
            if elements is None or (
                not ("'strict-dynamic'" in elements and trusted(elements))
                and any(item in {"*", "data:", "http:", "https:"} or "*" in item for item in elements)
            ):
                risks.add("broad script source allowlist")
            combined = risks if combined is None else combined & risks
    return sorted(combined or [])
