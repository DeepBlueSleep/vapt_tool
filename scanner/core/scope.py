from __future__ import annotations

import urllib.parse

from scanner.core.config import ScopeConfig


class Scope:
    def __init__(self, config: ScopeConfig) -> None:
        self.config = config

    def is_allowed(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in self.config.allowed_schemes:
            return False
        if not host or host in self.config.deny_hosts:
            return False
        if not self.config.allowed_hosts:
            return True
        if host in self.config.allowed_hosts:
            return True
        if self.config.allow_subdomains:
            return any(host.endswith("." + allowed) for allowed in self.config.allowed_hosts)
        return False
