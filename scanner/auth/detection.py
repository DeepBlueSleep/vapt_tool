from __future__ import annotations

from dataclasses import dataclass

from scanner.core.models import Form, Page


@dataclass(frozen=True)
class AuthSignal:
    url: str
    kind: str
    confidence: float
    evidence: str


def detect_auth_signals(page: Page) -> tuple[AuthSignal, ...]:
    signals: list[AuthSignal] = []
    lower_url = page.final_url.lower()
    if any(token in lower_url for token in ("login", "signin", "account", "session", "auth")):
        signals.append(AuthSignal(url=page.final_url, kind="auth_route", confidence=0.75, evidence="Auth keyword in URL."))
    for form in page.forms:
        signals.extend(_signals_from_form(page.final_url, form))
    if page.status in {401, 403}:
        signals.append(AuthSignal(url=page.final_url, kind="auth_required", confidence=0.9, evidence=f"HTTP {page.status}."))
    return tuple(signals)


def _signals_from_form(source_url: str, form: Form) -> list[AuthSignal]:
    signals = []
    names = {name.lower() for name in form.inputs}
    if form.has_password:
        signals.append(AuthSignal(url=form.action or source_url, kind="login_form", confidence=0.95, evidence="Password input present."))
    if any("csrf" in name or "token" in name for name in names | {name.lower() for name in form.hidden_inputs}):
        signals.append(
            AuthSignal(url=form.action or source_url, kind="csrf_token", confidence=0.85, evidence="Token-like form field present.")
        )
    return signals
