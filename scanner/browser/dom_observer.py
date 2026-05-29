from __future__ import annotations

from dataclasses import dataclass, field

from scanner.core.models import Form

DOM_OBSERVER_SCRIPT = """
() => {
  window.__scannerDomEvents = window.__scannerDomEvents || [];
  const collect = (source) => {
    const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href).slice(0, 500);
    const forms = Array.from(document.querySelectorAll('form')).map(f => ({
      action: f.action || location.href,
      method: (f.method || 'GET').toUpperCase(),
      inputs: Array.from(f.querySelectorAll('input, textarea, select')).map(i => i.name).filter(Boolean).slice(0, 100)
    })).slice(0, 100);
    window.__scannerDomEvents.push({source, url: location.href, links, forms, at: Date.now()});
  };
  collect('initial');
  const observer = new MutationObserver(() => collect('mutation'));
  observer.observe(document.documentElement, {childList: true, subtree: true, attributes: true});
}
"""


DOM_COLLECTION_SCRIPT = "() => (window.__scannerDomEvents || []).slice(-50)"


@dataclass(frozen=True)
class DomMutationObservation:
    source_url: str
    links: tuple[str, ...] = ()
    forms: tuple[Form, ...] = ()
    source: str = "mutation"
    metadata: dict[str, str] = field(default_factory=dict)


def parse_dom_observations(raw_events: object) -> tuple[DomMutationObservation, ...]:
    if not isinstance(raw_events, list):
        return ()
    observations: list[DomMutationObservation] = []
    for raw in raw_events:
        if not isinstance(raw, dict):
            continue
        forms = []
        for raw_form in raw.get("forms", []):
            if not isinstance(raw_form, dict):
                continue
            inputs = tuple(str(item) for item in raw_form.get("inputs", []) if item)
            forms.append(
                Form(
                    action=str(raw_form.get("action") or raw.get("url") or ""),
                    method=str(raw_form.get("method") or "GET").lower(),
                    has_password=False,
                    inputs=inputs,
                )
            )
        links = tuple(str(item) for item in raw.get("links", []) if item)
        observations.append(
            DomMutationObservation(
                source_url=str(raw.get("url") or ""),
                links=links,
                forms=tuple(forms),
                source=str(raw.get("source") or "mutation"),
            )
        )
    return tuple(observations)
