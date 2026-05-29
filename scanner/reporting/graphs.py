from __future__ import annotations

import hashlib
import html

from scanner.core.models import TargetReport


def mermaid_attack_surface(report: TargetReport) -> str:
    lines = ["flowchart LR"]
    root = _node_id(report.input_url)
    lines.append(f'  {root}["{_label(report.input_url)}"]')
    for page in report.inventory.get("pages", [])[:30]:
        page_id = _node_id("page:" + page)
        lines.append(f'  {page_id}["Page: {_label(page)}"]')
        lines.append(f"  {root} --> {page_id}")
    for api in (report.inventory.get("runtime_apis", []) + report.inventory.get("endpoints", []))[:40]:
        api_id = _node_id("api:" + api)
        lines.append(f'  {api_id}["API: {_label(api)}"]')
        lines.append(f"  {root} --> {api_id}")
    for form in (report.inventory.get("forms", []) + report.inventory.get("dynamic_forms", []))[:20]:
        form_id = _node_id("form:" + form)
        lines.append(f'  {form_id}["Form: {_label(form)}"]')
        lines.append(f"  {root} --> {form_id}")
    return "\n".join(lines)


def svg_placeholder(report: TargetReport) -> str:
    label = html.escape(report.input_url)
    return (
        "<svg xmlns='http://www.w3.org/2000/svg' width='900' height='120' role='img'>"
        "<rect width='900' height='120' fill='#f8fafc' stroke='#cbd5e1'/>"
        f"<text x='24' y='40' font-family='Arial' font-size='18' fill='#172033'>{label}</text>"
        f"<text x='24' y='76' font-family='Arial' font-size='14' fill='#536174'>"
        f"Pages {len(report.inventory.get('pages', []))} | APIs {len(report.inventory.get('runtime_apis', []))} | "
        f"Forms {len(report.inventory.get('forms', []))}</text></svg>"
    )


def _node_id(value: str) -> str:
    return "n" + hashlib.sha1(value.encode("utf-8", "ignore")).hexdigest()[:10]


def _label(value: str) -> str:
    return value.replace('"', "'")[:80]
