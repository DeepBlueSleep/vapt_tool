from unittest.mock import AsyncMock

import pytest

from scanner.core.enrichment import CveEnricher, enrich_report, identify_libraries
from scanner.core.models import TargetReport
from platform.api.schemas import ScanCreate
from platform.api.queue import scan_config_from_payload


def test_banners_require_explicit_name_and_full_version():
    assert identify_libraries("/*! jQuery v3.4.1 | license */") == {("jquery", "3.4.1")}
    assert identify_libraries("/* Vue.js v2.6.14 */") == {("vue", "2.6.14")}
    assert not identify_libraries('var version="3.4.1"; jquery-3.4.1.min.js')
    assert not identify_libraries("/*! jQuery v3.4 */")


def test_advisory_opt_in_survives_deep_profile(tmp_path):
    for enabled in (False, True):
        payload = ScanCreate(url="https://example.test", profile="deep", enable_cve_enrichment=enabled)
        assert scan_config_from_payload(payload, tmp_path).enable_cve_enrichment is enabled


@pytest.mark.asyncio
async def test_pagination_withdrawn_records_cache_and_privacy():
    client = CveEnricher()
    calls = []

    async def query(session, payload):
        calls.append(dict(payload))
        if len(calls) == 1:
            return {"vulns": [{"id": "A"}, {"id": "W", "withdrawn": "2025-01-01"}],
                    "next_page_token": "next"}
        return {"vulns": [{"id": "A"}, {"id": "B"}]}

    client._query = query
    result = await client.lookup(None, "jquery", "3.4.1")
    assert [record["id"] for record in result] == ["A", "B"]
    assert await client.lookup(None, "jquery", "3.4.1") == result
    assert len(calls) == 2
    assert calls[0] == {"package": {"name": "jquery", "ecosystem": "npm"}, "version": "3.4.1"}
    assert calls[1]["page_token"] == "next"


@pytest.mark.asyncio
async def test_budget_fails_without_network():
    with pytest.raises(ValueError, match="limit"):
        await CveEnricher(budget=0).lookup(None, "jquery", "3.4.1")


@pytest.mark.asyncio
async def test_reporting_evidence_and_failures(monkeypatch):
    report = TargetReport(input_url="https://example.test", scanned_at_utc="")
    report.inventory["coverage"] = []
    libraries = {("jquery", "3.4.1"): {"https://example.test/jquery.js"}}
    monkeypatch.setattr(CveEnricher, "lookup", AsyncMock(return_value=[{"id": "GHSA-test"}]))
    await enrich_report(report, libraries)
    assert len(report.findings) == 1
    assert report.findings[0].metadata["exploitability_verified"] is False
    assert report.findings[0].url.endswith("/jquery.js")
    monkeypatch.setattr(CveEnricher, "lookup", AsyncMock(side_effect=ValueError("unavailable")))
    await enrich_report(report, libraries)
    assert "incomplete" in report.errors[0]
    assert report.metrics["dependency_versions_checked"] == 0
