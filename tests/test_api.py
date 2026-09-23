import json
import urllib.error
from unittest import mock

import pytest
from pydantic import ValidationError

from eyetool import api


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Phising", api.EnrichmentCategory.PHISHING),
        ("phising", api.EnrichmentCategory.PHISHING),
        ("content injection", api.EnrichmentCategory.CONTENT_INJECTION),
        ("content_injection", api.EnrichmentCategory.CONTENT_INJECTION),
        ("drive-by-compromise", api.EnrichmentCategory.DRIVE_BY_COMPROMISE),
        ("compromise (driveby)", api.EnrichmentCategory.DRIVE_BY_COMPROMISE),
        ("valida_accounts", api.EnrichmentCategory.VALID_ACCOUNTS),
        ("valid-accounts", api.EnrichmentCategory.VALID_ACCOUNTS),
        ("external remote service", api.EnrichmentCategory.EXTERNAL_REMOTE_SERVICES),
        ("exploit public facing", api.EnrichmentCategory.EXPLOIT_PUBLIC_FACING_APPLICATION),
    ],
)
def test_normalize_category_handles_real_csv_variants(raw, expected):
    assert api.normalize_category(raw) == expected


def test_normalize_category_rejects_unknown_value():
    with pytest.raises(api.CategoryError):
        api.normalize_category("not a real category")


def test_build_enrichment_payload_happy_path():
    row = {"id": "402618", "asset_name": "server_spark", "ip": "8.245.154.104", "category": "phising"}
    payload = api.build_enrichment_payload(row)
    assert payload.id == 402618
    assert payload.asset == "server_spark"
    assert payload.category == api.EnrichmentCategory.PHISHING


@pytest.mark.parametrize(
    "row",
    [
        {"id": "1", "asset_name": "", "ip": "8.245.154.104", "category": "phishing"},
        {"id": "1", "asset_name": "   ", "ip": "8.245.154.104", "category": "phishing"},
        {"id": "1", "asset_name": "a", "ip": "not-an-ip", "category": "phishing"},
        {"id": "1", "asset_name": "a", "ip": "8.245.154.104", "category": "not a category"},
    ],
)
def test_build_enrichment_payload_rejects_bad_data(row):
    with pytest.raises((ValidationError, api.CategoryError)):
        api.build_enrichment_payload(row)


def test_build_enrichment_payload_rejects_non_numeric_id():
    row = {"id": "not-a-number", "asset_name": "a", "ip": "8.245.154.104", "category": "phishing"}
    with pytest.raises(ValueError):
        api.build_enrichment_payload(row)


def test_enrich_row_retries_on_500_then_succeeds():
    payload = api.EnrichmentRequest(id=1, asset="a", ip="1.2.3.4", category=api.EnrichmentCategory.PHISHING)
    attempts = {"n": 0}

    def flaky(url, payload, context, response_model):
        attempts["n"] += 1
        if attempts["n"] < 2:
            raise urllib.error.HTTPError(url, 500, "server error", {}, None)
        return response_model.model_validate({"asn": "ASN1", "category": "T1566", "correlationId": 1})

    with mock.patch.object(api, "_post_json", side_effect=flaky), mock.patch.object(api.time, "sleep"):
        result = api.enrich_row(payload, "test-corr")

    assert attempts["n"] == 2
    assert result.correlationId == 1


def test_enrich_row_does_not_retry_on_client_error():
    payload = api.EnrichmentRequest(id=1, asset="a", ip="1.2.3.4", category=api.EnrichmentCategory.PHISHING)
    attempts = {"n": 0}

    def bad_request(url, payload, context, response_model):
        attempts["n"] += 1
        raise urllib.error.HTTPError(url, 400, "invalid input", {}, None)

    with mock.patch.object(api, "_post_json", side_effect=bad_request), mock.patch.object(api.time, "sleep"):
        with pytest.raises(urllib.error.HTTPError):
            api.enrich_row(payload, "test-corr")

    assert attempts["n"] == 1


def test_enrich_row_gives_up_after_max_attempts():
    payload = api.EnrichmentRequest(id=1, asset="a", ip="1.2.3.4", category=api.EnrichmentCategory.PHISHING)

    def always_500(url, payload, context, response_model):
        raise urllib.error.HTTPError(url, 500, "server error", {}, None)

    with mock.patch.object(api, "_post_json", side_effect=always_500), mock.patch.object(api.time, "sleep"):
        with pytest.raises(urllib.error.HTTPError):
            api.enrich_row(payload, "test-corr")


def test_send_to_analytics_rejects_oversized_batch():
    items = [
        api.AnalyticsItem(
            id=i, asset="a", ip="1.2.3.4", category=api.AttackTechnique.T1566, asn="ASN1", correlationId=i
        )
        for i in range(api.ANALYTICS_MAX_ITEMS + 1)
    ]
    with pytest.raises(ValueError):
        api.send_to_analytics(items, "test-corr")


def _one_item():
    return [
        api.AnalyticsItem(id=1, asset="a", ip="1.2.3.4", category=api.AttackTechnique.T1566, asn="ASN1", correlationId=1)
    ]


def test_send_to_analytics_retries_on_500_then_succeeds(monkeypatch):
    monkeypatch.setattr(api, "_last_analytics_call", None)
    attempts = {"n": 0}

    def flaky(url, payload, context, response_model):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise urllib.error.HTTPError(url, 500, "server error", {}, None)
        return response_model.model_validate({"status": "ok", "itemsIngested": len(payload)})

    with mock.patch.object(api, "_post_json", side_effect=flaky), \
         mock.patch.object(api, "ANALYTICS_MIN_INTERVAL_SECONDS", 0):
        result = api.send_to_analytics(_one_item(), "test-corr")

    assert attempts["n"] == 3
    assert result.itemsIngested == 1


def test_send_to_analytics_retries_on_429(monkeypatch):
    monkeypatch.setattr(api, "_last_analytics_call", None)
    attempts = {"n": 0}

    def rate_limited(url, payload, context, response_model):
        attempts["n"] += 1
        if attempts["n"] < 2:
            raise urllib.error.HTTPError(url, 429, "rate limit", {}, None)
        return response_model.model_validate({"status": "ok", "itemsIngested": len(payload)})

    with mock.patch.object(api, "_post_json", side_effect=rate_limited), \
         mock.patch.object(api, "ANALYTICS_MIN_INTERVAL_SECONDS", 0):
        api.send_to_analytics(_one_item(), "test-corr")

    assert attempts["n"] == 2


def test_send_to_analytics_does_not_retry_on_client_error(monkeypatch):
    monkeypatch.setattr(api, "_last_analytics_call", None)
    attempts = {"n": 0}

    def bad_request(url, payload, context, response_model):
        attempts["n"] += 1
        raise urllib.error.HTTPError(url, 400, "invalid input", {}, None)

    with mock.patch.object(api, "_post_json", side_effect=bad_request), \
         mock.patch.object(api, "ANALYTICS_MIN_INTERVAL_SECONDS", 0):
        with pytest.raises(urllib.error.HTTPError):
            api.send_to_analytics(_one_item(), "test-corr")

    assert attempts["n"] == 1


def test_send_to_analytics_gives_up_after_max_attempts(monkeypatch):
    monkeypatch.setattr(api, "_last_analytics_call", None)
    attempts = {"n": 0}

    def always_500(url, payload, context, response_model):
        attempts["n"] += 1
        raise urllib.error.HTTPError(url, 500, "server error", {}, None)

    with mock.patch.object(api, "_post_json", side_effect=always_500), \
         mock.patch.object(api, "ANALYTICS_MIN_INTERVAL_SECONDS", 0):
        with pytest.raises(urllib.error.HTTPError):
            api.send_to_analytics(_one_item(), "test-corr")

    assert attempts["n"] == api.ANALYTICS_MAX_ATTEMPTS


def test_send_to_analytics_retries_are_paced_by_the_rate_limiter(monkeypatch):
    monkeypatch.setattr(api, "_last_analytics_call", None)
    call_times = []

    def flaky(url, payload, context, response_model):
        call_times.append(api.time.monotonic())
        if len(call_times) < 3:
            raise urllib.error.HTTPError(url, 500, "server error", {}, None)
        return response_model.model_validate({"status": "ok", "itemsIngested": len(payload)})

    with mock.patch.object(api, "_post_json", side_effect=flaky), \
         mock.patch.object(api, "ANALYTICS_MIN_INTERVAL_SECONDS", 0.2):
        api.send_to_analytics(_one_item(), "test-corr")

    gaps = [b - a for a, b in zip(call_times, call_times[1:])]
    assert all(gap >= 0.18 for gap in gaps)  # each retry waited for the rate limit, not fired back-to-back


def _fake_post_json(url, payload, context, response_model):
    if url == api.ENRICHMENT_URL:
        return response_model.model_validate({"asn": "ASN1", "category": "T1566", "correlationId": payload.id})
    if url == api.ANALYTICS_URL:
        return response_model.model_validate({"status": "ok", "itemsIngested": len(payload)})
    raise AssertionError(f"unexpected url: {url}")


def test_process_rows_excludes_bad_rows_from_analytics():
    rows = [
        {"id": "1", "asset_name": "good", "ip": "1.2.3.4", "category": "valid accounts"},
        {"id": "not-a-number", "asset_name": "a", "ip": "1.2.3.4", "category": "valid accounts"},
        {"id": "3", "asset_name": "", "ip": "1.2.3.4", "category": "valid accounts"},
        {"id": "4", "asset_name": "good2", "ip": "1.2.3.4", "category": "phising"},
    ]

    with mock.patch.object(api, "_post_json", side_effect=_fake_post_json):
        events = [json.loads(line) for line in api._process_rows(rows, "test-corr")]

    done = events[-1]
    assert done == {"event": "done", "received": 4, "enriched": 2, "enrichment_failed": 2, "delivered": 2, "delivery_failed": 0}

    delivered = next(e for e in events if e["event"] == "delivered")
    assert delivered["ids"] == [1, 4]


def test_process_rows_isolates_a_failing_analytics_batch():
    def enrichment_ok_analytics_fails(url, payload, context, response_model):
        if url == api.ENRICHMENT_URL:
            return response_model.model_validate({"asn": "ASN1", "category": "T1566", "correlationId": payload.id})
        raise urllib.error.HTTPError(url, 500, "server error", {}, None)

    rows = [{"id": str(i), "asset_name": f"a{i}", "ip": "1.2.3.4", "category": "valid accounts"} for i in range(1, 4)]

    # Analytics now retries on 5xx, paced by the rate limiter itself; shorten
    # that interval so this test doesn't spend 20+ real seconds on retries.
    with mock.patch.object(api, "_post_json", side_effect=enrichment_ok_analytics_fails), \
         mock.patch.object(api, "ANALYTICS_MIN_INTERVAL_SECONDS", 0):
        api._last_analytics_call = None
        events = [json.loads(line) for line in api._process_rows(rows, "test-corr")]

    done = events[-1]
    assert done["enriched"] == 3
    assert done["delivered"] == 0
    assert done["delivery_failed"] == 3
