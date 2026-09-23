from eyetool.client import send_batch


def test_full_flow_cli_to_api_streaming(api_server):
    """End-to-end: real HTTP request from the client to the real FastAPI app
    over a real socket, streaming NDJSON progress back, with only the
    outbound calls to api.heyering.com mocked (see conftest.api_server)."""
    rows = [
        {"id": str(i), "asset_name": f"asset{i}", "ip": "1.2.3.4", "category": "phishing"}
        for i in range(1, 26)  # 25 rows: exercises the >20-item analytics chunking
    ]

    events = []
    result = send_batch(rows, url=api_server, on_event=events.append)

    assert result["received"] == 25
    assert result["enriched"] == 25
    assert result["delivered"] == 25
    assert result["enrichment_failed"] == 0
    assert result["delivery_failed"] == 0

    delivered_events = [e for e in events if e["event"] == "delivered"]
    assert len(delivered_events) == 2  # chunked into a 20-item batch and a 5-item batch
    delivered_ids = sorted(id_ for e in delivered_events for id_ in e["ids"])
    assert delivered_ids == list(range(1, 26))


def test_full_flow_handles_bad_rows_without_losing_the_good_ones(api_server):
    rows = [
        {"id": "1", "asset_name": "good", "ip": "1.2.3.4", "category": "phishing"},
        {"id": "not-a-number", "asset_name": "bad", "ip": "1.2.3.4", "category": "phishing"},
        {"id": "3", "asset_name": "", "ip": "1.2.3.4", "category": "phishing"},
    ]

    result = send_batch(rows, url=api_server)

    assert result["received"] == 3
    assert result["enriched"] == 1
    assert result["enrichment_failed"] == 2
    assert result["delivered"] == 1
