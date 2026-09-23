import json
from unittest import mock

import pytest

from eyetool.client import StreamIncompleteError, send_batch


class FakeResponse:
    def __init__(self, lines):
        self._lines = lines

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def __iter__(self):
        return iter(self._lines)


def _ndjson(*events):
    return [(json.dumps(e) + "\n").encode() for e in events]


def test_send_batch_streams_events_and_returns_done_summary():
    lines = _ndjson(
        {"event": "enriched", "id": 1},
        {"event": "delivered", "ids": [1]},
        {"event": "done", "received": 1, "enriched": 1, "enrichment_failed": 0, "delivered": 1, "delivery_failed": 0},
    )
    seen = []

    with mock.patch("eyetool.client.urllib.request.urlopen", return_value=FakeResponse(lines)):
        result = send_batch([{"id": "1"}], on_event=seen.append)

    assert result["enriched"] == 1
    assert [e["event"] for e in seen] == ["enriched", "delivered", "done"]


def test_send_batch_raises_if_stream_ends_without_done():
    lines = _ndjson({"event": "enriched", "id": 1})

    with mock.patch("eyetool.client.urllib.request.urlopen", return_value=FakeResponse(lines)):
        with pytest.raises(StreamIncompleteError):
            send_batch([{"id": "1"}])
