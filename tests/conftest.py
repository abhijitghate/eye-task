import os
import threading
import time
from unittest import mock

import pytest
import uvicorn

# Must be set before eyetool.api is imported anywhere in the test session —
# it reads this at import time and refuses to start without it.
os.environ.setdefault("EYETOOL_AUTH_HEADER", "test-auth-header")

from eyetool import api  # noqa: E402

TEST_PORT = 8765
TEST_ROWS_URL = f"http://127.0.0.1:{TEST_PORT}/rows"


def fake_post_json(url, payload, context, response_model):
    """Stands in for the real api.heyering.com calls: fast, deterministic, and
    doesn't spend the real service's rate limit just by running the test suite."""
    if url == api.ENRICHMENT_URL:
        return response_model.model_validate(
            {"asn": "ASN1337", "category": "T1566", "correlationId": payload.id + 1000}
        )
    if url == api.ANALYTICS_URL:
        return response_model.model_validate({"status": "ok", "itemsIngested": len(payload)})
    raise AssertionError(f"unexpected url: {url}")


@pytest.fixture
def api_server():
    """Runs the real eyetool API app over a real local socket, with outbound
    calls to api.heyering.com mocked and the analytics rate-limit interval
    shortened so the test suite doesn't spend minutes waiting on it."""
    with mock.patch.object(api, "_post_json", side_effect=fake_post_json), \
         mock.patch.object(api, "ANALYTICS_MIN_INTERVAL_SECONDS", 0.1):
        config = uvicorn.Config(api.app, host="127.0.0.1", port=TEST_PORT, log_level="warning")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()

        deadline = time.monotonic() + 5
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)

        yield TEST_ROWS_URL

        server.should_exit = True
        thread.join(timeout=5)
