import json
import urllib.request
import uuid
from typing import Callable, Optional

DEFAULT_ROWS_URL = "http://127.0.0.1:8000/rows"


class StreamIncompleteError(RuntimeError):
    pass


def send_batch(
    rows: list[dict],
    url: str = DEFAULT_ROWS_URL,
    on_event: Optional[Callable[[dict], None]] = None,
    correlation_id: Optional[str] = None,
) -> dict:
    """POSTs rows and reads the NDJSON response as it streams in, line by line.

    Calls on_event(event) for every line as it arrives (enrichment/delivery outcomes),
    so a caller can show live progress instead of blocking silently until the whole
    batch finishes. Returns the final 'done' summary event.

    correlation_id is sent as X-Correlation-Id so this batch's logs on the API
    side can be matched up with the caller's own logs for the same request; if
    not given, one is generated (the caller won't see it, so pass one in if
    you need to log it yourself).
    """
    correlation_id = correlation_id or uuid.uuid4().hex[:8]
    data = json.dumps(rows).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "X-Correlation-Id": correlation_id},
        method="POST",
    )
    summary: Optional[dict] = None
    with urllib.request.urlopen(request) as response:
        for line in response:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            if on_event is not None:
                on_event(event)
            if event.get("event") == "done":
                summary = event

    if summary is None:
        raise StreamIncompleteError(f"response from {url} ended without a final 'done' event")
    return summary
