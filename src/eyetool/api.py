import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
import uuid
from enum import Enum
from typing import Annotated, Optional

from fastapi import FastAPI, Header
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, IPvAnyAddress, StringConstraints

from eyetool import __version__

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="eyetool API")

ENRICHMENT_URL = "https://api.heyering.com/enrichment"
ANALYTICS_URL = "https://api.heyering.com/analytics"
REQUEST_TIMEOUT_SECONDS = 10

# No hardcoded fallback on purpose: a credential baked into source is exactly
# the thing this env var exists to avoid.
AUTH_HEADER = os.environ.get("EYETOOL_AUTH_HEADER")
if not AUTH_HEADER:
    raise RuntimeError(
        "EYETOOL_AUTH_HEADER environment variable is not set. Set it to the "
        "Authorization header value for the enrichment/analytics services."
    )

# https://api.heyering.com/ca6b7066/docs#/paths/~1analytics/post
ANALYTICS_MAX_ITEMS = 20
ANALYTICS_MIN_INTERVAL_SECONDS = 10
ANALYTICS_MAX_ATTEMPTS = 3

ENRICHMENT_MAX_ATTEMPTS = 3
ENRICHMENT_RETRY_BACKOFF_SECONDS = 1

# Enrichment request `category` values, per the API docs
# (https://api.heyering.com/ca6b7066/docs#/paths/~1enrichment/post).
class EnrichmentCategory(str, Enum):
    CONTENT_INJECTION = "contentinjection"
    DRIVE_BY_COMPROMISE = "drivebycompromise"
    EXPLOIT_PUBLIC_FACING_APPLICATION = "exploitpublicfacingapplication"
    EXTERNAL_REMOTE_SERVICES = "externalremoteservices"
    HARDWARE_ADDITIONS = "hardwareadditions"
    PHISHING = "phishing"
    REPLICATION_THROUGH_REMOVABLE_MEDIA = "replicationthroughremovablemedia"
    SUPPLY_CHAIN_COMPROMISE = "supplychaincompromise"
    TRUSTED_RELATIONSHIP = "trustedrelationship"
    VALID_ACCOUNTS = "validaccounts"


# MITRE ATT&CK technique IDs used by both the enrichment response and the
# analytics request `category` field, per the API docs
# (https://api.heyering.com/ca6b7066/docs#/paths/~1analytics/post) — a
# different vocabulary from EnrichmentCategory, not the same field re-used.
class AttackTechnique(str, Enum):
    T1659 = "T1659"
    T1189 = "T1189"
    T1190 = "T1190"
    T1133 = "T1133"
    T1200 = "T1200"
    T1566 = "T1566"
    T1091 = "T1091"
    T1195 = "T1195"
    T1199 = "T1199"
    T1078 = "T1078"


# Reject blank/whitespace-only asset names and malformed IPs locally, before
# ever calling the (real, network) enrichment service with bad data.
AssetName = Annotated[str, StringConstraints(min_length=1, strip_whitespace=True)]


class EnrichmentRequest(BaseModel):
    id: int
    asset: AssetName
    ip: IPvAnyAddress
    category: EnrichmentCategory


class EnrichmentResponse(BaseModel):
    asn: str
    category: AttackTechnique
    correlationId: int


class AnalyticsItem(BaseModel):
    id: int
    asset: AssetName
    ip: IPvAnyAddress
    category: AttackTechnique
    asn: str
    correlationId: int


class AnalyticsResponse(BaseModel):
    status: str
    itemsIngested: int


# example_data_2.csv spells some categories inconsistently (spacing/casing/
# punctuation) or has outright typos ("phising", "valida_accounts") that
# don't reduce to a valid category after stripping punctuation alone.
CATEGORY_ALIASES = {
    "phising": "phishing",
    "compromisedriveby": "drivebycompromise",
    "explaoitpublicfacing": "exploitpublicfacingapplication",
    "exploitpublicfacing": "exploitpublicfacingapplication",
    "externalremoteservice": "externalremoteservices",
    "validaaccounts": "validaccounts",
}


class CategoryError(ValueError):
    pass


def normalize_category(raw: str) -> EnrichmentCategory:
    normalized = re.sub(r"[^a-z0-9]", "", raw.lower())
    normalized = CATEGORY_ALIASES.get(normalized, normalized)
    try:
        return EnrichmentCategory(normalized)
    except ValueError:
        raise CategoryError(f"unrecognized category: {raw!r}") from None


def build_enrichment_payload(row: dict) -> EnrichmentRequest:
    return EnrichmentRequest(
        id=int(row["id"]),
        asset=row["asset_name"],
        ip=row["ip"],
        category=normalize_category(row["category"]),
    )


def build_analytics_item(row: dict, enrichment_response: EnrichmentResponse) -> AnalyticsItem:
    return AnalyticsItem(
        id=int(row["id"]),
        asset=row["asset_name"],
        ip=row["ip"],
        category=enrichment_response.category,
        asn=enrichment_response.asn,
        correlationId=enrichment_response.correlationId,
    )


def _post_json(url: str, payload, *, context: str, response_model: type[BaseModel]) -> BaseModel:
    if isinstance(payload, list):
        body = [item.model_dump(mode="json") for item in payload]
    else:
        body = payload.model_dump(mode="json")
    data = json.dumps(body).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": AUTH_HEADER,
            "User-Agent": f"eyetool/{__version__}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return response_model.model_validate_json(response.read())
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        logger.error(
            "%s: HTTP %s from %s\n  payload: %s\n  response: %s",
            context, exc.code, url, data.decode("utf-8"), error_body,
        )
        raise
    except OSError as exc:
        logger.error("%s: request to %s failed: %s\n  payload: %s", context, url, exc, data.decode("utf-8"))
        raise


def _is_retryable_http_error(exc: urllib.error.HTTPError) -> bool:
    # 5xx: the service's problem, worth retrying. 429: told explicitly to slow
    # down and retry. Any other 4xx is a bad request on our side — retrying an
    # identical payload will never succeed, so fail immediately instead.
    return exc.code >= 500 or exc.code == 429


def enrich_row(payload: EnrichmentRequest, correlation_id: str) -> EnrichmentResponse:
    last_error: Optional[Exception] = None
    for attempt in range(1, ENRICHMENT_MAX_ATTEMPTS + 1):
        try:
            return _post_json(
                ENRICHMENT_URL,
                payload,
                context=f"[{correlation_id}] enrich_row attempt {attempt}/{ENRICHMENT_MAX_ATTEMPTS}",
                response_model=EnrichmentResponse,
            )
        except urllib.error.HTTPError as exc:
            if not _is_retryable_http_error(exc):
                raise
            last_error = exc
        except OSError as exc:
            last_error = exc

        if attempt < ENRICHMENT_MAX_ATTEMPTS:
            time.sleep(ENRICHMENT_RETRY_BACKOFF_SECONDS * attempt)

    raise last_error


_last_analytics_call: Optional[float] = None


def _throttle_analytics() -> None:
    global _last_analytics_call
    now = time.monotonic()
    if _last_analytics_call is not None:
        wait = ANALYTICS_MIN_INTERVAL_SECONDS - (now - _last_analytics_call)
        if wait > 0:
            time.sleep(wait)
    _last_analytics_call = time.monotonic()


def send_to_analytics(items: list[AnalyticsItem], correlation_id: str) -> AnalyticsResponse:
    if len(items) > ANALYTICS_MAX_ITEMS:
        raise ValueError(f"analytics batch too large: {len(items)} > {ANALYTICS_MAX_ITEMS}")

    last_error: Optional[Exception] = None
    for attempt in range(1, ANALYTICS_MAX_ATTEMPTS + 1):
        # Re-throttling before every attempt (not just the first) means a retry
        # is itself paced to the 1-req/10s limit instead of hammering straight
        # back into the same rate limit that likely caused the failure.
        _throttle_analytics()
        try:
            return _post_json(
                ANALYTICS_URL,
                items,
                context=f"[{correlation_id}] send_to_analytics attempt {attempt}/{ANALYTICS_MAX_ATTEMPTS}",
                response_model=AnalyticsResponse,
            )
        except urllib.error.HTTPError as exc:
            if not _is_retryable_http_error(exc):
                raise
            last_error = exc
        except OSError as exc:
            last_error = exc

    raise last_error


def _process_rows(payload: list[dict], correlation_id: str):
    """Yields one NDJSON line per enrichment/delivery outcome, then a final 'done' summary.

    A single /rows call can cover hundreds of rows, and analytics delivery alone is
    rate-limited to 1 request/10s, so processing can take minutes. Streaming events as
    they happen (rather than returning one response at the end) lets the CLI show live
    progress instead of appearing to hang.
    """
    stats = {"enriched": 0, "enrichment_failed": 0, "delivered": 0, "delivery_failed": 0}
    analytics_batch: list[AnalyticsItem] = []

    def emit(event: dict) -> bytes:
        return (json.dumps(event) + "\n").encode("utf-8")

    def flush_analytics(batch: list[AnalyticsItem]) -> bytes:
        ids = [item.id for item in batch]
        try:
            send_to_analytics(batch, correlation_id)
            stats["delivered"] += len(batch)
            return emit({"event": "delivered", "ids": ids})
        except Exception as exc:
            stats["delivery_failed"] += len(batch)
            logger.error("[%s] failed to deliver batch of %d row(s) to analytics: %s", correlation_id, len(batch), exc)
            return emit({"event": "delivery_failed", "ids": ids, "error": str(exc)})

    for row in payload:
        try:
            enrichment_response = enrich_row(build_enrichment_payload(row), correlation_id)
            analytics_batch.append(build_analytics_item(row, enrichment_response))
            stats["enriched"] += 1
            yield emit({"event": "enriched", "id": row.get("id")})
        except Exception as exc:
            stats["enrichment_failed"] += 1
            logger.warning("[%s] failed to enrich row id=%s: %s", correlation_id, row.get("id"), exc)
            yield emit({"event": "enrichment_failed", "id": row.get("id"), "error": str(exc)})
            continue

        if len(analytics_batch) >= ANALYTICS_MAX_ITEMS:
            yield flush_analytics(analytics_batch)
            analytics_batch = []

    if analytics_batch:
        yield flush_analytics(analytics_batch)

    logger.info(
        "[%s] processed %d row(s): %d enriched (%d enrichment failed), %d delivered (%d delivery failed)",
        correlation_id, len(payload), stats["enriched"], stats["enrichment_failed"], stats["delivered"], stats["delivery_failed"],
    )

    yield emit({"event": "done", "received": len(payload), **stats})


@app.post("/rows")
def receive_rows(payload: list[dict], x_correlation_id: Optional[str] = Header(None)) -> StreamingResponse:
    # Honor a correlation id the CLI already generated (so its logs and ours
    # can be matched up for the same batch); otherwise mint one so a request
    # from any other caller is still traceable through our own logs.
    correlation_id = x_correlation_id or uuid.uuid4().hex[:8]
    logger.info("[%s] received %d row(s)", correlation_id, len(payload))
    return StreamingResponse(_process_rows(payload, correlation_id), media_type="application/x-ndjson")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
