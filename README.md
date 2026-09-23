# eyetool

A CLI + microservice pair for ingesting security event CSVs, enriching each record via an
external enrichment service, and delivering the enriched records to an analytics platform.

## What it does

1. **CLI** (`eyetool readfile`) reads a CSV of security events, filters it by any combination
   of `asset_name`, `source`, `category`, and a `created_utc` date range (AND/OR combinable),
   and streams matching rows in batches to a local API.
2. **API** (`eyetool.api`, a FastAPI app) receives each batch on a single `POST /rows`
   endpoint. For every row it calls an external **Enrichment Service**, then forwards the
   enriched record to an external **Analytics Service**, respecting that service's documented
   rate limit (1 request/10s, max 20 items/request).
3. Progress streams back to the CLI live, row by row, rather than the CLI blocking silently
   until the whole batch finishes.

## Setup & usage

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip   # a fresh venv's bundled pip is often < 21.3, which
                             # can't do an editable install against a hatchling
                             # (no setup.py) backend — this avoids that failure
pip install -e .
```

```bash
# terminal 1: start the API (fails fast if EYETOOL_AUTH_HEADER isn't set)
source .venv/bin/activate
export EYETOOL_AUTH_HEADER=eye-am-hiring
python -m eyetool.api
# or with auto-reload during development:
uvicorn eyetool.api:app --reload
```

```bash
# terminal 2: run the CLI — a new shell, so the venv needs activating again
source .venv/bin/activate
eyetool readfile example_data_2.csv --source pxtrpf --category phising --filter-type and
```

`--category` matches the raw CSV text exactly (e.g. `phising`, as it's actually spelled in
`example_data_2.csv`) — normalization only happens server-side, against the enrichment
service's enum, not in the CLI's filter.

Filters: `--asset-name`, `--source`, `--category` (exact match), `--created-gt/-gte/-lt/-lte`
(accepts `YYYY-MM-DD` or `DD/MM/YYYY HH:MM`), `--filter-type and|or` (default `or`).

Env vars: `EYETOOL_AUTH_HEADER` (required, API only) — the `Authorization` header value for
the enrichment/analytics services. `EYETOOL_BATCH_SIZE` (default 100, CLI only) controls how
many CSV rows the CLI groups into one API call.

See Testing below for how to run the test suite.

## Architecture

Two separate processes, matching the brief's split of "a CLI application" and "a Microservice
API project": the CLI owns filtering/batching/user feedback, the API owns enrichment,
normalization, rate-limit compliance, and delivery. They talk over one endpoint (`POST
/rows`), which the CLI calls with a JSON array of raw CSV rows.

```
CSV file --filter--> CLI batches (EYETOOL_BATCH_SIZE) --HTTP--> API
                                                                   |
                                                     per row: enrich (retry on 5xx)
                                                                   |
                                                   per ≤20 rows: deliver to analytics
                                                        (rate-limited, 1 req/10s)
                                                                   |
                                              NDJSON progress events streamed back to CLI
```

### Why synchronous/blocking, not async or a message queue

The rate limiter (`_throttle_analytics` in `api.py`) is a single global timestamp with no
lock. That's only safe because there is exactly one caller today (the CLI, one request at a
time) — if `/rows` ever received concurrent requests, two threads could race past the check
before either updates the timestamp (FastAPI runs sync `def` handlers in a threadpool). I
considered three ways to close that gap and deliberately didn't build any of them for this
submission:

- **`asyncio.Queue`** with a single consumer task owning the rate limiter would make the
  throttle provably correct under concurrency, at the cost of rewriting the HTTP client layer
  as async and changing the request/response contract (the endpoint would need to return
  before delivery is confirmed, breaking the synchronous "here's exactly what happened"
  feedback the CLI currently gets).
- **A message broker** (e.g. RabbitMQ or Kafka) sitting between the stages — CLI → durable
  ingest queue → enrichment consumer(s) → durable enriched queue → a single analytics
  consumer, with the rate limiter living inside that one consumer — would give genuine
  horizontal scaling for enrichment, crash recovery (an in-flight message gets redelivered
  instead of lost if a consumer dies mid-processing), and replay. It's also new
  infrastructure and non-trivial delivery-semantics work of its own (at-least-once delivery
  means analytics writes need to be idempotent, keyed on `correlationId`, so a redelivered
  message doesn't get submitted twice; messages that repeatedly fail need a dead-letter
  path), and the brief explicitly says cloud infrastructure isn't expected — "if
  implementation details are necessary, state them in the README" is effectively an
  invitation to reason about this rather than build it.
- **Just don't fix it**, and say so here: today's actual concurrency is 1, so the bug is
  latent, not active. If this went to production behind more than one CLI/producer, this is
  the first thing I'd change — most likely a durable message broker along the lines above,
  since "mission-critical" ingestion that can't lose data under a crash is exactly the case
  for a persisted, replayable queue over an in-memory one.

### Why NDJSON streaming instead of a single JSON response

A single `/rows` call can cover hundreds of rows, and analytics delivery alone is
rate-limited to 1 request/10s — a 1000-row file could take several minutes. Returning one
JSON blob at the end would make the CLI look hung the entire time. `POST /rows` instead
returns a `StreamingResponse` of newline-delimited JSON events (`enriched`,
`enrichment_failed`, `delivered`, `delivery_failed`, then a final `done` summary); the CLI
reads it line-by-line via `urllib` (which supports this natively — no new HTTP client
dependency) and logs each event as it arrives.

### Why Pydantic models for the enrichment/analytics payloads

FastAPI already depends on Pydantic v2, so this added no new dependency. `EnrichmentRequest`,
`EnrichmentResponse`, `AnalyticsItem`, and `AnalyticsResponse` give two things a plain dict
didn't: local validation of outgoing data (blank `asset`, malformed `ip`, or an unrecognized
`category` now fail before a network call is even made — verified in tests that `_post_json`
is never invoked for these), and a specific error naming the exact field when the *external*
service returns something unexpected, instead of a bare `KeyError` surfacing deeper in the
call stack.

### Category normalization

`example_data_2.csv` spells `category` inconsistently — spacing, casing, hyphens/underscores,
and outright typos (`phising`, `valida_accounts`, `explaoit-public facing`). `normalize_category`
strips non-alphanumeric characters and lowercases first, which resolves most variants
automatically; a small `CATEGORY_ALIASES` table covers the handful of real typos and
reorderings that survive stripping. Rows whose category still doesn't resolve to one of the
10 documented enrichment categories fail fast, locally, with `CategoryError`.

## Error handling

Layered, so one bad row or one flaky service call doesn't take down a whole batch:

1. **Local validation** (Pydantic) — bad `id`/`asset`/`ip`/`category` rejected before any
   network call.
2. **Per-row isolation** — a row that fails enrichment (for any reason) is logged, counted,
   and skipped; the rest of the batch keeps processing.
3. **Retry with backoff, on both external calls** — the enrichment service is documented as
   intermittently flaky ("proceed with caution"); `enrich_row` retries up to 3 times with
   linear backoff on 5xx/429/connection errors, but not on other 4xx (a malformed request
   won't succeed by retrying it — verified against the real service's actual documented
   flakiness during development, logs showed live 500s recovering on retry). `send_to_analytics`
   retries the same way, but instead of a separate backoff timer it re-runs the rate limiter
   (`_throttle_analytics`) before every attempt — a retry is itself paced to the 1-req/10s
   limit rather than hammering straight back into the limit that likely caused the failure
   (verified: retries are spaced by the full interval, not fired back-to-back).
4. **Per-batch isolation for analytics** — once analytics retries are exhausted, a failed
   delivery marks that batch's rows as `delivery_failed` and processing moves on, rather than
   losing the whole request's results.
5. **Connection-level handling in the CLI** — if the API is unreachable entirely, or the
   NDJSON stream ends without a final `done` event, that batch is reported as failed and the
   CLI continues with the next one rather than crashing.

## Performance

Two deliberate levels of batching: the CLI groups CSV rows into API calls of
`EYETOOL_BATCH_SIZE` (configurable, default 100) instead of one HTTP call per row; the API
in turn chunks rows into groups of ≤20 for analytics, matching that service's documented
per-request item cap, instead of one analytics call per row (which the rate limit wouldn't
tolerate anyway — 1000 individual calls at 1/10s would take almost 3 hours instead of a few
minutes).

**What I'd add with more time:** enrichment calls are currently strictly sequential — a
1000-row file makes 1000 sequential blocking HTTP calls before any analytics chunk can even
start. Enrichment isn't documented as rate-limited, so bounding concurrency there (a small
thread pool, or the async rewrite discussed above) would be the next real lever.

## Observability

Both processes use Python's `logging` module (not `print`) with `INFO`/`WARNING`/`ERROR`
levels: `INFO` for normal progress (rows received, enriched, delivered, per-batch and final
summaries), `WARNING` for an isolated row failure that doesn't stop the run, `ERROR` for a
failed HTTP call (with the exact payload and response body attached) or a failed batch
delivery. The CLI logs to stderr so stdout stays script-friendly if piped elsewhere later.

**Correlation IDs:** the CLI generates a short id per batch (one `/rows` call), sends it as
an `X-Correlation-Id` header, and logs it on every line for that batch; the API reads that
header (or mints its own if the caller didn't send one) and logs it the same way, so one
batch's CLI-side and API-side log lines can be matched up directly instead of guessed at by
timestamp and row id.

**What's still missing, and what I'd add:** the logs are plain text, not structured (JSON) —
fine to read directly, but not queryable in a real log aggregator without one. I'd also add
basic counters (rows enriched/failed, analytics delivered/failed, retry counts) exposed as
Prometheus metrics — right now that data only exists as log lines and the final summary dict.

## Security

- **The `Authorization` credential is read from the `EYETOOL_AUTH_HEADER` environment
  variable**, not hardcoded — `api.py` fails fast at startup with a clear error if it isn't
  set, rather than silently sending an empty/`None` header. In a real system this would come
  from a secrets manager rather than a plain env var, but this at least keeps the credential
  out of source control.
- **`/rows` has no authentication or rate limiting of its own.** Per the brief, auth on our
  API is explicitly out of scope, but it's worth naming the consequence: anyone who can reach
  this endpoint can spend the shared enrichment/analytics credential arbitrarily. IAM-style
  thinking says this service account should be scoped to only what it needs (which it already
  is — two specific endpoints) and that `/rows` itself should sit behind network-level access
  control or its own credential in any real deployment.
- **No upper bound on payload size.** `receive_rows` accepts an arbitrary-length JSON array;
  a very large or malicious POST body could exhaust memory before any row-level validation
  runs. A max-batch-size check at the API boundary (independent of the CLI's own
  `EYETOOL_BATCH_SIZE`, which a malicious caller could simply ignore) would close this.
- **Input validation** (Pydantic models, IP format checking, category enum, non-blank asset)
  is the main defense against malformed or malicious row data reaching the external services.
  CSV formula/injection isn't a relevant risk here since nothing is ever rendered into a
  spreadsheet or shell.

## Testing

```bash
source .venv/bin/activate   # if this is a new shell
pip install pytest          # pip install -e . only installs runtime dependencies
pytest
```

- **Unit tests** (`tests/test_api.py`, `tests/test_client.py`, `tests/test_cli.py`) cover
  happy and unhappy paths: category normalization (including the real CSV's messy variants),
  Pydantic validation rejections, enrichment and analytics retry/backoff (both retry on 5xx
  and 429, skip other 4xx, give up after max attempts; analytics retries are additionally
  asserted to be paced by the rate limiter rather than fired back-to-back), analytics
  batch-size enforcement, per-row/per-batch failure isolation, filter AND/OR semantics, and
  streaming event parsing.
- **Integration test** (`tests/test_integration.py`) runs the real FastAPI app over a real
  local socket and drives it through the real client — the only thing mocked is the outbound
  call to `api.heyering.com` (`conftest.py`), so tests stay fast, deterministic, and don't
  spend the real service's rate limit just by running `pytest`. It also includes a regression
  test for a bug caught during review: a leftover local debug guard (`if count > 100: break`)
  that silently truncated any CSV over 100 rows — removed, with a 150-row test asserting
  every row gets processed.
- Not tested: the actual `api.heyering.com` integration itself (deliberately — that's a real
  third-party service, not something CI should depend on or hammer).

## Known gaps / what I'd improve with more time

- Enrichment calls are sequential, not concurrent — see Performance above.
- The rate limiter isn't safe under concurrent `/rows` requests — see Architecture above; a
  durable message broker (RabbitMQ or Kafka) is the direction I'd take this if it needed to
  scale beyond one caller.
- Logging is still plain text, not structured (JSON) — fine for one person reading it
  directly, but not for a real log aggregator/query tool. Correlation IDs are already in
  place (see Observability above); structuring the log lines themselves is the next step.
- No enforced max payload size on `/rows` — see Security above.
