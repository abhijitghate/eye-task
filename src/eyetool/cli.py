import argparse
import csv
import logging
import os
import urllib.error
import uuid
from datetime import datetime

from eyetool import __version__
from eyetool.client import StreamIncompleteError, send_batch

CSV_DELIMITER = ";"
CREATED_UTC_FORMAT = "%d/%m/%Y %H:%M"
DEFAULT_BATCH_SIZE = 100

logger = logging.getLogger(__name__)


def cmd_hello(args: argparse.Namespace) -> None:
    print("Hello from eyetool!")


def parse_created_utc(value: str) -> datetime:
    formats = (CREATED_UTC_FORMAT, "%Y-%m-%d %H:%M", "%Y-%m-%d")
    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(
        f"invalid datetime {value!r}, expected format like 'DD/MM/YYYY HH:MM' or 'YYYY-MM-DD'"
    )


def row_matches(row: dict, args: argparse.Namespace) -> bool:
    predicates = []

    if args.asset_name is not None:
        predicates.append(row["asset_name"] == args.asset_name)
    if args.source is not None:
        predicates.append(row["source"] == args.source)
    if args.category is not None:
        predicates.append(row["category"] == args.category)

    if any((args.created_gt, args.created_gte, args.created_lt, args.created_lte)):
        created = datetime.strptime(row["created_utc"], CREATED_UTC_FORMAT)
        if args.created_gt is not None:
            predicates.append(created > args.created_gt)
        if args.created_gte is not None:
            predicates.append(created >= args.created_gte)
        if args.created_lt is not None:
            predicates.append(created < args.created_lt)
        if args.created_lte is not None:
            predicates.append(created <= args.created_lte)

    if not predicates:
        return True

    combine = all if args.filter_type == "and" else any
    return combine(predicates)


def cmd_readfile(args: argparse.Namespace) -> None:
    batch_size = int(os.environ.get("EYETOOL_BATCH_SIZE", DEFAULT_BATCH_SIZE))
    batch: list[dict] = []

    stats = {
        "matched": 0,
        "sent": 0,
        "enriched": 0,
        "enrichment_failed": 0,
        "delivered": 0,
        "delivery_failed": 0,
        "batch_errors": 0,
    }

    def flush(batch: list[dict]) -> None:
        # One id per batch (not per CLI run): each batch is its own /rows
        # request, and this is what ties this batch's CLI-side logs to the
        # matching API-side logs for the same request.
        correlation_id = uuid.uuid4().hex[:8]

        def on_event(event: dict) -> None:
            kind = event.get("event")
            if kind == "enriched":
                logger.info("[%s] row id=%s enriched", correlation_id, event.get("id"))
            elif kind == "enrichment_failed":
                logger.warning(
                    "[%s] row id=%s failed enrichment: %s", correlation_id, event.get("id"), event.get("error")
                )
            elif kind == "delivered":
                logger.info("[%s] delivered %d row(s) to analytics", correlation_id, len(event.get("ids", [])))
            elif kind == "delivery_failed":
                logger.error(
                    "[%s] failed to deliver %d row(s) to analytics: %s",
                    correlation_id, len(event.get("ids", [])), event.get("error"),
                )

        try:
            response = send_batch(batch, on_event=on_event, correlation_id=correlation_id)
        except (urllib.error.URLError, OSError, StreamIncompleteError) as exc:
            stats["batch_errors"] += 1
            logger.error("[%s] failed to send batch of %d row(s) to API: %s", correlation_id, len(batch), exc)
            return

        stats["sent"] += response.get("received", len(batch))
        stats["enriched"] += response.get("enriched", 0)
        stats["enrichment_failed"] += response.get("enrichment_failed", 0)
        stats["delivered"] += response.get("delivered", 0)
        stats["delivery_failed"] += response.get("delivery_failed", 0)
        logger.info(
            "[%s] sent %d row(s): %d enriched (%d enrichment failed), "
            "%d delivered to analytics (%d delivery failed)",
            correlation_id,
            len(batch),
            response.get("enriched", 0),
            response.get("enrichment_failed", 0),
            response.get("delivered", 0),
            response.get("delivery_failed", 0),
        )

    with open(args.filename, newline="") as f:
        reader = csv.DictReader(f, delimiter=CSV_DELIMITER)
        for row in reader:
            if not row_matches(row, args):
                continue

            stats["matched"] += 1
            batch.append(row)

            if len(batch) >= batch_size:
                flush(batch)
                batch = []

    if batch:
        flush(batch)

    summary = (
        f"matched {stats['matched']} row(s); sent {stats['sent']} to the API "
        f"({stats['enriched']} enriched, {stats['enrichment_failed']} enrichment failed, "
        f"{stats['delivered']} delivered to analytics, {stats['delivery_failed']} delivery failed"
    )
    if stats["batch_errors"]:
        summary += f", {stats['batch_errors']} batch(es) failed to send"
    summary += ")"
    logger.info(summary)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="eyetool", description="eyetool command line interface.")
    parser.add_argument("--version", action="version", version=f"eyetool, version {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    hello_parser = subparsers.add_parser("hello", help="Print a greeting.")
    hello_parser.set_defaults(func=cmd_hello)

    readfile_parser = subparsers.add_parser("readfile", help="Read a CSV file and send filtered rows to the API.")
    readfile_parser.add_argument("filename", type=str, help="The path to the CSV file to read.")
    readfile_parser.add_argument("--asset-name", default=None, help="Keep rows with this exact asset_name.")
    readfile_parser.add_argument("--source", default=None, help="Keep rows with this exact source.")
    readfile_parser.add_argument("--category", default=None, help="Keep rows with this exact category.")
    readfile_parser.add_argument(
        "--created-gt", type=parse_created_utc, default=None, help="Keep rows where created_utc > this value."
    )
    readfile_parser.add_argument(
        "--created-gte", type=parse_created_utc, default=None, help="Keep rows where created_utc >= this value."
    )
    readfile_parser.add_argument(
        "--created-lt", type=parse_created_utc, default=None, help="Keep rows where created_utc < this value."
    )
    readfile_parser.add_argument(
        "--created-lte", type=parse_created_utc, default=None, help="Keep rows where created_utc <= this value."
    )
    readfile_parser.add_argument(
        "--filter-type",
        choices=["and", "or"],
        default="or",
        help="Combine the given filters with AND (all must match) or OR (any must match). Default: or.",
    )
    readfile_parser.set_defaults(func=cmd_readfile)

    return parser


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
