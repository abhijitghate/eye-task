import argparse
import sys
from datetime import datetime

import pytest

from eyetool import cli
from eyetool.cli import main, parse_created_utc, row_matches


def test_hello(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["eyetool", "hello"])
    main()
    captured = capsys.readouterr()
    assert "Hello from eyetool!" in captured.out


def _filter_args(**overrides):
    defaults = dict(
        asset_name=None,
        source=None,
        category=None,
        created_gt=None,
        created_gte=None,
        created_lt=None,
        created_lte=None,
        filter_type="or",
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def test_row_matches_with_no_filters_matches_everything():
    row = {"asset_name": "a", "source": "s", "category": "c", "created_utc": "01/01/2024 00:00"}
    assert row_matches(row, _filter_args()) is True


def test_row_matches_or_semantics():
    row = {"asset_name": "a", "source": "wrong", "category": "c", "created_utc": "01/01/2024 00:00"}
    args = _filter_args(asset_name="a", source="also-wrong", filter_type="or")
    assert row_matches(row, args) is True


def test_row_matches_and_semantics():
    row = {"asset_name": "a", "source": "wrong", "category": "c", "created_utc": "01/01/2024 00:00"}
    args = _filter_args(asset_name="a", source="also-wrong", filter_type="and")
    assert row_matches(row, args) is False


def test_row_matches_created_utc_range():
    row = {"asset_name": "a", "source": "s", "category": "c", "created_utc": "15/06/2024 00:00"}
    args = _filter_args(
        created_gte=datetime(2024, 1, 1), created_lt=datetime(2024, 12, 31), filter_type="and"
    )
    assert row_matches(row, args) is True


def test_parse_created_utc_accepts_multiple_formats():
    assert parse_created_utc("2024-06-01") == datetime(2024, 6, 1)
    assert parse_created_utc("01/06/2024 12:30") == datetime(2024, 6, 1, 12, 30)


def test_parse_created_utc_rejects_garbage():
    with pytest.raises(argparse.ArgumentTypeError):
        parse_created_utc("not-a-date")


def _readfile_args(filename, **overrides):
    return argparse.Namespace(filename=filename, **_filter_args(**overrides).__dict__)


def test_cmd_readfile_reports_batch_stats(tmp_path, monkeypatch, caplog):
    csv_file = tmp_path / "data.csv"
    csv_file.write_text(
        "id;asset_name;ip;created_utc;source;category\n"
        "1;a1;1.1.1.1;01/01/2024 00:00;src;phishing\n"
        "2;a2;1.1.1.2;01/01/2024 00:00;src;phishing\n"
    )

    def fake_send_batch(batch, on_event=None, correlation_id=None):
        return {
            "received": len(batch),
            "enriched": len(batch),
            "enrichment_failed": 0,
            "delivered": len(batch),
            "delivery_failed": 0,
        }

    monkeypatch.setattr(cli, "send_batch", fake_send_batch)

    with caplog.at_level("INFO"):
        cli.cmd_readfile(_readfile_args(str(csv_file)))

    assert "matched 2 row(s); sent 2 to the API (2 enriched" in caplog.text


def test_cmd_readfile_processes_every_row_no_silent_truncation(tmp_path, monkeypatch):
    """Regression test: cmd_readfile used to silently stop after the first 100
    rows read (leftover local debug code), which would drop the tail of any
    real-sized CSV without any error or warning."""
    header = "id;asset_name;ip;created_utc;source;category\n"
    body = "\n".join(f"{i};asset{i};1.1.1.1;01/01/2024 00:00;src;phishing" for i in range(1, 151))
    csv_file = tmp_path / "data.csv"
    csv_file.write_text(header + body + "\n")

    sent_batch_sizes = []

    def fake_send_batch(batch, on_event=None, correlation_id=None):
        sent_batch_sizes.append(len(batch))
        return {
            "received": len(batch),
            "enriched": len(batch),
            "enrichment_failed": 0,
            "delivered": len(batch),
            "delivery_failed": 0,
        }

    monkeypatch.setattr(cli, "send_batch", fake_send_batch)
    monkeypatch.setenv("EYETOOL_BATCH_SIZE", "50")

    cli.cmd_readfile(_readfile_args(str(csv_file)))

    assert sum(sent_batch_sizes) == 150


def test_cmd_readfile_survives_a_batch_send_failure(tmp_path, monkeypatch, caplog):
    csv_file = tmp_path / "data.csv"
    csv_file.write_text(
        "id;asset_name;ip;created_utc;source;category\n"
        "1;a1;1.1.1.1;01/01/2024 00:00;src;phishing\n"
    )

    def failing_send_batch(batch, on_event=None, correlation_id=None):
        raise OSError("connection refused")

    monkeypatch.setattr(cli, "send_batch", failing_send_batch)

    with caplog.at_level("INFO"):
        cli.cmd_readfile(_readfile_args(str(csv_file)))

    assert "1 batch(es) failed to send" in caplog.text
