"""Unit tests for package/bin/tiingo_client.py (no Splunk, no network).

A fake session records every request and answers from a script, so the tests
see exactly what went over the wire, not what the client says it sent.
"""
from __future__ import annotations

import calendar
import os
import sys
import time

import pytest
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "package", "bin"))
import tiingo_client as tc  # noqa: E402

KEY = "unit-key-9d2f1b"


class Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.headers = {}

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class Session:
    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append({"url": url, "params": dict(params or {}), "headers": dict(headers or {}), "timeout": timeout})
        a = self.answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a


def client(*answers):
    s = Session(*answers)
    return tc.Client(KEY, base="https://t.example", session=s, sleep=lambda _: None), s


def utc(day, hour=0):
    return calendar.timegm(time.strptime(day, "%Y-%m-%d")) + hour * 3600


def test_key_in_header_only():
    c, s = client(Resp(200, []))
    tc.collect_iex(c, ["aapl"], {})
    call = s.calls[0]
    assert call["headers"]["Authorization"] == "Token " + KEY
    assert KEY not in call["url"] and KEY not in str(call["params"])
    assert call["timeout"]


def test_429_not_retried():
    c, s = client(Resp(429, {"detail": "Error: You have run over your hourly request allocation."}))
    with pytest.raises(tc.TiingoRateLimited) as e:
        c.get("/iex/")
    assert len(s.calls) == 1 and e.value.status == 429 and "allocation" in e.value.detail


def test_503_then_200_is_retried():
    c, s = client(Resp(503, {}), Resp(200, [{"ticker": "x"}]))
    assert c.get("/iex/") == [{"ticker": "x"}]
    assert len(s.calls) == 2


def test_persistent_500_gives_up_after_retries():
    c, s = client(*[Resp(500, {"detail": "boom"})] * 4)
    with pytest.raises(tc.TiingoError) as e:
        c.get("/iex/")
    assert len(s.calls) == 4 and e.value.status == 500


def test_bad_key_is_an_auth_error():
    c, _ = client(Resp(403, {"detail": "Invalid token."}))
    with pytest.raises(tc.TiingoAuthError) as e:
        c.get("/iex/")
    assert e.value.detail == "Invalid token."


def test_error_object_on_200_is_not_data():
    c, _ = client(Resp(200, {"detail": "Error: something"}))
    with pytest.raises(tc.TiingoError):
        c.get("/iex/")


def test_network_error_message_has_no_url_or_key():
    exc = requests.ConnectionError("HTTPSConnectionPool: Max retries exceeded with url: /iex/?token=" + KEY)
    c, _ = client(exc, exc, exc, exc)
    with pytest.raises(tc.TiingoError) as e:
        c.get("/iex/")
    assert KEY not in str(e.value) and "token" not in str(e.value) and "ConnectionError" in str(e.value)


def test_parse_ts_variants():
    assert tc.parse_ts("2026-11-24") == utc("2026-11-24")
    assert tc.parse_ts("2026-11-24T00:00:00.000Z") == utc("2026-11-24")
    assert tc.parse_ts("2026-11-25T13:51:36.511718381-05:00") == pytest.approx(utc("2026-11-25", 18) + 51 * 60 + 36.511718)
    assert tc.parse_ts("2026-11-25T18:51:37.007000+00:00") == pytest.approx(utc("2026-11-25", 18) + 51 * 60 + 37.007)


def test_quotes_only_newer_than_checkpoint():
    rows = [{"ticker": "AAPL", "timestamp": "2026-11-25T13:00:00-05:00"},
            {"ticker": "MSFT", "timestamp": "2026-11-25T13:00:00-05:00"}]
    c, _ = client(Resp(200, rows))
    events, state = tc.collect_iex(c, ["aapl", "msft"], {"aapl": utc("2026-11-25", 18)})
    assert [e[1]["ticker"] for e in events] == ["MSFT"]
    assert state == {"aapl": utc("2026-11-25", 18), "msft": utc("2026-11-25", 18)}


def test_eod_first_run_takes_latest_day_only():
    c, s = client(Resp(200, [{"ticker": "aapl", "date": "2026-11-24", "close": 1.0}]))
    events, state = tc.collect_eod(c, ["aapl"], {})
    assert [(e[0], e[1]["date"]) for e in events] == [(utc("2026-11-24"), "2026-11-24")]
    assert state == {"aapl": "2026-11-24"} and len(s.calls) == 1


def test_eod_fills_a_gap_from_the_range_endpoint():
    batch = Resp(200, [{"ticker": "aapl", "date": "2026-11-24", "close": 4.0}])
    gap = Resp(200, [{"date": "2026-11-20T00:00:00.000Z", "close": 2.0}, {"date": "2026-11-23T00:00:00.000Z", "close": 3.0}])
    c, s = client(batch, gap)
    events, state = tc.collect_eod(c, ["aapl"], {"aapl": "2026-11-19"})
    assert [(e[1]["date"], e[1]["close"]) for e in events] == [("2026-11-20", 2.0), ("2026-11-23", 3.0), ("2026-11-24", 4.0)]
    assert s.calls[1]["url"].endswith("/tiingo/daily/aapl/prices")
    assert s.calls[1]["params"] == {"startDate": "2026-11-20", "endDate": "2026-11-23"}
    assert state == {"aapl": "2026-11-24"}


def test_eod_no_gap_request_over_a_weekend():
    c, s = client(Resp(200, [{"ticker": "aapl", "date": "2026-11-23", "close": 1.0}]))
    events, _ = tc.collect_eod(c, ["aapl"], {"aapl": "2026-11-20"})  # Friday -> Monday
    assert len(events) == 1 and len(s.calls) == 1


def test_eod_same_day_again_is_skipped():
    c, _ = client(Resp(200, [{"ticker": "aapl", "date": "2026-11-24", "close": 1.0}]))
    events, state = tc.collect_eod(c, ["aapl"], {"aapl": "2026-11-24"})
    assert events == [] and state == {"aapl": "2026-11-24"}


def _bar(day, hour, close):
    return {"date": "{}T{:02d}:00:00+00:00".format(day, hour), "close": close}


def test_crypto_skips_the_bar_in_progress():
    now = utc("2026-11-25", 3) + 600  # 03:10 UTC
    doc = [{"ticker": "btcusd", "baseCurrency": "btc", "quoteCurrency": "usd",
            "priceData": [_bar("2026-11-25", h, h) for h in range(4)]}]
    c, s = client(Resp(200, doc))
    events, state = tc.collect_crypto(c, ["btcusd"], {}, now=now)
    assert [e[1]["date"][11:13] for e in events] == ["00", "01", "02"]
    assert state == {"btcusd": utc("2026-11-25", 2)}
    assert "startDate" not in s.calls[0]["params"]


def test_crypto_resumes_from_the_checkpoint_day():
    now = utc("2026-11-25", 1) + 60
    doc = [{"ticker": "btcusd", "baseCurrency": "btc", "quoteCurrency": "usd",
            "priceData": [_bar("2026-11-24", 22, 1), _bar("2026-11-24", 23, 2), _bar("2026-11-25", 0, 3), _bar("2026-11-25", 1, 4)]}]
    c, s = client(Resp(200, doc))
    events, _ = tc.collect_crypto(c, ["btcusd"], {"btcusd": utc("2026-11-24", 22)}, now=now)
    assert s.calls[0]["params"]["startDate"] == "2026-11-24"
    assert [e[1]["close"] for e in events] == [2, 3]


def test_split_tickers():
    assert tc.split_tickers(" AAPL, msft,,aapl ") == ["aapl", "msft"]


def test_checkpoint_roundtrip(tmp_path):
    cp = tc.FileCheckpoint(str(tmp_path / "sub"), "tiingo_fx_current", "a/b")
    assert cp.load() == {}
    cp.save({"eurusd": 1.5})
    assert tc.FileCheckpoint(str(tmp_path / "sub"), "tiingo_fx_current", "a/b").load() == {"eurusd": 1.5}
    assert "/" not in os.path.basename(cp.path)
