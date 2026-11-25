"""Tiingo inputs end to end on real Splunk against the synthetic mock.

Covers what the live suite cannot provoke on demand: 429, 5xx, a rejected key,
unknown symbols, a stopped input catching up, frozen quotes and the crypto bar
still in progress. Expected values are computed here from the mock's own
formulas (docker/mock/mock_tiingo.py), never from anything the add-on wrote.

Splunk runs in Asia/Kolkata (+05:30) in this harness, so a timestamp parsed in
local time instead of UTC shows up as a wrong _time.
"""
from __future__ import annotations

import collections
import json
import os
import sys
import time
import urllib.parse
import urllib.request

import pytest

import tiingo_e2e as te

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "docker", "mock"))
import mock_tiingo as mock  # noqa: E402

_host = urllib.parse.urlparse(os.environ.get("SPLUNK_MGMT_URL", "https://127.0.0.1:8089")).hostname
pytestmark = pytest.mark.skipif(
    _host not in ("127.0.0.1", "localhost", "::1") or os.environ.get("TIINGO_MOCK") != "1",
    reason="needs the docker harness with the mock Tiingo upstream (TIINGO_MOCK=1)",
)

MOCK_URL = os.environ.get("TIINGO_MOCK_URL", "http://127.0.0.1:8081")
EOD, IEX, FX, CRYPTO = "tiingo_stock_endofday", "tiingo_iex_current", "tiingo_fx_current", "tiingo_crypto_endofday"
BAD_KEY = "mock-bad-key-0000"
INTERVAL = 30

# name -> (kind, tickers, account)
INPUTS = {
    "m_eod": (EOD, "aapl,msft", "m_good"),
    "m_iex": (IEX, "aapl,frozenq", "m_good"),
    "m_fx": (FX, "eurusd,frozenfx", "m_good"),
    "m_crypto": (CRYPTO, "btcusd,ethusd", "m_good"),
    "m_unknown": (IEX, "unknownq", "m_good"),
    "m_eod_unknown": (EOD, "unknowneod", "m_good"),
    "m_limited": (EOD, "limitedq", "m_good"),
    "m_flaky": (FX, "flakyfx", "m_good"),
    "m_boom": (CRYPTO, "boomusd", "m_good"),
    "m_badkey": (IEX, "aapl", "m_bad"),
}
EOD_GAP = 4  # the seeded EOD checkpoint is this many trading days behind


def mock_requests():
    with urllib.request.urlopen(MOCK_URL + "/__mock/requests", timeout=30) as r:
        return json.load(r)["data"]


@pytest.fixture(scope="module")
def setup(splunk):
    latest = mock.latest_trading_day()
    days = mock.trading_days(mock.day_str(mock.day_epoch(latest) - 21 * 86400), latest)
    seed_day = days[-1 - EOD_GAP]
    seed_bar = mock.day_epoch(mock.day_str(time.time())) - 4 * 3600  # 20:00 UTC yesterday
    te.create_account(splunk, "m_good", mock.GOOD_KEY)
    te.create_account(splunk, "m_bad", BAD_KEY)
    for name, (kind, _, _) in INPUTS.items():
        te.remove_checkpoint(kind, name)
    te.seed_checkpoint(EOD, "m_eod", {"aapl": seed_day})
    te.seed_checkpoint(CRYPTO, "m_crypto", {"btcusd": seed_bar})
    started = time.time()
    for name, (kind, tickers, account) in INPUTS.items():
        te.create_input(splunk, kind, name, tickers, account, interval=INTERVAL)
    good = [n for n in INPUTS if n in ("m_eod", "m_iex", "m_fx", "m_crypto", "m_unknown", "m_eod_unknown", "m_flaky")]
    bad = ("m_limited", "m_boom", "m_badkey")
    te.wait_until(lambda: all(len(te.runs(n)) >= 3 for n in good) and all(len(te.failures(n)) >= 2 for n in bad),
                  timeout=420)
    for name, (kind, _, _) in INPUTS.items():
        te.disable_input(splunk, kind, name)
    time.sleep(15)  # let the last writes index
    yield {"latest": latest, "days": days, "seed_day": seed_day, "seed_bar": seed_bar, "started": started}
    for name, (kind, _, _) in INPUTS.items():
        te.delete_input(splunk, kind, name)


def _runs_ok(name, n=3):
    got = te.runs(name)
    assert len(got) >= n, f"{name}: {len(got)} completed runs, failures: {te.failures(name)[-2:]}"
    return got


def test_harness_splunk_is_not_utc(splunk):
    rows = splunk.search('| makeresults | eval z=strftime(_time, "%z")', earliest="-1m")
    assert rows and rows[0].get("z") == "+0530", f"Splunk's zone is {rows and rows[0].get('z')}, want +0530"


def test_eod_catches_up_and_matches(splunk, setup):
    runs = _runs_ok("m_eod")
    rows = te.events(splunk, EOD, "m_eod")
    got = collections.defaultdict(list)
    for r in rows:
        got[r["ticker"]].append(r)
    want_aapl = [d for d in setup["days"] if d > setup["seed_day"]]
    assert [r["date"] for r in got["aapl"]] == want_aapl, "aapl days after the checkpoint"
    assert [r["date"] for r in got["msft"]] == [setup["latest"]], "msft first run: latest day only"
    for ticker, rs in got.items():
        for r in rs:
            want = mock.eod_values(ticker, r["date"])
            for f in ("open", "high", "low", "close", "volume", "adjClose", "adjVolume", "divCash", "splitFactor"):
                assert te.num(r.get(f)) == pytest.approx(want[f]), f"{ticker} {r['date']} {f}"
            assert float(r["t"]) == te.utc_day_epoch(r["date"]), f"{ticker} {r['date']} _time is not 00:00 UTC"
    assert [e for e, _ in runs[1:]] == [0] * (len(runs) - 1), f"later runs indexed again: {runs}"
    # one batch request per run, plus one range request for the gap on the first
    assert runs[0][1] == 2 and all(r == 1 for _, r in runs[1:]), f"requests per run: {runs}"
    assert te.read_checkpoint(EOD, "m_eod") == {"aapl": setup["latest"], "msft": setup["latest"]}


def test_crypto_closed_bars_only_and_contiguous(splunk, setup):
    _runs_ok("m_crypto")
    rows = te.events(splunk, CRYPTO, "m_crypto")
    by = collections.defaultdict(list)
    for r in rows:
        by[r["ticker"]].append(r)
    assert by["btcusd"], "no btcusd bars"
    for ticker, rs in by.items():
        starts = [te.iso_epoch(r["date"]) for r in rs]
        assert len(starts) == len(set(starts)), f"{ticker}: duplicate bars"
        assert all(b - a == 3600 for a, b in zip(starts, starts[1:])), f"{ticker}: bars not contiguous"
        for r, s in zip(rs, starts):
            assert s + 3600 <= float(r["it"]), f"{ticker} {r['date']}: bar indexed before it closed"
            assert float(r["t"]) == s, f"{ticker} {r['date']}: _time"
            want = mock.bar_values(ticker, s)
            for f in ("open", "high", "low", "close", "volume", "volumeNotional", "tradesDone"):
                assert te.num(r.get(f)) == pytest.approx(want[f]), f"{ticker} {r['date']} {f}"
            assert r.get("baseCurrency") == ticker[:3] and r.get("quoteCurrency") == "usd"
    assert te.iso_epoch(by["btcusd"][0]["date"]) == setup["seed_bar"] + 3600, "btcusd resumes after the checkpoint"
    # ethusd had no checkpoint, but the request started on btcusd's day: it gets that day too
    if by["ethusd"]:
        assert te.iso_epoch(by["ethusd"][0]["date"]) == mock.day_epoch(mock.day_str(setup["seed_bar"]))
    last = te.iso_epoch(by["btcusd"][-1]["date"])
    assert last + 7200 > time.time() - INTERVAL * 2, "btcusd stopped short of the last closed bar"
    assert te.read_checkpoint(CRYPTO, "m_crypto")["btcusd"] == last


@pytest.mark.parametrize("name,kind,field,frozen", [("m_iex", IEX, "timestamp", "frozenq"),
                                                     ("m_fx", FX, "quoteTimestamp", "frozenfx")])
def test_quotes_once_per_timestamp(splunk, setup, name, kind, field, frozen):
    runs = _runs_ok(name)
    rows = te.events(splunk, kind, name)
    keys = [(r["ticker"].lower(), r[field]) for r in rows]
    assert len(keys) == len(set(keys)), f"{name}: duplicate quotes"
    per = collections.Counter(k for k, _ in keys)
    assert per[frozen] == 1, f"{name}: a quote that never moves was indexed {per[frozen]} times over {len(runs)} runs"
    moving = [t for t in per if t != frozen]
    assert moving and per[moving[0]] >= 2, f"{name}: moving quote indexed {dict(per)}"
    for r in rows:
        assert float(r["t"]) == pytest.approx(te.iso_epoch(r[field]), abs=0.001), f"{name} {r[field]}: _time"
    if kind == IEX:
        for r in rows:
            t = r["ticker"].lower()
            prev = mock.latest_trading_day(te.iso_epoch(r["timestamp"]) - 5 * 3600)
            assert te.num(r["prevClose"]) == pytest.approx(mock.eod_values(t, prev)["close"]), f"{t} prevClose"
            assert r.get("tngoLast") and r.get("open"), f"{t}: fields missing"
    else:
        for r in rows:
            assert te.num(r["midPrice"]) == pytest.approx((te.num(r["bidPrice"]) + te.num(r["askPrice"])) / 2)
    cp = te.read_checkpoint(kind, name)
    assert cp[frozen] == pytest.approx(max(te.iso_epoch(r[field]) for r in rows if r["ticker"].lower() == frozen))


@pytest.mark.parametrize("name,kind", [("m_unknown", IEX), ("m_eod_unknown", EOD)])
def test_unknown_symbol_indexes_nothing_and_says_so(splunk, setup, name, kind):
    runs = _runs_ok(name)
    assert all(e == 0 for e, _ in runs), runs
    assert not te.events(splunk, kind, name)
    assert any("no data for 1 of 1 tickers" in ln for ln in te.log_lines(name)), "no warning for the unknown ticker"


def test_rate_limit_is_reported_and_not_retried(splunk, setup):
    fails = te.failures("m_limited")
    assert len(fails) >= 2 and all("rate_limited=1 status=429" in f and "requests=1 " in f for f in fails), fails
    assert not te.runs("m_limited")
    assert not te.events(splunk, EOD, "m_limited")
    assert te.read_checkpoint(EOD, "m_limited") is None, "checkpoint written by a failed run"
    hits = [r for r in mock_requests() if r["tickers"] == "limitedq"]
    assert len(hits) == len(fails), f"{len(hits)} requests for {len(fails)} runs: 429 was retried"


def test_5xx_is_retried(splunk, setup):
    runs = _runs_ok("m_flaky")
    assert runs[0] == (1, 2), f"first run (503 then 200): {runs[0]}"
    statuses = [r["status"] for r in mock_requests() if r["tickers"] == "flakyfx"]
    assert statuses[:2] == [503, 200], statuses
    assert te.events(splunk, FX, "m_flaky")


def test_persistent_5xx_gives_up(splunk, setup):
    fails = te.failures("m_boom")
    assert len(fails) >= 2 and all("status=500" in f and "requests=4 " in f for f in fails), fails
    assert not te.events(splunk, CRYPTO, "m_boom")
    assert te.read_checkpoint(CRYPTO, "m_boom") is None


def test_bad_key_indexes_nothing(splunk, setup):
    fails = te.failures("m_badkey")
    assert len(fails) >= 2 and all("status=403" in f and "Invalid token." in f for f in fails), fails
    assert not te.events(splunk, IEX, "m_badkey"), "the error document was indexed as events"


def test_key_only_in_the_header_and_never_logged(splunk, setup):
    reqs = [r for r in mock_requests() if not r["path"].startswith("/__mock")]
    assert reqs, "the mock saw no requests"
    assert not [r for r in reqs if r["token_in_query"]], "a request carried the key in its URL"
    assert all(r["auth_header"] for r in reqs), "a request had no Authorization header"
    assert te.grep_count("run complete kind=") > 0, "positive control: the add-on log is where grep looks"
    assert te.grep_count(mock.GOOD_KEY) == 0, "the API key is in Splunk's logs"
    assert te.grep_count(BAD_KEY) == 0, "the bad key is in Splunk's logs"


def test_checkpoint_files_are_flat_json(setup):
    for name, (kind, _, _) in INPUTS.items():
        assert "/" not in f"{kind}__{name}"
    assert isinstance(te.read_checkpoint(IEX, "m_iex"), dict)
