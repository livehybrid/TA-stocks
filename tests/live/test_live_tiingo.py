"""Every Tiingo input against the real api.tiingo.com, on real Splunk.

Runs only in the live CI job (push to main, schedule, dispatch). Kept small
for Tiingo's free tier (about 50 requests an hour, 1,000 a day, 500 symbols
a month): two symbols per input, two runs each, about 17 requests in total.

The add-on's results are checked against Tiingo's own answer, fetched here
through other endpoints than the add-on uses where Tiingo has one:
  EOD     add-on: batch /tiingo/daily/prices (+ range for gaps)
          test:   per-ticker range /tiingo/daily/<t>/prices
  IEX     add-on: /iex/?tickers=     test: /iex/<t> and EOD closes for prevClose
  FX      add-on: /tiingo/fx/top     test: /tiingo/fx/<t>/top
  crypto  add-on: /tiingo/crypto/prices from its checkpoint's day
          test:   the same endpoint (it has no other), fixed start day

A 429 from Tiingo (to the add-on or to the test) FAILS the run with
"TIINGO RATE LIMITED" in the message: it is never a pass and never a skip.
"""
from __future__ import annotations

import collections
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

import tiingo_e2e as te

KEY = os.environ.get("TIINGO_API_KEY", "")
API = "https://api.tiingo.com"
EOD, IEX, FX, CRYPTO = "tiingo_stock_endofday", "tiingo_iex_current", "tiingo_fx_current", "tiingo_crypto_endofday"
INPUTS = {
    "l_eod": (EOD, "aapl,msft"),
    "l_iex": (IEX, "aapl,msft"),
    "l_fx": (FX, "eurusd,gbpusd"),
    "l_crypto": (CRYPTO, "btcusd,ethusd"),
}
EOD_GAP = 3  # seeded EOD checkpoint: this many trading days behind the latest
REQUESTS = collections.Counter()


def tiingo(path, **params):
    """GET from Tiingo directly (not through the add-on). Never prints the key."""
    url = API + path + ("?" + urllib.parse.urlencode(params) if params else "")
    req = urllib.request.Request(url, headers={"Authorization": "Token " + KEY, "Content-Type": "application/json"})
    REQUESTS["test"] += 1
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 429:
            pytest.fail(f"TIINGO RATE LIMITED (429) on the test's own request to {path}: free-tier quota used up")
        pytest.fail(f"Tiingo {path} -> {e.code}")


def no_rate_limit(name):
    hits = [ln for ln in te.failures(name) if "rate_limited=1" in ln]
    if hits:
        pytest.fail(f"TIINGO RATE LIMITED (429) answering the add-on for {name}: {len(hits)} runs refused")


@pytest.fixture(scope="module")
def live(splunk):
    if not KEY:
        pytest.fail("TIINGO_API_KEY is empty: the live job needs the repo secret")
    today = time.strftime("%Y-%m-%d", time.gmtime())
    start = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 21 * 86400))
    days = [r["date"][:10] for r in tiingo("/tiingo/daily/aapl/prices", startDate=start)]
    assert len(days) > EOD_GAP, "Tiingo returned too few AAPL days"
    seed_day = days[-1 - EOD_GAP]
    midnight = te.utc_day_epoch(today)
    seed_bar = midnight - 3 * 3600  # 21:00 UTC yesterday
    te.create_account(splunk, "l_tiingo", KEY)
    for name, (kind, _) in INPUTS.items():
        te.remove_checkpoint(kind, name)
    te.seed_checkpoint(EOD, "l_eod", {"aapl": seed_day})
    te.seed_checkpoint(CRYPTO, "l_crypto", {"btcusd": seed_bar})
    for name, (kind, tickers) in INPUTS.items():
        te.create_input(splunk, kind, name, tickers, "l_tiingo", interval=60)
    te.wait_until(lambda: all(len(te.runs(n)) >= 2 or te.failures(n) for n in INPUTS), timeout=300)
    for name, (kind, _) in INPUTS.items():
        te.disable_input(splunk, kind, name)
    time.sleep(15)
    for name in INPUTS:
        no_rate_limit(name)
        REQUESTS["add-on"] += sum(r for _, r in te.runs(name))
    yield {"seed_day": seed_day, "seed_bar": seed_bar, "eod_start": start}
    print("tiingo requests:", dict(REQUESTS))
    for name, (kind, _) in INPUTS.items():
        te.delete_input(splunk, kind, name)


def _two_runs(name):
    runs = te.runs(name)
    assert len(runs) >= 2, f"{name}: {len(runs)} completed runs; failures: {[f.split('run failed', 1)[-1][:160] for f in te.failures(name)[-2:]]}"
    return runs


def rel(a, b):
    return abs(a - b) <= 1e-9 * max(1.0, abs(b))


def test_eod_matches_tiingo(splunk, live):
    runs = _two_runs("l_eod")
    rows = te.events(splunk, EOD, "l_eod")
    got = collections.defaultdict(list)
    for r in rows:
        got[r["ticker"]].append(r)
    truth = {t: {d["date"][:10]: d for d in tiingo(f"/tiingo/daily/{t}/prices", startDate=live["eod_start"])}
             for t in ("aapl", "msft")}
    latest = max(r["date"] for r in rows)
    want_aapl = sorted(d for d in truth["aapl"] if live["seed_day"] < d <= latest)
    assert [r["date"] for r in got["aapl"]] == want_aapl, "aapl: days after the checkpoint, each once"
    assert len(got["msft"]) >= 1 and len({r["date"] for r in got["msft"]}) == len(got["msft"]), "msft: once per day"
    bad = []
    for t, rs in got.items():
        for r in rs:
            src = truth[t].get(r["date"])
            if src is None:
                bad.append(f"{t} {r['date']} not in Tiingo's range answer")
                continue
            for f in ("open", "high", "low", "close", "volume", "adjClose"):
                if not rel(te.num(r.get(f)), float(src[f])):
                    bad.append(f"{t} {r['date']} {f}")
            if float(r["t"]) != te.utc_day_epoch(r["date"]):
                bad.append(f"{t} {r['date']} _time {r['t']}")
    assert not bad, f"{len(bad)} mismatches: {bad[:10]}"
    assert all(e == 0 for e, _ in runs[1:]) or len(rows) == len({(r["ticker"], r["date"]) for r in rows}), runs
    assert te.read_checkpoint(EOD, "l_eod") == {"aapl": got["aapl"][-1]["date"], "msft": got["msft"][-1]["date"]}


def test_crypto_matches_tiingo(splunk, live):
    _two_runs("l_crypto")
    rows = te.events(splunk, CRYPTO, "l_crypto")
    by = collections.defaultdict(list)
    for r in rows:
        by[r["ticker"]].append(r)
    assert set(by) == {"btcusd", "ethusd"}, f"tickers indexed: {sorted(by)}"
    start_day = time.strftime("%Y-%m-%d", time.gmtime(live["seed_bar"]))
    truth = {d["ticker"]: {te.iso_epoch(b["date"]): b for b in d["priceData"]}
             for d in tiingo("/tiingo/crypto/prices", tickers="btcusd,ethusd", resampleFreq="1hour", startDate=start_day)}
    bad = []
    for t, rs in by.items():
        starts = [te.iso_epoch(r["date"]) for r in rs]
        assert len(starts) == len(set(starts)), f"{t}: duplicate bars"
        first = live["seed_bar"] + 3600 if t == "btcusd" else te.utc_day_epoch(start_day)
        want = [s for s in sorted(truth[t]) if first <= s <= starts[-1]]
        assert starts == want, f"{t}: {len(starts)} bars indexed, Tiingo has {len(want)} in the same span"
        for r, s in zip(rs, starts):
            if s + 3600 > float(r["it"]):
                bad.append(f"{t} {r['date']} indexed before the bar closed")
            if float(r["t"]) != s:
                bad.append(f"{t} {r['date']} _time")
            for f in ("open", "high", "low", "close", "volume", "tradesDone"):
                if not rel(te.num(r.get(f)), float(truth[t][s][f])):
                    bad.append(f"{t} {r['date']} {f}")
    assert not bad, f"{len(bad)} problems: {bad[:10]}"
    assert te.read_checkpoint(CRYPTO, "l_crypto") == {t: te.iso_epoch(rs[-1]["date"]) for t, rs in by.items()}


def test_iex_matches_tiingo(splunk, live):
    _two_runs("l_iex")
    rows = te.events(splunk, IEX, "l_iex")
    keys = [(r["ticker"], r["timestamp"]) for r in rows]
    assert {k[0] for k in keys} == {"AAPL", "MSFT"}, f"tickers: {sorted({k[0] for k in keys})}"
    assert len(keys) == len(set(keys)), "a quote was indexed twice"
    closes = {t: {d["date"][:10]: float(d["close"]) for d in tiingo(f"/tiingo/daily/{t}/prices", startDate=live["eod_start"])}
              for t in ("aapl", "msft")}
    bad = []
    for r in rows:
        ts = te.iso_epoch(r["timestamp"])
        if abs(float(r["t"]) - ts) > 0.001:
            bad.append(f"{r['ticker']} _time {r['t']} vs {r['timestamp']}")
        et_day = time.strftime("%Y-%m-%d", time.gmtime(ts - 5 * 3600))
        prior = [d for d in closes[r["ticker"].lower()] if d < et_day]
        if prior and abs(te.num(r["prevClose"]) - closes[r["ticker"].lower()][max(prior)]) > 1e-4 * te.num(r["prevClose"]):
            bad.append(f"{r['ticker']} prevClose != Tiingo close for {max(prior)}")
        lo, hi, last = te.num(r.get("low")), te.num(r.get("high")), te.num(r.get("tngoLast"))
        if None not in (lo, hi, last) and not lo <= last <= hi:
            bad.append(f"{r['ticker']} tngoLast outside low..high")
    assert not bad, f"{len(bad)} problems: {bad[:10]}"
    now = tiingo("/iex/aapl")[0]
    newest = max((r for r in rows if r["ticker"] == "AAPL"), key=lambda r: te.iso_epoch(r["timestamp"]))
    assert te.iso_epoch(newest["timestamp"]) <= te.iso_epoch(now["timestamp"]) + 1
    assert abs(te.num(newest["tngoLast"]) - float(now["tngoLast"])) <= 0.05 * float(now["tngoLast"])
    cp = te.read_checkpoint(IEX, "l_iex")
    assert cp["aapl"] == pytest.approx(te.iso_epoch(newest["timestamp"]), abs=1e-5)


def test_fx_matches_tiingo(splunk, live):
    _two_runs("l_fx")
    rows = te.events(splunk, FX, "l_fx")
    keys = [(r["ticker"], r["quoteTimestamp"]) for r in rows]
    assert {k[0] for k in keys} == {"eurusd", "gbpusd"}
    assert len(keys) == len(set(keys)), "a quote was indexed twice"
    bad = []
    for r in rows:
        if abs(float(r["t"]) - te.iso_epoch(r["quoteTimestamp"])) > 0.001:
            bad.append(f"{r['ticker']} _time")
        if abs(te.num(r["midPrice"]) - (te.num(r["bidPrice"]) + te.num(r["askPrice"])) / 2) > 1e-4:
            bad.append(f"{r['ticker']} midPrice is not the bid/ask midpoint")
    assert not bad, bad[:10]
    now = tiingo("/tiingo/fx/eurusd/top")[0]
    newest = max((r for r in rows if r["ticker"] == "eurusd"), key=lambda r: te.iso_epoch(r["quoteTimestamp"]))
    assert abs(te.num(newest["midPrice"]) - float(now["midPrice"])) <= 0.01 * float(now["midPrice"])
    assert te.iso_epoch(newest["quoteTimestamp"]) <= te.iso_epoch(now["quoteTimestamp"]) + 1


def test_second_run_adds_no_duplicates(splunk, live):
    for name, (kind, _) in INPUTS.items():
        runs = _two_runs(name)
        assert runs[0][0] > 0, f"{name}: first run indexed nothing"
        n = len(te.events(splunk, kind, name))
        assert n == sum(e for e, _ in runs), f"{name}: {n} indexed vs {sum(e for e, _ in runs)} reported by the runs"


def test_key_never_in_splunk_logs(live):
    assert te.grep_count("run complete kind=") > 0, "positive control: grep reads the add-on logs"
    hits = te.grep_count(KEY)  # a bare name, so a failure cannot print the key
    assert hits == 0, f"the Tiingo key is in Splunk's logs ({hits} lines)"
