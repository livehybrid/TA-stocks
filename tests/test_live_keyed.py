"""
Live test for the Alpha Vantage collector.

The four Tiingo inputs are covered by tests/test_mock_tiingo_e2e.py (mock
upstream, every push) and tests/live/test_live_tiingo.py (the real API, live
job only).

They run the real path a user takes: store an account through the add-on's own
REST handler (the Configuration page does the same), create the input through
the add-on's input handler, let splunkd schedule the packaged script, and assert
events are indexed.

Keys come from the environment and nothing else:
  ALPHAVANTAGE_API_KEY  unset -> Alpha Vantage's public `demo` key, which only
                        serves IBM. Its rate limit is shared, so if a direct
                        probe from this runner is refused the test SKIPS.

Each test also checks the key never reaches any log under var/log/splunk
(read straight from disk in the container, not through anything the add-on
reports): until 1.0.6 the collectors logged the request URL, key included.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

import pytest

from conftest import docker_exec

APP = "TA-stocks"
INDEX = "main"
POLL_SECONDS = 240
POLL_INTERVAL = 10

AV_KEY = os.environ.get("ALPHAVANTAGE_API_KEY") or "demo"
AV_TICKER = "IBM" if AV_KEY == "demo" else os.environ.get("ALPHAVANTAGE_TICKER", "IBM")


def _post(splunk, path, data):
    status, body = splunk.request("POST", path, data={**data, "output_mode": "json"})
    assert status in (200, 201), f"POST {path} -> {status}: {body[:400]}"


def _delete(splunk, path):
    splunk.request("DELETE", path, params={"output_mode": "json"})


@pytest.fixture
def keyed_input(splunk):
    """Create an account plus one input of `kind`; remove both afterwards."""
    made = []

    def make(kind, account, key, field, value):
        acct = f"/servicesNS/nobody/{APP}/{APP}_account"
        _delete(splunk, f"{acct}/{account}")
        _post(splunk, acct, {"name": account, "api_key": key})
        made.append(f"{acct}/{account}")
        inp = f"/servicesNS/nobody/{APP}/{APP}_{kind}"
        name = f"{kind}_probe"
        _delete(splunk, f"{inp}/{name}")
        _post(splunk, inp, {"name": name, field: value, "account": account, "index": INDEX, "interval": "60"})
        made.insert(0, f"{inp}/{name}")

    yield make
    for path in made:
        _delete(splunk, path)


def _events(splunk, sourcetype):
    deadline = time.time() + POLL_SECONDS
    while time.time() < deadline:
        # Events carry the trading day at 23:59:59Z, so today's can be in the future.
        rows = splunk.search(f"search index={INDEX} sourcetype={sourcetype} | head 5 | spath",
                             earliest="-30d", latest="+2d")
        if rows:
            return rows
        time.sleep(POLL_INTERVAL)
    return []


def _key_in_logs(needle):
    rc, out, _ = docker_exec("grep", "-rlF", needle, "/opt/splunk/var/log/splunk/")
    return out.split() if rc == 0 else []


def _alphavantage_serves():
    """Ask Alpha Vantage directly (not through the add-on) whether it will answer."""
    url = f"https://www.alphavantage.co/query?function=GLOBAL_QUOTE&symbol={AV_TICKER}&apikey={AV_KEY}"
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            body = json.loads(r.read().decode())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, f"Alpha Vantage unreachable from the runner: {exc!r}"
    if not body.get("Global Quote"):
        return False, f"Alpha Vantage refused the request: {str(body)[:200]}"
    return True, ""


def test_alphavantage_daily_indexes_quote(splunk, keyed_input):
    ok, why = _alphavantage_serves()
    if not ok:
        pytest.skip(why)
    keyed_input("alphavantage_daily", "av_probe", AV_KEY, "ticker", AV_TICKER)
    rows = _events(splunk, "alphavantage_daily")
    if not rows:
        ok, why = _alphavantage_serves()
        if not ok:
            pytest.skip(f"no events, and upstream now refuses: {why}")
        pytest.fail("Alpha Vantage answers this runner, but no alphavantage_daily events were indexed")
    row = rows[0]
    assert row.get("symbol") == AV_TICKER, f"unexpected quote row: {row}"
    assert row.get("price"), f"quote row has no price: {row}"
    leaked = _key_in_logs(f"apikey={AV_KEY}")
    assert not leaked, f"Alpha Vantage key written to {leaked}"
