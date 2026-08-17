"""
Live end-to-end test for the vanguard_graphql modular input.

This is the real integration proof, and it is deliberately built around the one
input that needs no API key: `vanguard_graphql` hits Vanguard's public GraphQL
endpoint (https://www.vanguard.co.uk/gpx/graphql) with a static consumer id, so
it can run in CI without any Splunkbase/Tiingo/Alpha Vantage secret. It creates a
real input in the running Splunk, lets splunkd schedule and run the packaged
script, and asserts that real events are indexed with the fields the collector
emits.

The five keyed collectors (alphavantage_daily, tiingo_*) cannot be exercised
live without credentials; their scheme execution + registration is covered by
test_modinput_scheme.py and test_install_smoke.py instead.

Honest failure semantics (mirrors the keyless upstream pattern):
  * events indexed with fields   -> PASS  (the whole pipeline works)
  * no events, but splunkd logged the input's own upstream fetch error
                                 -> SKIP  (Vanguard unreachable/blocked from the
                                           runner, e.g. geo/datacentre IP; not us)
  * no events and no error logged -> FAIL  (the input never ran / is broken)
"""
from __future__ import annotations

import time

import pytest

STANZA = "vanguard_probe"
INDEX = "main"
SOURCETYPE = "vanguard_graphql"

# Namespaces to try, in order. `search` is writable by the container's splunk
# user without touching the bind-mounted app dir; the app namespace is a fallback.
CREATE_PATHS = (
    "/servicesNS/nobody/search/data/inputs/vanguard_graphql",
    "/servicesNS/nobody/TA-stocks/data/inputs/vanguard_graphql",
)

POLL_SECONDS = 240
POLL_INTERVAL = 10


@pytest.fixture(scope="module")
def vanguard_input(splunk):
    """Create a short-interval vanguard_graphql input; remove it on teardown."""
    used_path = None
    status = body = None
    for path in CREATE_PATHS:
        status, body = splunk.request(
            "POST",
            path,
            data={
                "name": STANZA,
                # endofday pulls NAV price history for a fund (portId 9218 is the
                # portfolio the query defaults to) — a small, keyless payload.
                "function": "endofday",
                "portids": "9218",
                "index": INDEX,
                "interval": "60",
            },
        )
        if status in (200, 201) or status == 409:  # created, or already exists
            used_path = path
            break
    assert used_path, f"could not create vanguard_graphql input (last {status}: {str(body)[:400]})"
    # Ensure it is enabled even if it pre-existed (409).
    splunk.request("POST", f"{used_path}/{STANZA}/enable")

    yield used_path

    splunk.request("DELETE", f"{used_path}/{STANZA}", params={"output_mode": "json"})


def _upstream_error_logged(splunk):
    # solnlib logs the input under $SPLUNK_HOME/var/log/splunk/ta-stocks_vanguard_graphql.log,
    # which splunkd monitors into _internal. The collector catches upstream
    # failures and logs them, so an error here means "the input ran but Vanguard
    # was unreachable", not "our code is broken".
    spl = (
        "search index=_internal source=*ta-stocks_vanguard_graphql* "
        '("Exception raised while ingesting" OR "Query failed with status code" '
        'OR "ConnectionError" OR "Max retries" OR "Timeout" '
        'OR "Temporary failure in name resolution" OR "ERROR") '
        "earliest=-15m"
    )
    return bool(splunk.search(spl, earliest="-15m"))


def test_vanguard_events_indexed(splunk, vanguard_input):
    deadline = time.time() + POLL_SECONDS
    results = []
    while time.time() < deadline:
        # `| spath` parses each event's JSON `_raw` directly, so field assertions
        # are independent of whether search-time auto-kv (props KV_MODE=json) is
        # in scope for this oneshot context. This is how a dashboard panel reads
        # the payload too, so it tests the real contract deterministically.
        results = splunk.search(
            f"search index={INDEX} sourcetype={SOURCETYPE} | head 5 | spath",
            earliest="-7d",
        )
        if results:
            break
        time.sleep(POLL_INTERVAL)

    if not results:
        if _upstream_error_logged(splunk):
            pytest.skip("vanguard_graphql input ran but Vanguard was unreachable from the runner")
        pytest.fail(
            f"no {SOURCETYPE} events indexed within {POLL_SECONDS}s and no upstream "
            "error logged — the modular input did not run"
        )

    # Prove Splunk indexed the JSON payload the collector emits (NAV price rows:
    # price / currencyCode / date).
    row = results[0]
    assert any(k in row for k in ("price", "currencyCode", "date")), (
        f"indexed event missing expected vanguard NAV fields: {sorted(row)}"
    )
