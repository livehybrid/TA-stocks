"""
Install / load smoke tests (network-free).

Prove the built add-on installs into a real Splunk cleanly: it is enabled, every
modular input is registered, their schemes introspect, and nothing in the add-on
failed to import at startup.
"""
from __future__ import annotations

import json

APP = "TA-stocks"
INPUTS = (
    "alphavantage_daily",
    "vanguard_graphql",
    "tiingo_iex_current",
    "tiingo_stock_endofday",
    "tiingo_crypto_endofday",
    "tiingo_fx_current",
)


def test_app_installed_and_enabled(splunk):
    entries = splunk.entries(f"/services/apps/local/{APP}")
    assert entries, f"{APP} is not installed"
    content = entries[0]["content"]
    assert content.get("disabled") in (False, 0, "0"), f"{APP} is disabled: {content.get('disabled')}"


def test_all_modular_inputs_registered(splunk):
    names = {e["name"] for e in splunk.entries("/services/data/modular-inputs")}
    missing = [i for i in INPUTS if i not in names]
    assert not missing, f"modular inputs not registered: {missing} (have: {sorted(names)})"


def test_modinput_schemes_expose_expected_args(splunk):
    # If a script failed to import, Splunk cannot introspect its scheme, so the
    # input-specific argument would be absent. Shape-tolerant: check the JSON.
    # The tiingo/alphavantage collectors key off a `ticker(s)` arg; the vanguard
    # GraphQL collector keys off `portids` + `function`.
    expected = {
        "alphavantage_daily": "ticker",
        "vanguard_graphql": "function",
        "tiingo_iex_current": "tickers",
        "tiingo_stock_endofday": "tickers",
        "tiingo_crypto_endofday": "tickers",
        "tiingo_fx_current": "tickers",
    }
    for inp, arg in expected.items():
        data = splunk.get_json(f"/services/data/modular-inputs/{inp}")
        assert arg in json.dumps(data), f"{inp} scheme missing expected arg '{arg}'"


def test_no_startup_import_or_init_errors(splunk):
    # Precise signatures: a failed modular-input init or an import error tied to
    # our scripts. Deliberately does NOT match runtime fetch errors (those are a
    # separate concern covered by the live test).
    input_clause = " OR ".join(f'"Unable to initialize modular input \\"{i}\\""' for i in INPUTS)
    script_clause = " OR ".join(INPUTS + ("stocks_helper", "import_declare_test"))
    spl = (
        "search index=_internal log_level=ERROR "
        f"({input_clause} "
        '   OR (("ImportError" OR "ModuleNotFoundError" OR "Traceback") '
        f"       AND ({script_clause}))) "
        "earliest=-1h"
    )
    hits = splunk.search(spl, earliest="-1h")
    assert not hits, f"startup import/init errors found: {[h.get('_raw', '')[:200] for h in hits[:3]]}"
