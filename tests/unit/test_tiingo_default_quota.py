"""The shipped Tiingo defaults must fit Tiingo's free tier (about 1,000 requests a day).

Each run of a Tiingo input is one request, so a day at the default intervals is
sum(86400 / interval). Read straight from globalConfig.json, which is what UCC
turns into the Inputs page defaults.
"""
import json
from pathlib import Path

FREE_TIER_PER_DAY = 1000
CONFIG = Path(__file__).resolve().parents[2] / "globalConfig.json"


def _default_intervals():
    services = json.loads(CONFIG.read_text())["pages"]["inputs"]["services"]
    out = {}
    for svc in services:
        if not svc["name"].startswith("tiingo_"):
            continue
        for ent in svc["entity"]:
            if ent["field"] == "interval":
                out[svc["name"]] = int(ent["defaultValue"])
    return out


def test_every_tiingo_input_has_a_default_interval():
    assert set(_default_intervals()) == {
        "tiingo_iex_current", "tiingo_stock_endofday",
        "tiingo_crypto_endofday", "tiingo_fx_current",
    }


def test_stock_endofday_defaults_to_hourly():
    assert _default_intervals()["tiingo_stock_endofday"] == 3600


def test_defaults_fit_the_free_tier_per_day():
    per_day = sum(86400 // i for i in _default_intervals().values())
    assert per_day <= FREE_TIER_PER_DAY, per_day
