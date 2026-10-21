# TA-stocks

**Stock Market data collector**: a Splunk add-on (built with the
[UCC framework](https://github.com/splunk/addonfactory-ucc-generator)) that
pulls market data from several public providers through modular inputs. Each
input checkpoints its progress, so it is safe to run on any interval without
duplicating events.

| Input | Provider | API key |
|-------|----------|---------|
| **Vanguard GraphQL** | Vanguard fund GraphQL endpoint | not required |
| **AlphaVantage Daily** | AlphaVantage | required |
| **Tiingo IEX Current** | Tiingo | required |
| **Tiingo Stock EndOfDay** | Tiingo | required |
| **Tiingo Crypto EndOfDay** | Tiingo | required |
| **Tiingo Forex Current** | Tiingo | required |

## Compatibility

| Attribute | Value |
|-----------|-------|
| **Add-on version** | 1.0.x |
| **Tested against** | Splunk Enterprise 10.0 (Python 3.9) and 10.6 (Python 3.13), real Splunk in Docker, on every CI run |
| **Python runtime** | 3.13 on Splunk 10.2 and later, 3.9 on Splunk 10.1 and earlier |
| **Expected compatible** | Splunk Enterprise and Cloud 9.3+ and 10.x |
| **Deployment roles** | Standalone, Distributed, Search Head Clustering |
| **AppInspect** | Passes the `cloud`, `future` and `private_victoria` tag sets |

Splunk 10.2 and later ship Python 3.9 and 3.13 side by side; this add-on sets
`python.required = 3.13`, so it runs on 3.13 there. Splunk 10.1 and earlier
ignore `python.required` and run it on 3.9 (`python.version = python3`), so the
code and vendored libraries stay 3.9-compatible (`requests < 2.33`,
`splunk-sdk < 3`). CI runs the integration tests on Splunk 10.0 (Python 3.9)
and 10.6 (Python 3.13) to hold both.

## Testing

The add-on ships a real-Splunk integration harness under `docker/`
(`make build up test down`): it installs the packaged add-on into Splunk 10 in
Docker and asserts that the app installs, every modular input registers, each
input scheme exposes its expected arguments and the keyless **Vanguard GraphQL**
input actually indexes events. The same suite runs on every push via GitHub
Actions.

The keyed collectors have live tests too (`tests/test_live_keyed.py`): each
stores an account through the add-on's REST handler, creates the input and
asserts events are indexed, and checks the key never reaches a log file.
Keys come from `ALPHAVANTAGE_API_KEY` and `TIINGO_API_KEY` (repo secrets in CI).

> **Coverage gap:** CI holds no provider keys. Alpha Vantage then runs on its
> public `demo` key (IBM only) and skips if Alpha Vantage refuses the runner;
> the four Tiingo tests skip with `TIINGO_API_KEY not set`. A broken Tiingo
> collector would still pass CI. Tracked in
> [deploy-splunk-app-action#22](https://github.com/livehybrid/deploy-splunk-app-action/issues/22).

## Versioning

Release builds stamp `<tag>+<short sha>` (for example `1.0.6+abc1234`) into
`app.conf` and `app.manifest`, and set `[install] build` to
`MAJOR*10000 + MINOR*100 + PATCH` (1.0.6 is 10006). CI re-reads both from the
packaged tarball and fails the build if either is wrong.
