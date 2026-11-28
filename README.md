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
| **Tested against** | Splunk Enterprise 10.4 and the newest 10.6 (Python 3.13), real Splunk in Docker, on every CI run |
| **Python runtime** | 3.13 |
| **Supported** | Splunk Enterprise and Cloud 10.4 and later |
| **Deployment roles** | Standalone, Distributed, Search Head Clustering |
| **AppInspect** | Passes the `cloud`, `future` and `private_victoria` tag sets |

The add-on sets `python.required = 3.13`, which every supported Splunk honours,
so it runs on Python 3.13; CI checks that splunkd launched every input on 3.13.
New releases support Splunk 10.4 and later. For an older Splunk, use the last
release that supported it (1.1.0 was tested on 10.0 and 10.6).

## Testing

The add-on ships a real-Splunk integration harness under `docker/`
(`make build up test down`): it installs the packaged add-on into Splunk 10 in
Docker and asserts that the app installs, every modular input registers, each
input scheme exposes its expected arguments and the keyless **Vanguard GraphQL**
input actually indexes events. The same suite runs on every push via GitHub
Actions.

The Tiingo inputs are tested three ways:

| Tier | Where | What |
|------|-------|------|
| `tests/unit/` | every push, Python 3.13 | client: retries, 429, errors, checkpoints, closed crypto bars, EOD gap fill |
| `tests/test_mock_tiingo_e2e.py` | every push except Dependabot, Splunk 10.4 and the newest 10.6 | all four inputs against a synthetic Tiingo (`docker/mock`): values, `_time`, no duplicates over three runs, catch-up after a stop, 429, 5xx, bad key, unknown symbols, key never in a URL or a log |
| `tests/live/test_live_tiingo.py` | push to main, weekly schedule, manual runs; the newest Splunk 10.6 | all four inputs against the real API, checked against Tiingo's own answer fetched by the test; about 17 requests a run |

Splunk runs in Asia/Kolkata in the harness, so a timestamp read in local time
instead of UTC fails the tests. The live job needs the `TIINGO_API_KEY` repo
secret; a 429 from Tiingo fails it with `TIINGO RATE LIMITED`. Alpha Vantage
runs live on its public `demo` key (IBM only) and skips if Alpha Vantage
refuses the runner.

## Tiingo inputs: behaviour

From the release after 1.0.7, every Tiingo input keeps a checkpoint (a JSON file per input in
Splunk's modular-input checkpoint directory) and indexes only what is new:

| Input | Endpoint | Indexed per run | Event time |
|-------|----------|-----------------|------------|
| Tiingo IEX Current | `/iex/` | a quote whose `timestamp` is newer than the last one | `timestamp` |
| Tiingo Stock EndOfDay | `/tiingo/daily/prices` | a trading day not yet indexed; after a stop, the days missed (from `/tiingo/daily/<ticker>/prices`) | the day at 00:00 UTC |
| Tiingo Crypto EndOfDay | `/tiingo/crypto/prices` (hourly) | hourly bars that have closed, from the checkpoint's day (at most 7 days back) | bar start |
| Tiingo Forex Current | `/tiingo/fx/top` | a quote whose `quoteTimestamp` is newer than the last one | `quoteTimestamp` |

Up to 1.0.7 each run indexed the same data again (an EOD day or a crypto bar
was indexed once per interval, 288 times a day at the default 300 s), the
crypto bar still in progress was indexed with partial values, an error answer
(bad key, rate limit) was indexed as an event, and on a Splunk server not on
UTC an EOD day was put at local midnight. Searches that de-duplicated with
`dedup` keep working; sums over time are now right without it.

Errors are logged as `run failed kind=<input> status=<n> detail="..."`
(`rate_limited=1` for a 429) and never include the key, which is sent only in
the `Authorization` header. A 429 is not retried; 5xx and network errors are
retried three times. Tiingo's free tier allows about 50 requests an hour and
1,000 a day: each run is one request per input (plus one per ticker after a
stop). The end-of-day stock input defaults to 3,600 s (a daily price does not
change more often) and the other three Tiingo inputs to 300 s, so the defaults
make 37 requests an hour and 888 a day, inside the free tier. Four inputs at
300 s would make 1,152 a day and hit the daily limit.

## Versioning

Release builds stamp `<tag>+<short sha>` (for example `1.0.6+abc1234`) into
`app.conf` and `app.manifest`, and set `[install] build` to
`MAJOR*10000 + MINOR*100 + PATCH` (1.0.6 is 10006). CI re-reads both from the
packaged tarball and fails the build if either is wrong.
