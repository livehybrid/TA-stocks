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
| **Add-on version** | 1.0.3 |
| **Tested against** | Splunk Enterprise 10.0, Python 3.9 (real Splunk in Docker, on every CI run) |
| **Python runtime** | 3.9, Splunk's long-term-support runtime |
| **Expected compatible** | Splunk Enterprise and Cloud 9.3+ and 10.x (any release on the Python 3.9 runtime) |
| **Deployment roles** | Standalone, Distributed, Search Head Clustering |
| **AppInspect** | Passes the `cloud`, `future` and `private_victoria` tag sets |

Splunk 9.3 through 10.1 default to Python 3.9, and 3.9 stays the LTS runtime on
10.2 and later, so an add-on that is clean on 3.9 runs unchanged across that
whole range. This add-on is validated on 3.9 and pins its vendored libraries to
versions that stay 3.9-clean. It is not yet validated on the opt-in Python 3.13
runtime introduced in Splunk 10.2.

## Testing

The add-on ships a real-Splunk integration harness under `docker/`
(`make build up test down`): it installs the packaged add-on into Splunk 10 in
Docker and asserts that the app installs, every modular input registers, each
input scheme exposes its expected arguments and the keyless **Vanguard GraphQL**
input actually indexes events. The same suite runs on every push via GitHub
Actions.

> **Coverage gap:** the five keyed collectors (AlphaVantage and the four Tiingo
> inputs) are currently scheme- and registration-tested only, not exercised
> against their live APIs, because CI holds no provider API keys. A broken keyed
> collector would still pass CI. Tracked in
> [deploy-splunk-app-action#22](https://github.com/livehybrid/deploy-splunk-app-action/issues/22).
