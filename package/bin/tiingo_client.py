"""Tiingo API client and collectors for the four Tiingo inputs.

Kept free of Splunk imports so the unit tests can load it on its own. Python
3.9 compatible (Splunk 10.1 and earlier run the add-on on 3.9).

Security: the key travels in the Authorization header only, never in a URL, so
no exception text, proxy log or urllib3 debug line can carry it. Errors carry
the HTTP status and Tiingo's `detail` text (which never echoes the key).

Each collector takes the previous checkpoint state ({ticker: last value}) and
returns (events, new_state). Events are (epoch_seconds, dict). Nothing is
written and the checkpoint is not moved when a collector raises, so a failed
run (429, 5xx, network) is simply retried on the next interval.

Real API behaviour (checked live 25 Nov 2026):
  /iex/?tickers=a,b              list of current quotes, `timestamp` in US
                                 Eastern with nanoseconds; unknown -> []
  /tiingo/daily/prices?tickers=  latest trading day per ticker, `date` as
                                 YYYY-MM-DD; unknown tickers are left out;
                                 startDate is refused (400, deprecated 2024)
  /tiingo/daily/<t>/prices       range per ticker, `date` as ...T00:00:00.000Z;
                                 unknown -> 404 {"detail": ...}
  /tiingo/crypto/prices          hourly bars, without startDate only today
                                 (UTC) including the bar still in progress
  /tiingo/fx/top?tickers=        current top of book, `quoteTimestamp` UTC
  bad key                        403 {"detail": "Invalid token."}
None of these endpoints paginate.
"""
import calendar
import datetime
import json
import os
import re
import time

import requests

DEFAULT_API_BASE = "https://api.tiingo.com"
USER_AGENT = "TA-stocks"
RETRY_STATUSES = (500, 502, 503, 504)
MAX_BACKOFF = 30.0
CRYPTO_BAR_SECONDS = 3600
# After a long outage the crypto input catches up at most this far back.
CRYPTO_MAX_LOOKBACK_DAYS = 7


class TiingoError(Exception):
    """API call failed. Carries the status and Tiingo's detail, never a URL or key."""

    def __init__(self, status=None, detail=""):
        self.status = status
        self.detail = (detail or "")[:200]
        super().__init__("Tiingo API error status={} detail={}".format(
            status if status is not None else "-", json.dumps(self.detail)))


class TiingoAuthError(TiingoError):
    """401/403: the key is wrong."""


class TiingoRateLimited(TiingoError):
    """429: hourly or daily allocation used up. Not retried (it would burn more)."""


def resolve_api_base(environ=None, app_dir=None):
    """Base URL for the Tiingo API.

    1. TIINGO_API_BASE environment variable.
    2. `local/tiingo_api_base` in the app. splunkd does not reliably pass
       environment variables to modular-input processes, so the test harness
       writes this file to point the add-on at its mock upstream.
    3. The real Tiingo API.
    """
    environ = os.environ if environ is None else environ
    env = (environ.get("TIINGO_API_BASE") or "").strip()
    if env:
        return env.rstrip("/")
    if app_dir is None:
        app_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir)
    try:
        with open(os.path.join(app_dir, "local", "tiingo_api_base")) as fh:
            val = fh.read().strip()
        if val:
            return val.rstrip("/")
    except OSError:
        pass
    return DEFAULT_API_BASE


def _detail(resp):
    try:
        body = resp.json()
    except ValueError:
        return ""
    if isinstance(body, dict):
        return str(body.get("detail", ""))
    if isinstance(body, list) and body and isinstance(body[0], str):
        return body[0]
    return ""


class Client:
    def __init__(self, api_key, base=None, session=None, timeout=30, max_retries=3, sleep=time.sleep):
        if not api_key:
            raise TiingoAuthError(None, "no API key on the account")
        self.base = (base or resolve_api_base()).rstrip("/")
        self.session = session or requests.Session()
        self.timeout = timeout
        self.max_retries = max_retries
        self.sleep = sleep
        self.requests_made = 0
        self._headers = {
            "Authorization": "Token " + api_key,
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        }

    def get(self, path, params=None):
        """GET a JSON list. 5xx and network errors are retried; 429 is not."""
        url = self.base + path
        for attempt in range(self.max_retries + 1):
            self.requests_made += 1
            try:
                resp = self.session.get(url, params=params, headers=self._headers, timeout=self.timeout)
            except requests.RequestException as exc:
                if attempt < self.max_retries:
                    self.sleep(min(2.0 ** attempt, MAX_BACKOFF))
                    continue
                # type name only: requests' messages include the URL
                raise TiingoError(None, type(exc).__name__)
            status = resp.status_code
            if status in RETRY_STATUSES and attempt < self.max_retries:
                self.sleep(min(2.0 ** attempt, MAX_BACKOFF))
                continue
            if status == 429:
                raise TiingoRateLimited(status, _detail(resp))
            if status in (401, 403):
                raise TiingoAuthError(status, _detail(resp))
            if status >= 400:
                raise TiingoError(status, _detail(resp))
            try:
                body = resp.json()
            except ValueError:
                raise TiingoError(status, "response is not JSON")
            if isinstance(body, dict):
                # An error document on a 200 (the old code indexed its keys as events).
                raise TiingoError(status, str(body.get("detail", "unexpected object response")))
            if not isinstance(body, list):
                raise TiingoError(status, "unexpected response")
            return body
        raise TiingoError(None, "retries exhausted")  # pragma: no cover


# ------------------------------------------------------------------ helpers ---

_FRACTION = re.compile(r"(\.\d{1,6})\d*")


def parse_ts(value):
    """ISO 8601 (Z, offsets, up to nanoseconds) or YYYY-MM-DD -> epoch seconds (UTC)."""
    if not value:
        raise ValueError("empty timestamp")
    s = str(value).strip()
    if len(s) == 10:
        return float(calendar.timegm(time.strptime(s, "%Y-%m-%d")))
    s = s.replace("Z", "+00:00")
    s = _FRACTION.sub(lambda m: m.group(1), s, count=1)
    dt = datetime.datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.timestamp()


def split_tickers(raw):
    seen = []
    for t in (raw or "").split(","):
        t = t.strip().lower()
        if t and t not in seen:
            seen.append(t)
    return seen


def _day(epoch):
    return time.strftime("%Y-%m-%d", time.gmtime(epoch))


# --------------------------------------------------------------- collectors ---

def _snapshots(rows, field, state):
    """Quotes newer than the checkpoint, one per ticker and timestamp."""
    events, new_state = [], dict(state)
    for row in rows:
        ticker = str(row.get("ticker", "")).lower()
        if not ticker or not row.get(field):
            continue
        ts = parse_ts(row[field])
        last = new_state.get(ticker)
        if last is not None and ts <= float(last):
            continue
        events.append((ts, row))
        new_state[ticker] = ts
    return events, new_state


def collect_iex(client, tickers, state, now=None):
    rows = client.get("/iex/", {"tickers": ",".join(tickers)})
    return _snapshots(rows, "timestamp", state)


def collect_fx(client, tickers, state, now=None):
    rows = client.get("/tiingo/fx/top", {"tickers": ",".join(tickers)})
    return _snapshots(rows, "quoteTimestamp", state)


def collect_eod(client, tickers, state, now=None):
    """Latest trading day per ticker from the batch endpoint.

    A first run takes the latest day only. When the checkpoint is more than one
    weekday behind, the days in between are fetched from the per-ticker range
    endpoint (the batch endpoint refuses ranges), so a stopped input loses nothing.
    """
    rows = client.get("/tiingo/daily/prices", {"tickers": ",".join(tickers)})
    events, new_state = [], dict(state)
    for row in rows:
        ticker = str(row.get("ticker", "")).lower()
        if not ticker or not row.get("date"):
            continue
        day = str(row["date"])[:10]
        last = new_state.get(ticker)
        if last is not None and day <= last:
            continue
        if last is not None:
            gap_start = _day(parse_ts(last) + 86400)
            gap_end = _day(parse_ts(day) - 86400)
            if gap_start <= gap_end and _has_weekday(gap_start, gap_end):
                for gap_row in client.get("/tiingo/daily/{}/prices".format(ticker),
                                          {"startDate": gap_start, "endDate": gap_end}):
                    gap_day = str(gap_row.get("date", ""))[:10]
                    if not gap_day or gap_day <= last or gap_day >= day:
                        continue
                    shaped = {"ticker": ticker, "date": gap_day}
                    shaped.update({k: v for k, v in gap_row.items() if k != "date"})
                    events.append((parse_ts(gap_day), shaped))
        row = dict(row, ticker=ticker, date=day)
        events.append((parse_ts(day), row))
        new_state[ticker] = day
    return events, new_state


def _has_weekday(start, end):
    t = parse_ts(start)
    while _day(t) <= end:
        if time.gmtime(t).tm_wday < 5:
            return True
        t += 86400
    return False


def collect_crypto(client, tickers, state, now=None):
    """Hourly bars that have closed and are newer than the checkpoint.

    The bar still in progress is never indexed (it would be indexed once with
    partial values and then skipped as already seen). With a checkpoint the
    request starts on the checkpoint's day, so bars either side of midnight UTC
    are not lost.
    """
    now = time.time() if now is None else now
    params = {"tickers": ",".join(tickers), "resampleFreq": "1hour"}
    known = [float(state[t]) for t in tickers if state.get(t) is not None]
    if known:
        floor = now - CRYPTO_MAX_LOOKBACK_DAYS * 86400
        params["startDate"] = _day(max(min(known), floor))
    rows = client.get("/tiingo/crypto/prices", params)
    events, new_state = [], dict(state)
    for ticker_doc in rows:
        ticker = str(ticker_doc.get("ticker", "")).lower()
        for bar in ticker_doc.get("priceData") or []:
            if not bar.get("date"):
                continue
            start = parse_ts(bar["date"])
            if start + CRYPTO_BAR_SECONDS > now:
                continue
            last = new_state.get(ticker)
            if last is not None and start <= float(last):
                continue
            event = dict(bar)
            event["baseCurrency"] = ticker_doc.get("baseCurrency")
            event["quoteCurrency"] = ticker_doc.get("quoteCurrency")
            event["ticker"] = ticker_doc.get("ticker")
            events.append((start, event))
            new_state[ticker] = start
    events.sort(key=lambda e: e[0])
    return events, new_state


COLLECTORS = {
    "tiingo_iex_current": collect_iex,
    "tiingo_fx_current": collect_fx,
    "tiingo_stock_endofday": collect_eod,
    "tiingo_crypto_endofday": collect_crypto,
}


# ------------------------------------------------------------- checkpoint ---

class FileCheckpoint:
    """One JSON file per input in the modular-input checkpoint directory."""

    def __init__(self, directory, kind, name):
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", "{}__{}".format(kind, name))
        self.path = os.path.join(directory, safe + ".json")

    def load(self):
        try:
            with open(self.path) as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def save(self, state):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(state, fh, sort_keys=True)
        os.replace(tmp, self.path)
