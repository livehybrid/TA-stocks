"""Deterministic stand-in for api.tiingo.com (stdlib only, synthetic data).

Shapes, status codes and error bodies copy what the real API returned on
25 Nov 2026 (see package/bin/tiingo_client.py). Prices are a pure function of
(ticker, day) or (ticker, hour), so a test can import this module and compute
what the add-on should have indexed without asking the add-on.

Special tickers:
  limited*   429 with Tiingo's allocation message, every time
  flaky*     first request per path answers 503, then normal
  boom*      500 every time
  frozen*    IEX/fx quote timestamp never moves (market closed)
  unknown*   not listed (lists leave it out, per-ticker range is 404)
Any key other than GOOD_KEY gets 403 {"detail": "Invalid token."}.

/__mock/requests lists every request (path, query, auth seen, status).
"""
import calendar
import json
import os
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

GOOD_KEY = "mock-good-key-tiingo-5c1e"
DAY = 86400
HOUR = 3600
QUOTE_STEP = 20  # seconds between moving IEX/fx quotes
ET_OFFSET = -5 * HOUR  # mock keeps US Eastern at -05:00 all year

_lock = threading.Lock()
_requests = []
_seen_paths = set()


def _base(ticker):
    return 50 + zlib.crc32(ticker.encode()) % 450


def day_str(epoch):
    return time.strftime("%Y-%m-%d", time.gmtime(epoch))


def day_epoch(day):
    return calendar.timegm(time.strptime(day, "%Y-%m-%d"))


def is_weekday(epoch):
    return time.gmtime(epoch).tm_wday < 5


def latest_trading_day(now=None):
    now = time.time() if now is None else now
    t = day_epoch(day_str(now)) - DAY
    while not is_weekday(t):
        t -= DAY
    return day_str(t)


def trading_days(start, end):
    out, t = [], day_epoch(start)
    while t <= day_epoch(end):
        if is_weekday(t):
            out.append(day_str(t))
        t += DAY
    return out


def eod_values(ticker, day):
    d = day_epoch(day) // DAY
    b = _base(ticker)
    close = round(b + (d % 17) * 0.37, 4)
    return {
        "close": close,
        "high": round(close + 1.25, 4),
        "low": round(close - 1.5, 4),
        "open": round(close - 0.2, 4),
        "volume": int(1000000 + (d % 29) * 1111 + b),
        "adjClose": close,
        "adjHigh": round(close + 1.25, 4),
        "adjLow": round(close - 1.5, 4),
        "adjOpen": round(close - 0.2, 4),
        "adjVolume": int(1000000 + (d % 29) * 1111 + b),
        "divCash": 0.0,
        "splitFactor": 1.0,
    }


def bar_values(ticker, hour_start, partial_minute=None):
    h = int(hour_start) // HOUR
    b = _base(ticker) * 100.0
    close = round(b + (h % 23) * 3.5, 6)
    if partial_minute is not None:
        close = round(close - 10 - partial_minute, 6)  # differs from the final bar
    return {
        "open": round(b + (h % 19), 6),
        "high": round(b + 200, 6),
        "low": round(b - 200, 6),
        "close": close,
        "volume": round(10 + (h % 7) * 1.5, 6),
        "volumeNotional": round(1000 + (h % 11) * 2.5, 6),
        "tradesDone": float(100 + h % 13),
    }


def quote_epoch(ticker, now=None):
    now = time.time() if now is None else now
    if ticker.startswith("frozen"):
        return day_epoch(latest_trading_day(now)) + 21 * HOUR  # 16:00 ET
    return now - now % QUOTE_STEP


def iex_row(ticker, now=None):
    ts = quote_epoch(ticker, now)
    local = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts + ET_OFFSET))
    prev = latest_trading_day(ts + ET_OFFSET)  # last trading day before the quote's ET date
    last = round(_base(ticker) + (int(ts) // QUOTE_STEP % 50) * 0.01, 4)
    return {
        "ticker": ticker.upper(), "timestamp": local + ".123456789-05:00",
        "lastSaleTimestamp": None, "quoteTimestamp": None,
        "open": round(last - 1, 4), "high": round(last + 2, 4), "low": round(last - 2, 4),
        "mid": last, "tngoLast": last, "last": None, "lastSize": None,
        "bidSize": None, "bidPrice": None, "askPrice": None, "askSize": None,
        "prevClose": eod_values(ticker, prev)["close"], "volume": 1234.0,
    }


def fx_row(ticker, now=None):
    ts = quote_epoch(ticker, now)
    mid = round(1 + (zlib.crc32(ticker.encode()) % 100) / 100 + (int(ts) // QUOTE_STEP % 40) * 0.00001, 6)
    return {
        "ticker": ticker,
        "quoteTimestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + ".007000+00:00",
        "bidPrice": round(mid - 0.00001, 6), "bidSize": 1000000.0,
        "askPrice": round(mid + 0.00001, 6), "askSize": 1000000.0, "midPrice": mid,
    }


def crypto_doc(ticker, start_day=None, now=None):
    now = time.time() if now is None else now
    t = day_epoch(start_day) if start_day else day_epoch(day_str(now))
    bars = []
    while t <= now:
        partial = int((now - t) // 60) if t + HOUR > now else None
        bar = {"date": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(t))}
        bar.update(bar_values(ticker, t, partial))
        bars.append(bar)
        t += HOUR
    return {"ticker": ticker, "baseCurrency": ticker[:-3], "quoteCurrency": ticker[-3:], "priceData": bars}


def _known(t):
    return not t.startswith("unknown")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
        return status

    def do_GET(self):
        url = urlparse(self.path)
        q = {k: v[-1] for k, v in parse_qs(url.query).items()}
        if url.path == "/__mock/health":
            self._send(200, {"ok": True})
            return
        if url.path == "/__mock/requests":
            with _lock:
                self._send(200, {"data": list(_requests)})
            return
        status = self._route(url.path, q)
        auth = self.headers.get("Authorization", "")
        with _lock:
            _requests.append({
                "path": url.path, "query_keys": sorted(q), "tickers": q.get("tickers", ""),
                "token_in_query": "token" in q, "auth_header": auth.startswith("Token "),
                "good_key": auth == "Token " + GOOD_KEY, "status": status, "at": time.time(),
            })

    def _route(self, path, q):
        if self.headers.get("Authorization", "") != "Token " + GOOD_KEY:
            return self._send(403, {"detail": "Invalid token."})
        tickers = [t for t in q.get("tickers", "").lower().split(",") if t]
        names = tickers or [path.rstrip("/").split("/")[-2] if path.endswith("/prices") else ""]
        if any(t.startswith("limited") for t in names):
            return self._send(429, {"detail": "Error: You have run over your hourly request allocation. "
                                              "Please upgrade at https://api.tiingo.com/pricing"})
        if any(t.startswith("boom") for t in names):
            return self._send(500, {"detail": "Internal Server Error"})
        if any(t.startswith("flaky") for t in names):
            key = path + "?" + ",".join(names)
            with _lock:
                first = key not in _seen_paths
                _seen_paths.add(key)
            if first:
                return self._send(503, {"detail": "Service Unavailable"})
        now = time.time()
        if path in ("/iex", "/iex/"):
            return self._send(200, [iex_row(t, now) for t in tickers if _known(t)])
        if path == "/tiingo/fx/top":
            return self._send(200, [fx_row(t, now) for t in tickers if _known(t)])
        if path == "/tiingo/crypto/prices":
            return self._send(200, [crypto_doc(t, q.get("startDate"), now) for t in tickers if _known(t)])
        if path == "/tiingo/daily/prices":
            if "startDate" in q or "endDate" in q:
                return self._send(400, ["Error: This experimental feature has been officially been deprecated. "
                                        "The bulk endpoint withstartDate and endDate specified for historical "
                                        "data is no longer supported as of 2024-07-29."])
            day = latest_trading_day(now)
            return self._send(200, [dict({"ticker": t, "date": day}, **eod_values(t, day)) for t in tickers if _known(t)])
        parts = path.strip("/").split("/")
        if len(parts) == 4 and parts[:2] == ["tiingo", "daily"] and parts[3] == "prices":
            t = parts[2].lower()
            if not _known(t):
                return self._send(404, {"detail": "Error: Ticker '{}' not found".format(t.upper())})
            end = min(q.get("endDate", "9999-12-31"), latest_trading_day(now))
            start = q.get("startDate", end)
            days = trading_days(start, end) if start <= end else []
            return self._send(200, [dict({"date": d + "T00:00:00.000Z"}, **eod_values(t, d)) for d in days])
        return self._send(404, {"detail": "Not found."})


def main():
    port = int(os.environ.get("MOCK_PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
