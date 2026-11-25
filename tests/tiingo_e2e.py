"""Helpers shared by the Tiingo mock and live end-to-end suites.

Everything about a run is read from places the add-on writes but never reads
back for its own decisions: Splunk's index (events), the add-on's log file and
the checkpoint file on disk. Keys travel on stdin, never on a command line.
"""
from __future__ import annotations

import calendar
import datetime
import json
import os
import re
import subprocess
import time

APP = "TA-stocks"
NS = f"/servicesNS/nobody/{APP}"
CONTAINER = os.environ.get("SPLUNK_CONTAINER", "ta_stocks_splunk")
LOG_DIR = "/opt/splunk/var/log/splunk"
MODINPUTS = "/opt/splunk/var/lib/splunk/modinputs"
_RUN_RE = re.compile(r"run complete kind=(\S+) events=(\d+) requests=(\d+)")


def _exec(*cmd, stdin=None, user="root", timeout=120):
    p = subprocess.run(["docker", "exec", "-i", "-u", user, CONTAINER, *cmd],
                       input=stdin, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout


def create_account(splunk, name, key):
    splunk.request("DELETE", f"{NS}/{APP}_account/{name}")
    st, _ = splunk.request("POST", f"{NS}/{APP}_account", data={"name": name, "api_key": key})
    assert st in (200, 201), f"create account -> {st}"  # never echo the body


def create_input(splunk, kind, name, tickers, account, interval=60, index="main"):
    st, body = splunk.request("POST", f"{NS}/{APP}_{kind}", data={
        "name": name, "tickers": tickers, "account": account, "index": index, "interval": str(interval)})
    assert st in (200, 201), f"create {kind} input -> {st}: {body[:200]}"


def disable_input(splunk, kind, name):
    splunk.request("POST", f"{NS}/data/inputs/{kind}/{name}/disable")


def delete_input(splunk, kind, name):
    splunk.request("DELETE", f"{NS}/{APP}_{kind}/{name}")


def checkpoint_path(kind, name):
    return f"{MODINPUTS}/{kind}/{kind}__{name}.json"


def seed_checkpoint(kind, name, state):
    path = checkpoint_path(kind, name)
    rc, _ = _exec("bash", "-c", f"mkdir -p {MODINPUTS}/{kind} && cat > {path} && chown -R splunk:splunk {MODINPUTS}/{kind}",
                  stdin=json.dumps(state))
    assert rc == 0, "could not seed the checkpoint"


def remove_checkpoint(kind, name):
    _exec("bash", "-c", f"rm -f {checkpoint_path(kind, name)}")


def read_checkpoint(kind, name):
    rc, out = _exec("cat", checkpoint_path(kind, name))
    return json.loads(out) if rc == 0 and out.strip() else None


def log_lines(name):
    rc, out = _exec("bash", "-c", f"cat {LOG_DIR}/ta-stocks_{name}.log 2>/dev/null || true")
    return out.splitlines()


def runs(name):
    """[(events, requests)] per completed run, oldest first."""
    out = []
    for line in log_lines(name):
        m = _RUN_RE.search(line)
        if m:
            out.append((int(m.group(2)), int(m.group(3))))
    return out


def failures(name):
    return [ln for ln in log_lines(name) if "run failed" in ln]


def wait_until(predicate, timeout=300, step=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(step)
    return predicate()


def events(splunk, kind, name):
    """Indexed events of one input, with _time and _indextime, oldest first.

    Fields come from Splunk's own search-time extraction (no spath), which is
    what a user's search sees.
    """
    rows = splunk.search(
        f'search index=main sourcetype={kind} source="{kind}://{name}" '
        "| eval t=_time, it=_indextime | sort 0 t | table *",
        earliest="0", latest="+10d", count=0,
    )
    return rows


def grep_count(needle, path=LOG_DIR):
    """Lines containing `needle` anywhere under `path` (needle via stdin)."""
    rc, out = _exec("bash", "-c", f"grep -rhF -f /dev/stdin {path} | wc -l", stdin=needle + "\n")
    assert rc == 0, "grep in container failed"
    return int(out.strip() or 0)


def utc_day_epoch(day):
    return calendar.timegm(time.strptime(day[:10], "%Y-%m-%d"))


def iso_epoch(value):
    """Independent ISO parser for the tests (not the add-on's)."""
    s = value.replace("Z", "+00:00")
    m = re.match(r"(.*T\d\d:\d\d:\d\d)(\.\d+)?([+-]\d\d:\d\d)$", s)
    assert m, f"unexpected timestamp {value!r}"
    base = datetime.datetime.strptime(m.group(1) + m.group(3).replace(":", ""), "%Y-%m-%dT%H:%M:%S%z")
    frac = float("0" + m.group(2)) if m.group(2) else 0.0
    return base.timestamp() + frac


def num(v):
    return float(v) if v not in (None, "", "null") else None
