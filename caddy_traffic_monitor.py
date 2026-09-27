#!/usr/bin/env python3
"""Caddy Traffic Monitor.

Tail a Caddy JSON access log and show live traffic in an htop-style terminal
view: a one-line header (totals, a rolling 60 s request rate with sparkline,
per-class counts), a pane of client IPs grouped with per-class counts, last
seen, a scanner flag, and who owns each IP, a pane of the newest requests, and
a footer of the keys that work right now. When stdout isn't a terminal it just
prints a plain color-coded request stream instead. An on-exit summary is always
shown.

Interactive keys (POSIX TTY only): ``↑``/``↓`` (or ``j``/``k``), PgUp/PgDn,
Home/End move a cursor over the IPs or scroll the request pane, whichever has
focus (``←``/``→`` switch it; End returns the requests to live); ``Enter``
narrows the request pane to the
selected IP and ``Esc`` returns to all IPs; ``Tab`` cycles the layout (split /
IPs only / requests only); ``a``/``0`` all status codes, ``2``-``5`` only that
class; ``s`` toggles the IP sort (most recent / most hits); ``q`` quits.

IP owners come from RDAP (the regional internet registries, via rdap.org) plus
reverse DNS, looked up in the background only for IPs being shown, and cached.
``--no-lookup`` disables all such network queries.

This is a pure-Python rewrite of the original Bash tool: it has no external
dependencies (no ``jq``, ``tail``, or ``stdbuf``) and follows the log file
natively, surviving Caddy's default log rotation.

Usage:
    sudo python3 caddy_traffic_monitor.py [LOG_FILE] [options]

Examples:
    sudo python3 caddy_traffic_monitor.py
    sudo python3 caddy_traffic_monitor.py /var/log/caddy/access.log
    sudo python3 caddy_traffic_monitor.py --layout ips --from-start
    python3 caddy_traffic_monitor.py --from-start --no-color < dump.log
    CADDY_LOG_FILE=/path/to.log python3 caddy_traffic_monitor.py
"""

import sys

from caddymon.cli import run

if __name__ == "__main__":
    sys.exit(run())
