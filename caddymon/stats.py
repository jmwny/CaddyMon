"""Status classification and running totals (overall, per IP, per path, and
per site when following several logs)."""

from __future__ import annotations

import heapq
from collections import Counter
from dataclasses import dataclass, field

from .logsource import Record


# Status-class buckets: key -> (label, palette-attribute-name). The order here
# is the order shown in the summary. classify() is the only place the ranges
# are defined; colors (Palette.style_for) and markers (marker) derive from it.
CLASSES = [
    ("2xx", "2xx Success:", "GREEN"),
    ("3xx", "3xx Redirect:", "CYAN"),
    ("4xx", "4xx Client:", "YELLOW"),
    ("5xx", "5xx Server:", "BRIGHT_RED"),
    ("other", "Other:", "DIM"),
]


CLASS_STYLE = {key: attr for key, _label, attr in CLASSES}


CLASS_MARKER = {"2xx": "✓", "3xx": "→", "4xx": "✗", "5xx": "✗", "other": "·"}


def classify(status: int) -> str:
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    if status >= 500:
        return "5xx"
    return "other"


def marker(status: int) -> str:
    """✓ / → / ✗ by status class; "·" for "other" (e.g. 101 upgrades)."""
    return CLASS_MARKER[classify(status)]


@dataclass
class IpStat:
    """Per-IP running totals for the grouped view and the summary. With
    ``Stats.per_site``, ``sites`` holds the same totals split by site (site ->
    IpStat, whose own ``sites`` stays empty)."""

    hits: int = 0
    classes: Counter = field(default_factory=Counter)
    last_time: str = ""
    last_seq: int = 0  # Stats.total at the last hit; orders "most recent"
    sites: dict = field(default_factory=dict)

    def add(self, cls: str, when: str, seq: int) -> None:
        self.hits += 1
        self.classes[cls] += 1
        self.last_time = when
        self.last_seq = seq


@dataclass
class Stats:
    """Running totals. ``total`` and ``classes`` are exact for the whole run.
    The per-key tables (IPs, paths, denied IPs) are capped so a monitor left
    running for weeks against scanners (random paths, rotating IPs) stays
    bounded: past ``MAX_*`` keys, a table is cut back to half, keeping the
    biggest counts (and, for IPs, also the most recently seen). Long-tail counts
    are therefore approximate on very long runs. ``on_evict`` is called with
    the IPs dropped, so the resolver can forget them too.

    ``per_site`` (set when following several logs) also splits the totals by
    ``Record.site``: ``sites`` (site -> class Counter, exact) and each IP's
    ``IpStat.sites``. Off, nothing per-site is kept."""

    MAX_IPS = 20000
    MAX_PATHS = 5000
    MAX_DENIED = 5000

    total: int = 0
    classes: Counter = field(default_factory=Counter)
    denied_ips: Counter = field(default_factory=Counter)
    paths: Counter = field(default_factory=Counter)
    ips: dict = field(default_factory=dict)  # ip -> IpStat
    on_evict: object = None  # callable(list_of_ips) or None
    per_site: bool = False
    sites: dict = field(default_factory=dict)  # site -> Counter (per_site only)

    def record(self, rec: Record) -> None:
        self.total += 1
        cls = classify(rec.status)
        self.classes[cls] += 1
        if self.per_site:
            self.sites.setdefault(rec.site, Counter())[cls] += 1
        if rec.status == 403:
            self.denied_ips[rec.ip] += 1
            if len(self.denied_ips) > self.MAX_DENIED:
                self.denied_ips = Counter(
                    dict(self.denied_ips.most_common(self.MAX_DENIED // 2)))
        self.paths[rec.uri.split("?", 1)[0]] += 1
        if len(self.paths) > self.MAX_PATHS:
            self.paths = Counter(dict(self.paths.most_common(self.MAX_PATHS // 2)))
        st = self.ips.get(rec.ip)
        if st is None:
            if len(self.ips) >= self.MAX_IPS:
                self._prune_ips()  # before inserting, so the new IP survives
            st = self.ips[rec.ip] = IpStat()
        st.add(cls, rec.time, self.total)
        if self.per_site:
            site = st.sites.get(rec.site)
            if site is None:
                site = st.sites[rec.site] = IpStat()
            site.add(cls, rec.time, self.total)

    def _prune_ips(self) -> None:
        # A quarter by hits plus a quarter by recency: at most half survives,
        # so pruning is rare (amortised) rather than on every new IP.
        quarter = self.MAX_IPS // 4
        items = self.ips.items()
        keep = {ip for ip, _ in heapq.nlargest(  # ties: the more recent wins
            quarter, items, key=lambda kv: (kv[1].hits, kv[1].last_seq))}
        keep |= {ip for ip, _ in heapq.nlargest(quarter, items, key=lambda kv: kv[1].last_seq)}
        dropped = [ip for ip in self.ips if ip not in keep]
        self.ips = {ip: st for ip, st in self.ips.items() if ip in keep}
        if self.on_evict and dropped:
            self.on_evict(dropped)
