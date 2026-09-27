"""The interactive htop-style terminal view (alternate screen)."""

from __future__ import annotations

import os
import re
import sys
import time
from collections import deque

from .logsource import Record
from .output import Palette
from .rdap import OwnerResolver
from .stats import CLASSES, IpStat, Stats, classify, marker
from .text import clip, vlen


# filter key -> status class ("all" shows everything).
FILTER_KEYS = {
    "a": "all", "A": "all", "0": "all",
    "2": "2xx", "3": "3xx", "4": "4xx", "5": "5xx",
}


# Escape sequences for the navigation keys (normal and application cursor mode).
KEY_SEQS = {
    "\x1b[A": "up", "\x1b[B": "down", "\x1bOA": "up", "\x1bOB": "down",
    "\x1b[C": "right", "\x1b[D": "left", "\x1bOC": "right", "\x1bOD": "left",
    "\x1b[5~": "pgup", "\x1b[6~": "pgdn",
    "\x1b[H": "home", "\x1b[F": "end", "\x1bOH": "home", "\x1bOF": "end",
    "\x1b[1~": "home", "\x1b[4~": "end",
}


_KEY_SEQ_RE = re.compile(r"\x1b(\[[0-9;]*[A-Za-z~]|O[A-Za-z])")


# Keys that move the cursor (IP pane) or scroll (request pane), whichever has focus.
NAV_KEYS = ("up", "k", "down", "j", "pgup", "pgdn", "home", "end")


SPARK_CHARS = "▁▂▃▄▅▆▇█"


def parse_keys(text: str) -> list:
    """Split raw terminal input into key names: printable characters as-is,
    plus "up"/"down"/"left"/"right"/"pgup"/"pgdn"/"home"/"end", "tab",
    "enter", and "esc" (a lone ESC). Unknown escape sequences are dropped."""
    keys, i = [], 0
    while i < len(text):
        ch = text[i]
        if ch == "\x1b":
            m = _KEY_SEQ_RE.match(text, i)
            if m:
                keys.append(KEY_SEQS.get(m.group(0), ""))
                i = m.end()
                continue
            keys.append("esc")
        else:
            keys.append({"\t": "tab", "\n": "enter", "\r": "enter"}.get(ch, ch))
        i += 1
    return [k for k in keys if k]


def fmt_duration(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60:02d}s"
    return f"{s // 3600}h{s // 60 % 60:02d}m"


class RateMeter:
    """Requests per second over a sliding ``WINDOW`` (one bucket per second),
    plus a sparkline of the same window.

    Arrival time, not log time, is what's measured, so a ``--from-start``
    backlog would look like one enormous burst; the caller calls ``reset()``
    once the backlog is drained (the follower's first idle tick)."""

    WINDOW = 60

    def __init__(self):
        self.reset()

    def reset(self) -> None:
        self._start = time.monotonic()
        self._buckets: deque = deque()  # [second, count], oldest first

    def add(self) -> None:
        sec = int(time.monotonic())
        if self._buckets and self._buckets[-1][0] == sec:
            self._buckets[-1][1] += 1
        else:
            self._buckets.append([sec, 1])
        self._trim(sec)

    def _trim(self, sec: int) -> None:
        while self._buckets and self._buckets[0][0] <= sec - self.WINDOW:
            self._buckets.popleft()

    def rate(self) -> float:
        now = time.monotonic()
        self._trim(int(now))
        span = min(self.WINDOW, max(now - self._start, 1.0))
        return sum(c for _, c in self._buckets) / span

    def bins(self, width: int) -> list:
        """Counts for ``width`` equal slices of the window, oldest first."""
        sec = int(time.monotonic())
        per = self.WINDOW / width
        out = [0] * width
        for s, c in self._buckets:
            idx = width - 1 - int((sec - s) // per)
            if 0 <= idx < width:
                out[idx] += c
        return out


class Screen:
    """Interactive full-terminal view (htop-style), drawn on the alternate
    screen:

    - a one-line header: file, uptime, totals, rolling rate + sparkline, and
      per-class counts (segments drop off on narrow terminals);
    - an *IP pane*: one entry per client IP, two lines each — stats (hits,
      per-class counts with zeros as a dim ``·``, last seen, a ``⚠`` for likely
      scanners), then the owner from ``OwnerResolver`` on a ``└─`` connector;
    - a *request pane*: the newest requests, all IPs or just the followed one,
      scrollable back through ``history``;
    - a footer listing the keys that work right now.

    ``layout`` is "split" (both panes), "ips", or "stream"; ``tab`` cycles it.
    The navigation keys (``NAV_KEYS``) act on the focused pane: in "split"
    ``←``/``→`` switch ``focus``; "ips" and "stream" have only one pane. In the
    IP pane they move a cursor (tracked by IP, not by row, so it stays on the
    same address as the order shifts); in the request pane they scroll back
    (``_req_back`` = matching requests hidden below the view, 0 = live — new
    matches bump it so a scrolled view stays put; ``end`` goes live again).
    ``enter`` follows the selected IP in the request pane, ``esc`` goes back
    to all IPs.

    Drawing: every frame is composed as a list of lines and only lines that
    changed since the last frame are rewritten (each ends with erase-to-EOL, so
    nothing blanks first and there's no flicker). Autowrap is off for the
    session and every line is clipped to ``cols - 1``, so nothing can wrap or
    scroll. Frames are throttled to ``FRAME_INTERVAL`` for data changes, redrawn
    immediately for keys, and at least every ``HEARTBEAT`` so the clock and the
    rate stay live when the log is idle.

    Resizes stay async-signal-safe: the SIGWINCH handler (``mark_resized``) only
    flips a flag — it must NOT write to stdout, because a signal can fire
    mid-write and re-entering the buffered writer raises ``RuntimeError:
    reentrant call``. ``service()``, called by the main loop after each row and
    on each idle tick, does the redraw.
    """

    MIN_COLS, MIN_ROWS = 64, 12
    FRAME_INTERVAL = 0.2  # seconds between data-driven redraws
    HEARTBEAT = 1.0  # max seconds between redraws (clock / rate)
    SPLIT_IPS = 0.55  # share of the body given to the IP pane in "split"
    SPARK_WIDTH = 15  # 4 s per character over the 60 s window
    IP_COL_MIN, IP_COL_MAX = 15, 39  # dotted IPv4 .. full IPv6
    # Visible width of an IP stats line minus the IP column:
    # cursor(2) sp hits(6) counts(4x5) sp(2) last(8) sp(2) flag(1)
    STATS_FIXED = 2 + 1 + 6 + 4 * 5 + 2 + 8 + 2 + 1
    OWNER_INDENT = "  └─ "  # owner line: hangs off the IP above it
    LAYOUTS = ("split", "ips", "stream")

    def __init__(self, p: Palette, stats: Stats, resolver: OwnerResolver,
                 log_path: str, layout: str = "split", suspect: int = 10,
                 keys: bool = True, history_size: int = 5000):
        self.p = p
        self.stats = stats
        self.resolver = resolver
        self.log_path = log_path
        self.layout = layout
        self.suspect = suspect  # 4xx hits (with no 2xx) that flag an IP; 0 = off
        self.keys = keys  # whether keyboard input works (for the footer)
        self.history: deque = deque(maxlen=history_size)  # Records
        self.meter = RateMeter()
        self.start_ts = time.monotonic()
        self.filter = "all"
        self.sort = "recent"  # IP pane order: "recent" or "hits"
        self.selected = None  # IP under the cursor (None = no cursor)
        self.follow = None  # IP the request pane is narrowed to
        self.focus = "ips"  # pane the navigation keys drive in "split"
        self.cols, self.rows = 80, 24
        self.active = False
        self._ip_offset = 0  # first IP entry shown (scrolls with the cursor)
        self._ip_fit = 1  # IP entries that fit, for page up/down
        self._req_back = 0  # matching requests below the view (0 = live)
        self._req_fit = 1  # request rows that fit, for page up/down
        self._entries_key = None  # memo for _ip_entries()
        self._entries: list = []
        self._frame: list[str] = []  # lines currently on screen
        self._dirty = True
        self._last_draw = 0.0
        self._resized = False
        self._backlog_reset = False

    # ---- lifecycle ----
    def start(self) -> None:
        # Alternate screen, hide cursor, autowrap off.
        sys.stdout.write("\033[?1049h\033[?25l\033[?7l")
        self.active = True
        self._full_redraw()

    def stop(self) -> None:
        """Restore the terminal (main screen, cursor, autowrap) so the exit
        summary prints normally."""
        if self.active:
            sys.stdout.write("\033[0m\033[?7h\033[?25h\033[?1049l")
            sys.stdout.flush()
        self.active = False

    def mark_resized(self, *_) -> None:
        """SIGWINCH handler. Only sets a flag — no stdout I/O here (see class
        docstring); ``service()`` performs the redraw from the main loop."""
        self._resized = True

    # ---- input from the main loop ----
    def add(self, rec: Record) -> None:
        """A new parsed record (already counted in ``stats``)."""
        self.history.append(rec)
        if self._req_back and self._shows(rec):
            self._req_back += 1  # scrolled back: keep the same requests in view
        self.meter.add()
        self._dirty = True

    def backlog_done(self) -> None:
        """First idle tick: the startup backlog is drained, so restart the rate
        window rather than report the backlog as a burst."""
        if not self._backlog_reset:
            self._backlog_reset = True
            self.meter.reset()

    def service(self) -> None:
        """Apply a pending resize, or redraw if the frame is due."""
        if not self.active:
            return
        if self._resized:
            self._resized = False
            self._full_redraw()
            return
        since = time.monotonic() - self._last_draw
        if (((self._dirty or self.resolver.updated) and since >= self.FRAME_INTERVAL)
                or since >= self.HEARTBEAT):
            self.draw()

    def handle_input(self, text: str) -> None:
        for key in parse_keys(text):
            self.handle_key(key)

    def handle_key(self, key: str) -> None:
        """Apply one key and redraw immediately. Raises KeyboardInterrupt on
        quit so the normal exit path (restore terminal + summary) runs."""
        if key in ("q", "Q"):
            raise KeyboardInterrupt
        if key in FILTER_KEYS:
            self.filter = FILTER_KEYS[key]
            self._req_back = 0  # a different set of requests: back to live
        elif key in ("tab", "g", "G"):
            i = self.LAYOUTS.index(self.layout)
            self.layout = self.LAYOUTS[(i + 1) % len(self.LAYOUTS)]
        elif key in ("s", "S"):
            self.sort = "hits" if self.sort == "recent" else "recent"
        elif key in NAV_KEYS:
            if self._focused() == "requests":
                self._scroll(key)
            else:
                self._navigate(key)
        elif key in ("left", "right", "h", "l"):
            if self.layout != "split":
                return  # only one pane to focus
            self.focus = "requests" if self.focus == "ips" else "ips"
        elif key == "enter":
            if self.layout == "stream":
                return  # no IP pane to pick from
            if self.selected is None:
                self._move(0)  # nothing selected yet: take the top entry
            if self.selected is not None:
                self.follow = self.selected
                self._req_back = 0
                if self.layout == "ips":
                    self.layout = "split"  # so the followed requests are visible
        elif key == "esc":
            self.follow = self.selected = None
            self._req_back = 0
        else:
            return
        self.draw()

    def _focused(self) -> str:
        """The pane the navigation keys drive: "ips" or "requests"."""
        return {"ips": "ips", "stream": "requests"}.get(self.layout, self.focus)

    def _navigate(self, key: str) -> None:
        """A navigation key in the IP pane: move the cursor."""
        if key in ("up", "k"):
            self._move(-1)
        elif key in ("down", "j"):
            self._move(1)
        elif key == "pgup":
            self._move(-self._ip_fit)
        elif key == "pgdn":
            self._move(self._ip_fit)
        elif key == "home":
            self._jump(0)
        else:
            self._jump(-1)

    def _scroll(self, key: str) -> None:
        """A navigation key in the request pane: scroll back (up) or toward
        the newest (down). ``_request_pane()`` clamps to what's in history."""
        if key == "home":
            back = len(self.history)
        elif key == "end":
            back = 0
        else:
            step = {"up": 1, "k": 1, "down": -1, "j": -1,
                    "pgup": self._req_fit, "pgdn": -self._req_fit}[key]
            back = self._req_back + step
        self._req_back = max(0, min(back, len(self.history)))

    def _move(self, delta: int) -> None:
        ips = [ip for ip, _ in self._ip_entries()]
        if not ips:
            return
        if self.selected in ips:
            idx = ips.index(self.selected) + delta
        else:
            idx = 0  # first press puts the cursor on the top entry
        self.selected = ips[max(0, min(idx, len(ips) - 1))]

    def _jump(self, idx: int) -> None:
        """Put the cursor on entry ``idx`` (0 = top, -1 = bottom)."""
        ips = [ip for ip, _ in self._ip_entries()]
        if ips:
            self.selected = ips[idx]

    # ---- drawing ----
    def _full_redraw(self) -> None:
        try:
            size = os.get_terminal_size()
            self.cols, self.rows = size.columns, size.lines
        except OSError:
            self.cols, self.rows = 80, 24
        self._frame = []
        sys.stdout.write("\033[0m\033[2J")
        self.draw()

    def draw(self) -> None:
        """Compose the frame and rewrite only the lines that changed."""
        if not self.active:
            return
        self.resolver.updated = False  # this frame picks up any new owners
        p = self.p
        lines = [clip(line, self.cols - 1, p.RESET) for line in self._compose()]
        lines = (lines + [""] * self.rows)[: self.rows]
        out = []
        for i, line in enumerate(lines):
            if i < len(self._frame) and self._frame[i] == line:
                continue
            out.append(f"\033[{i + 1};1H{line}{p.RESET}\033[K")
        self._frame = lines
        if out:
            sys.stdout.write("".join(out))
            sys.stdout.flush()
        self._dirty = False
        self._last_draw = time.monotonic()

    def _compose(self) -> list:
        if self.cols < self.MIN_COLS or self.rows < self.MIN_ROWS:
            return [f"Terminal too small ({self.cols}x{self.rows}); "
                    f"need at least {self.MIN_COLS}x{self.MIN_ROWS}."]
        width = self.cols - 1
        body = self.rows - 2  # minus header and footer
        lines = [self._header(width)]
        if self.layout == "split":
            ip_h = max(4, int(body * self.SPLIT_IPS))
            lines += self._ip_pane(ip_h, width)
            lines += self._request_pane(body - ip_h, width)
        elif self.layout == "ips":
            lines += self._ip_pane(body, width)
        else:
            lines += self._request_pane(body, width)
        lines.append(self._footer(width))
        return lines

    def _match(self, cls: str) -> bool:
        return self.filter == "all" or cls == self.filter

    def _rule(self, width: int, title: str, details: str = "",
              right: str = "", pane: str = "") -> str:
        """Pane divider: ``─ Title · details ─────── right ─``. In "split" the
        title of the pane without focus is dimmed."""
        p = self.p
        left = f"─ {title}" + (f" · {details}" if details else "") + " "
        tail = f" {right} ─" if right else ""
        fill = "─" * max(width - len(left) - len(tail), 1)
        unfocused = self.layout == "split" and pane and pane != self.focus
        return (
            f"{p.DIM}─ {p.RESET}{p.DIM if unfocused else p.BOLD}{title}{p.RESET}"
            f"{p.DIM}{(' · ' + details) if details else ''} {fill}{tail}{p.RESET}"
        )

    def _header(self, width: int) -> str:
        p = self.p
        c = self.stats.classes
        classes = "  ".join(
            f"{getattr(p, attr)}{key} {c.get(key, 0):,}{p.RESET}"
            for key, _label, attr in CLASSES[:4]
        )
        bins = self.meter.bins(self.SPARK_WIDTH)
        top = max(bins) or 1
        spark = "".join(
            f"{p.GREEN}{SPARK_CHARS[min(int(n / top * 7.999), 7)]}{p.RESET}"
            if n else f"{p.DIM}{SPARK_CHARS[0]}{p.RESET}"
            for n in bins
        )
        parts = {
            "title": f"{p.BOLD}{p.WHITE}CADDY MONITOR{p.RESET}",
            "file": f"{p.DIM}{os.path.basename(self.log_path) or self.log_path}{p.RESET}",
            "uptime": f"{p.DIM}up {fmt_duration(time.monotonic() - self.start_ts)}{p.RESET}",
            "total": (f"{p.WHITE}{self.stats.total:,}{p.RESET} req  "
                      f"{p.WHITE}{self.meter.rate():.1f}{p.RESET}/s"),
            "spark": spark,
            "classes": classes,
        }
        sep = f" {p.DIM}│{p.RESET} "
        groups = (("title", "file", "uptime"), ("total", "spark"), ("classes",))
        # Drop the least useful segments first until the line fits.
        for drop in ("", "file", "spark", "uptime", "title", "classes"):
            parts.pop(drop, None)
            line = " " + sep.join(
                "  ".join(parts[k] for k in g if k in parts)
                for g in groups if any(k in parts for k in g)
            )
            if vlen(line) <= width:
                break
        return line

    def _footer(self, width: int) -> str:
        p = self.p
        if not self.keys:
            return (f" {p.DIM}keys need a POSIX terminal on stdin · "
                    f"layout: {self.layout} · Ctrl+C quits{p.RESET}")
        # (key, label, short label); tighten spacing, then shorten the labels,
        # before anything has to be clipped.
        keys = []
        if self._focused() == "requests":
            keys.append(("↑↓", "scroll", "scroll"))
        else:
            keys.append(("↑↓", "select", "move"))
        if self.layout == "split":
            keys.append(("←→", "pane", "pane"))
        if self.layout != "stream":
            keys.append(("⏎", "follow IP", "follow"))
        if self._req_back and self.layout != "ips":
            keys.append(("end", "latest", ""))  # short: the pane title says it
        if self.follow or self.selected:
            keys.append(("esc", "all IPs", ""))  # short: the pane title says it
        keys += [("tab", "layout", "view"), ("a/2-5", "filter", "filter"),
                 ("s", "sort", ""), ("q", "quit", "quit")]  # sort: least needed
        for gap, short in (("   ", False), ("  ", False), ("  ", True)):
            line = " " + gap.join(
                f"{p.BOLD}{k}{p.RESET} {p.DIM}{s if short else d}{p.RESET}"
                for k, d, s in keys
                if d and (s or not short)  # empty short label: drop when short
            )
            if vlen(line) <= width:
                break
        return line

    # ---- IP pane ----
    def _ip_entries(self) -> list:
        """(ip, IpStat) pairs: filtered by status class, sorted by most recent
        hit or by hit count (the filtered class's count when a filter is on).
        Memoised until a record arrives (``stats.total`` changes; that's also
        when ``Stats`` prunes) or the filter/sort changes, so idle frames and
        key presses don't re-sort every IP. Treat the result as read-only."""
        memo_key = (self.stats.total, self.filter, self.sort)
        if memo_key == self._entries_key:
            return self._entries
        if self.filter == "all":
            items = list(self.stats.ips.items())
        else:
            items = [kv for kv in self.stats.ips.items()
                     if kv[1].classes.get(self.filter, 0)]
        if self.sort == "hits":
            if self.filter == "all":
                key = lambda kv: (kv[1].hits, kv[1].last_seq)
            else:
                key = lambda kv: (kv[1].classes[self.filter], kv[1].last_seq)
        else:
            key = lambda kv: kv[1].last_seq
        items.sort(key=key, reverse=True)
        self._entries_key, self._entries = memo_key, items
        return items

    def _is_suspect(self, st: IpStat) -> bool:
        """Scanner pattern: lots of client errors and nothing successful."""
        return (self.suspect > 0 and st.classes.get("4xx", 0) >= self.suspect
                and not st.classes.get("2xx", 0))

    def _ip_pane(self, height: int, width: int) -> list:
        p = self.p
        entries = self._ip_entries()
        ips = [ip for ip, _ in entries]
        if self.selected is not None and self.selected not in ips:
            self.selected = None  # filtered out (or never seen)
        fit = max((height - 2) // 2, 1)  # rule + column header, 2 lines per IP
        self._ip_fit = fit
        if self.selected is not None:  # keep the cursor on screen
            idx = ips.index(self.selected)
            if idx < self._ip_offset:
                self._ip_offset = idx
            elif idx >= self._ip_offset + fit:
                self._ip_offset = idx - fit + 1
        self._ip_offset = max(0, min(self._ip_offset, len(entries) - fit))
        shown = entries[self._ip_offset: self._ip_offset + fit]

        filt = "all codes" if self.filter == "all" else self.filter
        right = (f"{self._ip_offset + 1}–{self._ip_offset + len(shown)} of {len(entries)}"
                 if len(entries) > fit else "")
        widest = max((len(ip) for ip, _ in shown), default=0)
        w = max(self.IP_COL_MIN,
                min(widest, self.IP_COL_MAX, width - self.STATS_FIXED))
        lines = [
            self._rule(width, f"IPs {len(entries)}", f"by {self.sort} · {filt}", right,
                       pane="ips"),
            f"  {p.BOLD}{'IP ADDRESS':<{w}} {'HITS':>6}"
            f"{'2xx':>5}{'3xx':>5}{'4xx':>5}{'5xx':>5}  {'LAST':<8}{p.RESET}",
        ]
        for ip, st in shown:
            lines.extend(self._ip_rows(ip, st, w, width))
        if not entries:
            what = "requests yet" if self.filter == "all" else "matching IPs"
            lines.append(f"  {p.DIM}(no {what}){p.RESET}")
        return (lines + [""] * height)[:height]

    def _ip_rows(self, ip: str, st: IpStat, w: int, width: int) -> tuple:
        """The two lines for one IP: stats, then its owner beneath."""
        p = self.p
        selected = ip == self.selected
        cursor = f"{p.BOLD}{p.WHITE}▶{p.RESET} " if selected else "  "
        shown = ip if len(ip) <= w else ip[: w - 1] + "…"
        counts = "".join(
            f"{getattr(p, attr)}{st.classes[key]:>5,}{p.RESET}"
            if st.classes.get(key, 0) else f"{p.DIM}{'·':>5}{p.RESET}"
            for key, _label, attr in CLASSES[:4]
        )
        flags = f"  {p.BRIGHT_RED}⚠{p.RESET}" if self._is_suspect(st) else ""
        if ip == self.follow:
            flags += f"  {p.DIM}◀ following{p.RESET}"
        owner = self.resolver.lookup(ip)
        if owner is None:
            text = "resolving…"
        elif owner:
            text = owner
        else:
            text = "-" if self.resolver.enabled else "(lookups off)"
        return (
            f"{cursor}{p.BOLD if selected else ''}{p.CYAN}{shown:<{w}}{p.RESET} "
            f"{p.WHITE}{st.hits:>6,}{p.RESET}{counts}  "
            f"{p.DIM}{st.last_time[11:]:<8}{p.RESET}{flags}",
            f"{p.DIM}{self.OWNER_INDENT}{p.RESET}{text}",
        )

    # ---- request pane ----
    def _shows(self, rec: Record) -> bool:
        """Whether the request pane's filter and ``follow`` let ``rec`` in."""
        return self._match(classify(rec.status)) and (
            self.follow is None or rec.ip == self.follow)

    def _request_pane(self, height: int, width: int) -> list:
        p = self.p
        want = max(height - 1, 0)
        self._req_fit = max(want, 1)
        # Newest first. Live, stop once the pane is full; scrolled back, take
        # every match (for the position and the clamp: history may have dropped
        # the oldest ones, or the filter shrunk the set).
        matches = []
        for rec in reversed(self.history):
            if not self._req_back and len(matches) >= want:
                break
            if self._shows(rec):
                matches.append(rec)
        back = self._req_back = max(0, min(self._req_back, len(matches) - want))
        recs = matches[back: back + want]
        recs.reverse()  # oldest at the top, newest at the bottom

        filt = "all codes" if self.filter == "all" else self.filter
        who = self.follow or "all IPs"
        if back:
            last = len(matches) - back
            right = f"{last - len(recs) + 1:,}–{last:,} of {len(matches):,}"
        else:
            right = "esc: all IPs" if self.follow else ""
        lines = [self._rule(width, "Requests", f"{who} · {filt}"
                            + (" · paused" if back else ""), right, pane="requests")]
        ip_w = max([self.IP_COL_MIN] + [len(r.ip) for r in recs])
        ip_w = min(ip_w, self.IP_COL_MAX)
        for rec in recs:
            color = p.style_for(rec.status)
            ip_col = "" if self.follow else f"{p.CYAN}{rec.ip:<{ip_w}}{p.RESET} "
            lines.append(
                f"  {p.DIM}{rec.time[11:]:<8}{p.RESET}  "
                f"{color}{marker(rec.status)} {rec.status:<3}{p.RESET}  "
                f"{p.WHITE}{rec.method:<6}{p.RESET} {ip_col}{p.DIM}{rec.uri}{p.RESET}"
            )
        if not recs:
            lines.append(f"  {p.DIM}(no matching requests in the recent buffer){p.RESET}")
        return (lines + [""] * height)[:height]
