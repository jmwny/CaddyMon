"""Who owns an IP: RDAP lookups against the regional registries (via IANA's
bootstrap files), strictly rate limited, with a persistent range cache, plus
reverse DNS. See the "RDAP rate limits" section of CLAUDE.md before changing
anything that sends requests."""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import queue
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from contextlib import contextmanager
from email.utils import parsedate_to_datetime

from .text import clean


def offline_label(addr) -> str | None:
    """Label for addresses that need no registry lookup (None = public)."""
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_private:
        return "private network"
    if not addr.is_global:
        return "reserved"
    return None


def _vcard_fn(entity: dict) -> str | None:
    """The formatted name ("fn") from an RDAP entity's jCard, if present."""
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
        for prop in vcard[1]:
            if (isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn"
                    and isinstance(prop[3], str) and prop[3].strip()):
                return clean(prop[3].strip())
    return None


def _rdap_org(data: dict) -> str | None:
    """Best owner name from an RDAP ip-network response: the registrant
    entity's name (searched breadth-first through nested entities), falling back
    to the network name (e.g. ``GOOGLE``)."""
    queue_ = list(data.get("entities") or [])
    while queue_:
        ent = queue_.pop(0)
        if not isinstance(ent, dict):
            continue
        if "registrant" in (ent.get("roles") or []):
            fn = _vcard_fn(ent)
            if fn:
                return fn
        queue_.extend(ent.get("entities") or [])
    name = data.get("name")
    return clean(name) if isinstance(name, str) and name else None


class RateLimited(Exception):
    """A host can't be asked right now: it answered 429/503/403, or our own
    pacing would make a worker wait more than ``MAX_WAIT``. ``retry_in`` is how
    many seconds until asking again is worthwhile."""

    def __init__(self, host: str, retry_in: float):
        super().__init__(host)  # str(exc) names the host
        self.retry_in = retry_in


def retry_after_seconds(value, default: float = 60.0,
                        cap: float = 3600.0) -> float:
    """Parse a ``Retry-After`` header (delta-seconds or an HTTP date)."""
    if value:
        value = value.strip()
        try:
            secs = float(value)
        except ValueError:
            try:
                when = parsedate_to_datetime(value)
                secs = when.timestamp() - time.time()
            except (TypeError, ValueError, IndexError, OverflowError):
                secs = default
        return max(1.0, min(secs, cap))
    return default


class RateLimiter:
    """Per-host request pacing shared by all resolver threads.

    Each host has one or more ``(requests, window_seconds)`` rules, enforced as
    sliding windows over the times requests were *sent*; every window is
    stretched by ``MARGIN`` so network jitter can't push two requests into the
    server's window. ``backoff()`` (after a 429/503) blocks a host outright
    until its ``Retry-After`` has passed. ``acquire()`` blocks the calling
    worker thread until a request to ``host`` is allowed, then records it.

    Use ``slot(host)`` around a request: it also allows only one request in
    flight per host, so a 429 is always seen (and its backoff applied) before
    the next request to that host can start.
    """

    MARGIN = 1.1

    def __init__(self, rules: dict, default: list):
        self._rules = rules
        self._default = default
        self._sent: dict = {}  # host -> deque of monotonic send times
        self._blocked: dict = {}  # host -> monotonic time the backoff ends
        self._in_flight: dict = {}  # host -> Lock held for the request
        self._lock = threading.Lock()

    @contextmanager
    def slot(self, host: str):
        with self._lock:
            host_lock = self._in_flight.setdefault(host, threading.Lock())
        with host_lock:
            self.acquire(host)
            yield

    def rules(self, host: str) -> list:
        return self._rules.get(host, self._default)

    def delay(self, host: str) -> float:
        """Seconds until a request to ``host`` would be allowed (0 = now)."""
        # Locked: another worker's acquire() may be appending to (or trimming)
        # this host's send times, and iterating a deque mid-change raises.
        with self._lock:
            return self._delay(host)

    def _delay(self, host: str) -> float:  # caller holds the lock
        now = time.monotonic()
        wait = self._blocked.get(host, 0.0) - now
        sent = self._sent.get(host, ())
        for limit, window in self.rules(host):
            window *= self.MARGIN
            recent = [t for t in sent if t > now - window]
            if len(recent) >= limit:
                # Allowed once the oldest of the last `limit` sends ages out.
                wait = max(wait, recent[-limit] + window - now)
        return max(wait, 0.0)

    def acquire(self, host: str) -> None:
        while True:
            with self._lock:
                wait = self._delay(host)
                if wait <= 0:
                    sent = self._sent.setdefault(host, deque())
                    now = time.monotonic()
                    sent.append(now)
                    longest = max(w for _, w in self.rules(host)) * self.MARGIN
                    while sent and sent[0] <= now - longest:
                        sent.popleft()
                    return
            # Re-check at least every second: a backoff may land meanwhile.
            time.sleep(min(wait, 1.0))

    def backoff(self, host: str, seconds: float) -> None:
        with self._lock:
            until = time.monotonic() + seconds
            self._blocked[host] = max(self._blocked.get(host, 0.0), until)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Surface redirects as HTTPError so each hop can be rate-limited."""

    def redirect_request(self, *args, **kwargs):
        return None


class RangeCache:
    """Network range -> owner, learned from RDAP answers, optionally persisted
    to a JSON file so later runs don't repeat the lookups.

    An RDAP answer describes the whole registered block (``startAddress`` to
    ``endAddress``), so one query covers every IP in it. Only these ranges are
    stored, never individual client IPs. Entries expire: ``TTL_FOUND`` for a
    named owner, ``TTL_EMPTY`` when the registry had the block but no name.
    Failures and rate-limited answers are never stored.

    Saving is at most every ``SAVE_EVERY`` seconds while running, plus once on
    exit. Each save merges with what's on disk (another instance may have
    written since), drops expired entries, and writes a temp file that replaces
    the old one, created owner-only (0600) because it records which networks
    hit the server. A failed save (e.g. a read-only directory) disables further
    saves and is reported via ``error``; the in-memory cache keeps working.
    With ``path=None`` the cache is memory-only.
    """

    TTL_FOUND = 30 * 86400
    TTL_EMPTY = 86400
    SAVE_EVERY = 60.0
    MAX_ENTRIES = 50000
    VERSION = 1

    def __init__(self, path: str | None = None):
        self.path = path
        self.error: str | None = None  # why saving failed, reported on exit
        self._nets: dict = {}  # ip_network -> (owner or None, expires epoch)
        # Prefix lengths present, per IP version, longest first: get() probes
        # one dict key per length instead of scanning every range.
        self._prefixes: dict = {4: [], 6: []}
        self._lock = threading.Lock()
        self._save_lock = threading.Lock()
        self._dirty = False
        self._last_save = time.monotonic()
        # Bumped whenever the ranges change, so callers can memoise get()
        # answers until there's something new (OwnerResolver.lookup does).
        self.generation = 0

    def _store(self, net, value) -> None:  # caller holds the lock
        self.generation += 1
        self._nets[net] = value
        lengths = self._prefixes[net.version]
        if net.prefixlen not in lengths:
            lengths.append(net.prefixlen)
            lengths.sort(reverse=True)

    def get(self, addr):
        """``(hit, owner)`` from the most specific unexpired range holding
        ``addr``; owner is None for a known block with no name."""
        now = time.time()
        with self._lock:
            for plen in self._prefixes[addr.version]:
                value = self._nets.get(ipaddress.ip_network((addr, plen), strict=False))
                if value is not None and value[1] > now:
                    return True, value[0]
        return False, None

    def put(self, nets, owner: str | None) -> None:
        expires = time.time() + (self.TTL_FOUND if owner else self.TTL_EMPTY)
        with self._lock:
            for net in nets:
                self._store(net, (owner, expires))
            self._dirty = True
        if time.monotonic() - self._last_save >= self.SAVE_EVERY:
            self.save()

    def _read(self) -> dict:
        """Unexpired, well-formed entries from the file ({} if it's missing,
        unreadable, or corrupt — it's only a cache)."""
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return {}
        nets = data.get("networks") if isinstance(data, dict) else None
        if not isinstance(nets, dict):
            return {}
        now = time.time()
        out = {}
        for cidr, value in nets.items():
            try:
                owner, expires = value
                net = ipaddress.ip_network(cidr)
                expires = float(expires)
            except (TypeError, ValueError):
                continue
            if expires > now and (owner is None or isinstance(owner, str)):
                out[net] = (clean(owner) if owner else None, expires)
        return out

    def load(self) -> int:
        """Load the file (if any); returns how many ranges were loaded."""
        if not self.path:
            return 0
        entries = self._read()
        with self._lock:
            for net, value in entries.items():
                if net not in self._nets or value[1] > self._nets[net][1]:
                    self._store(net, value)
        return len(entries)

    def save(self) -> None:
        if not self.path or self.error:
            return
        with self._save_lock:
            with self._lock:
                if not self._dirty:
                    return
                self._dirty = False
                self._last_save = time.monotonic()
                mine = dict(self._nets)
            merged = self._read()  # keep what another instance saved
            for net, value in mine.items():
                if net not in merged or value[1] > merged[net][1]:
                    merged[net] = value
            now = time.time()
            live = sorted(((n, v) for n, v in merged.items() if v[1] > now),
                          key=lambda kv: kv[1][1], reverse=True)[: self.MAX_ENTRIES]
            payload = {
                "version": self.VERSION,
                "networks": {str(n): [owner, int(exp)] for n, (owner, exp) in live},
            }
            tmp = f"{self.path}.{os.getpid()}.tmp"
            try:
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(payload, f, separators=(",", ":"))
                os.replace(tmp, self.path)
            except OSError as e:
                self.error = e.strerror or str(e)
                try:
                    os.remove(tmp)
                except OSError:
                    pass


class RdapBootstrap:
    """IANA's RDAP bootstrap registry for IP addresses (RFC 9224): which
    regional registry's RDAP server is authoritative for which block.

    Querying the registry directly (instead of via rdap.org's redirect) halves
    the requests per lookup, and it tells us the target host *before* sending
    anything, so a host that's backing off can be skipped without spending a
    request (rdap.org itself suggests heavy users consume the bootstrap files).
    Each file is fetched once per run, lazily, through the resolver's rate-
    limited fetcher; if a fetch fails it's retried after ``RETRY_AFTER`` and
    ``base_url()`` returns None meanwhile (the caller falls back to rdap.org).
    Registries still redirect for space transferred between them, which the
    resolver's hand-followed redirects handle.
    """

    RETRY_AFTER = 600

    def __init__(self, urls: dict, fetch_json):
        self._urls = urls  # {4: url, 6: url}; empty = disabled
        self._fetch_json = fetch_json
        self._table: dict = {}  # version -> [(ip_network, base_url)], longest first
        self._retry_at: dict = {}
        self._lock = threading.Lock()

    def base_url(self, addr) -> str | None:
        """Registry RDAP base URL (ending in "/") for ``addr``, or None."""
        version = addr.version
        url = self._urls.get(version)
        if not url:
            return None
        with self._lock:  # one fetch per version; others wait briefly for it
            if (version not in self._table
                    and time.monotonic() >= self._retry_at.get(version, 0.0)):
                try:
                    self._table[version] = self._parse(self._fetch_json(url))
                except Exception:  # network, JSON, rate limit: fall back for now
                    self._retry_at[version] = time.monotonic() + self.RETRY_AFTER
            table = self._table.get(version, ())
        for net, base in table:
            if addr in net:
                return base
        return None

    @staticmethod
    def _parse(data) -> list:
        """``services`` entries are ``[[prefixes...], [urls...]]``; prefer an
        https URL. Returns [(network, base_url)] sorted most specific first."""
        table = []
        for service in data.get("services") or []:
            try:
                prefixes, urls = service[0], service[1]
                base = next((u for u in urls if u.startswith("https://")), urls[0])
            except (TypeError, IndexError, KeyError, AttributeError, StopIteration):
                continue
            if not isinstance(base, str):
                continue
            base = base if base.endswith("/") else base + "/"
            for prefix in prefixes:
                try:
                    table.append((ipaddress.ip_network(prefix), base))
                except (TypeError, ValueError):
                    continue
        if not table:
            raise ValueError("empty RDAP bootstrap file")
        table.sort(key=lambda item: item[0].prefixlen, reverse=True)
        return table


class OwnerResolver:
    """Background "who owns this IP" lookups: RDAP (registry org + country)
    plus reverse DNS, cached per IP.

    ``lookup()`` never blocks: it returns what is known now (or None while a
    lookup is in flight) and queues the IP for the worker threads. Workers never
    touch stdout; they just fill the cache and set ``updated`` so the main loop
    knows to redraw. RDAP answers carry the network's address range, which goes
    into ``RangeCache`` (``ranges``, optionally persisted across runs), so other
    IPs from the same block — and repeat visitors on later runs — cost no query.
    Ordinary failures are retried after ``RETRY_AFTER`` seconds.

    Being a polite RDAP client (the registries publish rate limits and ban
    clients that ignore them):

    - Each IP is sent straight to its registry using IANA's bootstrap files
      (``RdapBootstrap``); rdap.org (a redirecting bootstrap service) is only
      the fallback. Redirects are followed by hand so *each* hop goes through
      ``RateLimiter`` against its own host's limits (``RDAP_LIMITS``); unknown
      hosts get ``RDAP_DEFAULT_LIMIT``.
    - Workers never sit out a long wait. If a host is backing off (it answered
      429/503/403) or its pacing would hold a worker more than ``MAX_WAIT``
      seconds, the lookup is deferred: the IP gets a retry time and is picked up
      again when it's due and still on screen. So one throttled registry can't
      stall lookups to the others.
    - The queue is LIFO, so what was just drawn is looked up first; an IP nobody
      has asked about for ``STALE_AFTER`` seconds (scrolled away) is dropped
      from the queue instead of costing a request; and concurrent lookups in
      the same /24 (/48) wait for the one already in flight.

    With ``enabled=False`` no network lookups happen at all; only the offline
    labels (private, loopback, ...) and owners already in ``ranges`` are shown.
    """

    RDAP_URL = "https://rdap.org/ip/"  # fallback: redirects to the registry
    # IANA's RDAP bootstrap files for IP space (RFC 9224). Empty = don't use.
    BOOTSTRAP_URLS = {
        4: "https://data.iana.org/rdap/ipv4.json",
        6: "https://data.iana.org/rdap/ipv6.json",
    }
    # Per-client limits as (requests, seconds) windows:
    # - rdap.org: "a maximum of 10 requests in 10 seconds" (about.rdap.org).
    # - LACNIC publishes no current numbers (its RDAP page only says the Whois
    #   restrictions apply). Historical figures: 100/5 min + 1000/60 min (LACNIC,
    #   IETF weirds list, 2013) and 10/min (reported 2016). This keeps to the
    #   strictest of each.
    RDAP_LIMITS = {
        "rdap.org": [(10, 10)],
        "rdap.lacnic.net": [(10, 60), (1000, 3600)],
    }
    RDAP_DEFAULT_LIMIT = [(10, 10)]  # other registries: rdap.org's pace
    # Responses that mean "slow down": 429/503, plus 403, which LACNIC has used
    # for "rate limit exceeded" (RDAP data is public, so 403 has no other
    # common meaning here).
    RATE_LIMIT_CODES = (403, 429, 503)
    MAX_REDIRECTS = 3
    MAX_WAIT = 5.0  # longest a worker will wait on pacing before deferring
    STALE_AFTER = 30.0
    BLOCK_WAIT = 30.0  # max wait for a sibling lookup in the same /24 (/48)
    TIMEOUT = 8
    RETRY_AFTER = 300
    WORKERS = 3

    def __init__(self, enabled: bool, ranges: RangeCache | None = None):
        self.enabled = enabled
        self.ranges = ranges if ranges is not None else RangeCache()
        self.updated = False
        self._cache: dict[str, str] = {}
        # ip -> (ranges.generation, text): lookup()'s answer while pending
        self._provisional: dict = {}
        self._retry_at: dict[str, float] = {}  # ip -> monotonic time to retry
        self._pending: set[str] = set()
        self._wanted: dict[str, float] = {}  # ip -> last time lookup() asked
        self._inflight: dict = {}  # /24 or /48 -> Event set when its query ends
        self._lock = threading.Lock()
        self._queue: queue.Queue = queue.LifoQueue()
        self._limiter = RateLimiter(self.RDAP_LIMITS, self.RDAP_DEFAULT_LIMIT)
        self._opener = urllib.request.build_opener(_NoRedirect)
        self._bootstrap = RdapBootstrap(self.BOOTSTRAP_URLS, self._fetch_json)
        self._started = False

    @staticmethod
    def _parse(ip: str):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return addr

    def lookup(self, ip: str) -> str | None:
        """Owner text for ``ip``: cached result, an offline label or cached
        block owner, "" when nothing can be known, or None while a lookup is
        still pending.

        Called for every visible IP on every frame, so the local answers are
        memoised: with lookups off in ``_cache`` (the ranges can't change
        without lookups), and while a lookup is pending in ``_provisional``,
        keyed on ``ranges.generation`` so a sibling's new answer shows up."""
        cached = self._cache.get(ip)
        if not self.enabled:  # local knowledge only, no network
            if cached is None:
                addr = self._parse(ip)
                cached = self._cache[ip] = "" if addr is None else (
                    offline_label(addr) or self.ranges.get(addr)[1] or "")
            return cached
        if cached is None:
            addr = self._parse(ip)
            if addr is None:
                return ""
        now = time.monotonic()
        with self._lock:
            self._wanted[ip] = now  # still on screen
            retry_at = self._retry_at.get(ip)
            if retry_at is None:
                queue_it = cached is None
            else:
                queue_it = now >= retry_at  # failed or deferred: wait until due
            if queue_it and ip not in self._pending:
                self._pending.add(ip)
                self._retry_at.pop(ip, None)
                self._queue.put(ip)
                self._start_workers()
        if cached is not None:
            self._provisional.pop(ip, None)  # answered: the guess is done with
            return cached
        # Provisional while lookups run (the range lookup only happens here).
        generation = self.ranges.generation
        memo = self._provisional.get(ip)
        if memo is None or memo[0] != generation:
            memo = self._provisional[ip] = (
                generation, offline_label(addr) or self.ranges.get(addr)[1])
        return memo[1]

    def wait(self, ips, timeout: float) -> None:
        """Queue lookups for ``ips`` and wait (up to ``timeout``) for them."""
        if not self.enabled:
            return
        for ip in ips:
            self.lookup(ip)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and self._pending & set(ips):
            time.sleep(0.05)

    def forget(self, ips) -> None:
        """Drop per-IP state for IPs the stats no longer track (``Stats``
        prunes on long runs); block owners stay in ``ranges``."""
        with self._lock:
            for ip in ips:
                self._cache.pop(ip, None)
                self._provisional.pop(ip, None)
                self._retry_at.pop(ip, None)
                self._wanted.pop(ip, None)

    def _start_workers(self) -> None:  # caller holds the lock
        if self._started:
            return
        self._started = True
        for _ in range(self.WORKERS):
            threading.Thread(target=self._work, daemon=True).start()

    def _work(self) -> None:
        while True:
            ip = self._queue.get()
            with self._lock:
                stale = (time.monotonic() - self._wanted.get(ip, 0.0)
                         > self.STALE_AFTER)
                if stale:  # scrolled away: skip; re-queued if shown again
                    self._pending.discard(ip)
                    continue
            addr = self._parse(ip)
            org, ok, host = None, False, None
            try:
                # Registry owner first and published right away: reverse DNS
                # for an IP with no PTR record can stall ~10s in the resolver.
                org, ok = self._org(addr)
                if org:
                    self._cache[ip] = org
                    self.updated = True
                host = self._rdns(addr)
            except RateLimited as limited:
                # Deferred, not failed: keep whatever is shown, retry when the
                # host is expected to be free (if the IP is still on screen).
                with self._lock:
                    self._pending.discard(ip)
                    self._retry_at[ip] = time.monotonic() + limited.retry_in
                continue
            except Exception:  # never let a worker die
                pass
            text = " · ".join(part for part in (org, host) if part)
            with self._lock:
                self._cache[ip] = text or ("unknown" if ok else "lookup failed")
                self._pending.discard(ip)
                if not ok:
                    self._retry_at[ip] = time.monotonic() + self.RETRY_AFTER
            self.updated = True

    def _org(self, addr):
        """Return ``(org_or_None, ok)``; ok=False schedules a retry. Lets
        ``RateLimited`` through so the worker can defer the IP."""
        label = offline_label(addr)
        if label:
            return label, True
        hit, org = self.ranges.get(addr)
        if hit:
            return org, True  # org may be None: a known block with no name
        # One query per neighbourhood at a time: scanners hit many IPs from the
        # same subnet at once, and one answer usually covers them all.
        block = ipaddress.ip_network(
            f"{addr}/{24 if addr.version == 4 else 48}", strict=False)
        with self._lock:
            done = self._inflight.get(block)
            if done is None:
                self._inflight[block] = threading.Event()
        if done is not None:
            done.wait(self.BLOCK_WAIT)
            hit, org = self.ranges.get(addr)
            if hit:
                return org, True
            return self._query(addr)  # sibling's answer didn't cover us
        try:
            return self._query(addr)
        finally:
            with self._lock:
                self._inflight.pop(block).set()

    def _query(self, addr):
        try:
            return self._rdap(addr), True
        except urllib.error.HTTPError as e:
            return None, e.code == 404  # no registry record: don't retry
        except (OSError, ValueError, http.client.HTTPException):
            return None, False

    @staticmethod
    def _rdns(addr) -> str | None:
        try:
            return clean(socket.gethostbyaddr(str(addr))[0])
        except (OSError, UnicodeError):
            return None

    def _fetch_json(self, url: str):
        """GET a JSON URL, following redirects by hand so every hop is paced
        by the rate limiter against its own host. Raises ``RateLimited``
        instead of waiting long: when a host is backing off or its pacing would
        exceed ``MAX_WAIT`` (checked before spending a request), or when it
        answers with a rate-limit status."""
        for _ in range(self.MAX_REDIRECTS + 1):
            host = (urllib.parse.urlsplit(url).hostname or "").lower()
            busy = self._limiter.delay(host)
            if busy > self.MAX_WAIT:
                raise RateLimited(host, busy)
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/rdap+json, application/json",
                         "User-Agent": "caddy-traffic-monitor"},
            )
            location = None
            with self._limiter.slot(host):  # paced; one in flight per host
                try:
                    with self._opener.open(req, timeout=self.TIMEOUT) as resp:
                        return json.loads(resp.read().decode("utf-8", "replace"))
                except urllib.error.HTTPError as e:
                    with e:  # release the connection whatever happens next
                        location = e.headers.get("Location") if e.headers else None
                        if e.code in (301, 302, 303, 307, 308) and location:
                            pass  # follow below, outside this host's slot
                        elif e.code in self.RATE_LIMIT_CODES:
                            # Applied before the slot is released, so no other
                            # request to this host can slip in first.
                            wait = retry_after_seconds(e.headers.get("Retry-After"))
                            self._limiter.backoff(host, wait)
                            raise RateLimited(host, wait) from e
                        else:
                            raise
            url = urllib.parse.urljoin(url, location)
        raise ValueError("too many RDAP redirects")

    def _rdap(self, addr) -> str | None:
        base = self._bootstrap.base_url(addr)
        url = f"{base}ip/{addr}" if base else self.RDAP_URL + str(addr)
        data = self._fetch_json(url)
        if not isinstance(data, dict):
            return None
        org = _rdap_org(data)
        country = data.get("country")
        if org and isinstance(country, str) and country:
            org = f"{org} ({clean(country)})"
        org = org or None
        try:
            nets = list(ipaddress.summarize_address_range(
                ipaddress.ip_address(data.get("startAddress")),
                ipaddress.ip_address(data.get("endAddress")),
            ))
        except (TypeError, ValueError):
            nets = []
        if nets:
            self.ranges.put(nets, org)
        return org
