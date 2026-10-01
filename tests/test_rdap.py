"""Owner lookups (caddymon.rdap): rate limiting, range cache, bootstrap.

All HTTP goes to local fake servers and reverse DNS is stubbed out, so these
tests never contact a real registry, IANA, rdap.org or DNS server. Rate-limit
windows are shrunk so the timing checks run in a few seconds."""

from __future__ import annotations

import ipaddress as ipa
import json
import os
import tempfile
import threading
import time
import unittest
from email.utils import formatdate
from unittest import mock

from caddymon import rdap
from caddymon.rdap import (OwnerResolver, RangeCache, RateLimiter, RdapBootstrap,
                           _rdap_org, _vcard_fn, retry_after_seconds)

from helpers import FakeServer, rdap_network, read_json, reply, third_octet, wait_until


class OfflineTestCase(unittest.TestCase):
    """Base: no real bootstrap, no real DNS, fast limits. Subclasses set
    servers and override the class attributes they need."""

    def setUp(self):
        for name, value in {
            "BOOTSTRAP_URLS": {},
            "RDAP_URL": "http://127.0.0.1:9/ip/",  # nothing listens here
            "RDAP_LIMITS": {"127.0.0.1": [(100, 1)], "localhost": [(100, 1)]},
            "RDAP_DEFAULT_LIMIT": [(100, 1)],
        }.items():
            patcher = mock.patch.object(OwnerResolver, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(OwnerResolver, "_rdns", staticmethod(lambda addr: None))
        patcher.start()
        self.addCleanup(patcher.stop)

    def serve(self, respond, host="127.0.0.1"):
        server = FakeServer(respond, host)
        self.addCleanup(server.close)
        return server


class HelperTests(unittest.TestCase):
    def test_retry_after_parsing(self):
        self.assertEqual(retry_after_seconds("5"), 5)
        self.assertEqual(retry_after_seconds(None), 60)
        self.assertEqual(retry_after_seconds("junk"), 60)
        self.assertEqual(retry_after_seconds("99999"), 3600)  # capped
        self.assertEqual(retry_after_seconds("-3"), 1)
        http_date = formatdate(time.time() + 30, usegmt=True)
        self.assertTrue(28 <= retry_after_seconds(http_date) <= 31)

    def test_limiter_windows_with_margin(self):
        lim = RateLimiter({"a": [(10, 10)], "lac": [(10, 60), (1000, 3600)]}, [(10, 10)])
        now = time.monotonic()
        lim._sent["a"] = rdap.deque([now - 1.0] * 10)
        self.assertAlmostEqual(lim.delay("a"), 11.0 - 1.0, delta=0.05)  # 10 s * 1.1
        lim._sent["lac"] = rdap.deque([now - 5.0] * 10)
        self.assertAlmostEqual(lim.delay("lac"), 66.0 - 5.0, delta=0.05)
        lim._sent["lac"] = rdap.deque([now - 70.0 - i for i in range(1000)])
        self.assertGreater(lim.delay("lac"), 3000)  # hourly rule
        lim.backoff("b", 7)
        self.assertTrue(6.9 < lim.delay("b") <= 7)
        self.assertEqual(lim.delay("idle"), 0)

    def test_delay_waits_for_the_lock(self):
        # _fetch_json calls delay() while other workers' acquire() may be
        # changing the same send-time deque; reading it unlocked could raise
        # "deque mutated during iteration". So delay() must take the lock.
        lim = RateLimiter({}, [(10, 10)])
        lim.acquire("a")
        done = threading.Event()
        with lim._lock:
            threading.Thread(target=lambda: (lim.delay("a"), done.set()),
                             daemon=True).start()
            self.assertFalse(done.wait(0.2))  # blocked while the lock is held
        self.assertTrue(done.wait(5))

    def test_rdap_names_are_cleaned(self):
        entity = {"vcardArray": ["vcard", [["fn", {}, "text", "Evil\x1b[2J Corp"]]]}
        self.assertEqual(_vcard_fn(entity), "Evil?[2J Corp")
        self.assertEqual(_rdap_org({"name": "NET\x07"}), "NET?")
        nested = {"entities": [{"roles": ["tech"], "entities": [
            {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Deep Org"]]]}]}]}
        self.assertEqual(_rdap_org(nested), "Deep Org")

    def test_bootstrap_parse_prefers_https_and_most_specific(self):
        table = RdapBootstrap._parse({"services": [
            [["45.0.0.0/8"], ["http://a.example/", "https://a.example/"]],
            [["45.148.0.0/16"], ["https://b.example"]],
            ["broken"],
        ]})
        self.assertEqual(table[0], (ipa.ip_network("45.148.0.0/16"), "https://b.example/"))
        self.assertEqual(table[1], (ipa.ip_network("45.0.0.0/8"), "https://a.example/"))
        with self.assertRaises(ValueError):
            RdapBootstrap._parse({"services": []})


class RangeCacheTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "rdap_cache.json")

    def test_most_specific_unexpired_range_wins(self):
        c = RangeCache()
        c.put([ipa.ip_network("45.0.0.0/8")], "Broad")
        c.put([ipa.ip_network("45.148.10.0/24")], "Specific")
        c.put([ipa.ip_network("198.51.100.0/24")], None)
        c.put([ipa.ip_network("2001:db8::/32")], "V6")
        with c._lock:
            c._store(ipa.ip_network("45.148.10.0/25"), ("Expired", time.time() - 1))
        self.assertEqual(c.get(ipa.ip_address("45.148.10.5")), (True, "Specific"))
        self.assertEqual(c.get(ipa.ip_address("45.1.1.1")), (True, "Broad"))
        self.assertEqual(c.get(ipa.ip_address("198.51.100.5")), (True, None))
        self.assertEqual(c.get(ipa.ip_address("2001:db8::1")), (True, "V6"))
        self.assertEqual(c.get(ipa.ip_address("9.9.9.9")), (False, None))

    def test_lookup_is_fast_with_many_ranges(self):
        c = RangeCache()
        c.put([ipa.ip_network(f"10.{i // 256}.{i % 256}.0/24") for i in range(50000)], "X")
        start = time.perf_counter()
        for _ in range(1000):
            c.get(ipa.ip_address("10.100.7.9"))
        self.assertLess(time.perf_counter() - start, 0.5)

    def test_persistence_ttls_and_merge(self):
        c = RangeCache(self.path)
        c.put([ipa.ip_network("203.0.1.0/24")], "Named")
        c.put([ipa.ip_network("203.0.2.0/24")], None)
        c.save()
        data = read_json(self.path)
        self.assertEqual(data["version"], 1)
        named_ttl = data["networks"]["203.0.1.0/24"][1] - time.time()
        empty_ttl = data["networks"]["203.0.2.0/24"][1] - time.time()
        self.assertTrue(29.9 * 86400 < named_ttl <= 30 * 86400)
        self.assertTrue(0.9 * 86400 < empty_ttl <= 86400)
        # Another instance saves in between: both sets survive.
        other = RangeCache(self.path)
        other.load()
        other.put([ipa.ip_network("203.0.3.0/24")], "Other")
        c.put([ipa.ip_network("203.0.4.0/24")], "Mine")
        other.save()
        c.save()
        merged = RangeCache(self.path)
        self.assertEqual(merged.load(), 4)
        self.assertEqual(merged.get(ipa.ip_address("203.0.3.9"))[1], "Other")
        self.assertEqual(merged.get(ipa.ip_address("203.0.4.9"))[1], "Mine")

    def test_expired_entries_are_not_saved(self):
        c = RangeCache(self.path)
        c.put([ipa.ip_network("203.0.1.0/24")], "Live")
        with c._lock:
            c._store(ipa.ip_network("203.0.9.0/24"), ("Old", time.time() - 1))
        c.save()
        self.assertNotIn("203.0.9.0/24", read_json(self.path)["networks"])

    def test_corrupt_file_and_hostile_owner_text(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("{not json")
        self.assertEqual(RangeCache(self.path).load(), 0)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "networks": {
                "203.0.1.0/24": ["Evil\x1b]0;x\x07", time.time() + 999],
                "not-a-network": ["x", time.time() + 999],
                "203.0.2.0/24": ["no expiry"],
            }}, f)
        c = RangeCache(self.path)
        self.assertEqual(c.load(), 1)
        self.assertEqual(c.get(ipa.ip_address("203.0.1.1"))[1], "Evil?]0;x?")

    def test_unwritable_location_is_reported_not_raised(self):
        c = RangeCache(os.path.join(self.dir.name, "missing-dir", "c.json"))
        c.put([ipa.ip_network("203.0.1.0/24")], "Mem")
        c.save()
        self.assertTrue(c.error)
        self.assertEqual(c.get(ipa.ip_address("203.0.1.1"))[1], "Mem")
        self.assertFalse([f for f in os.listdir(self.dir.name) if f.endswith(".tmp")])


class FallbackPathTests(OfflineTestCase):
    """The rdap.org-style path: a redirecting "bootstrap" on 127.0.0.1 sends
    every lookup to a registry on localhost (a different host to the limiter)."""

    def make_servers(self, limited_code=None):
        state = {"limited": False}

        def registry(h):
            if limited_code and not state["limited"]:
                state["limited"] = True
                time.sleep(0.3)  # slow: a concurrent request would overlap it
                return reply(h, code=limited_code, headers=[("Retry-After", "1")])
            n = third_octet(h.path)
            reply(h, rdap_network(n, f"Org {n}"))

        reg = self.serve(registry, host="localhost")

        def bootstrap(h):
            reply(h, code=302, headers=[("Location", f"{reg.base}registry{h.path}")])

        boot = self.serve(bootstrap)
        OwnerResolver.RDAP_URL = f"{boot.base}ip/"
        return boot, reg

    def resolve(self, resolver, ips, timeout):
        done = wait_until(lambda: all(resolver._cache.get(ip) for ip in ips), timeout,
                          tick=lambda: [resolver.lookup(ip) for ip in ips])
        self.assertTrue(done, {ip: resolver._cache.get(ip) for ip in ips})

    def test_redirects_are_followed_and_paced_per_host(self):
        boot, reg = self.make_servers()
        OwnerResolver.RDAP_LIMITS = {"localhost": [(2, 1)], "127.0.0.1": [(100, 1)]}
        r = OwnerResolver(enabled=True)
        ips = [f"203.0.{n}.7" for n in range(1, 7)]
        self.resolve(r, ips, 15)
        self.assertEqual([r._cache[ip] for ip in ips], [f"Org {n} (ZZ)" for n in range(1, 7)])
        times = [t for _, t in reg.requests]
        self.assertEqual(len(boot.requests), len(reg.requests))  # every hop came via the redirect
        for i in range(2, len(times)):  # 2 per 1.1 s sliding window
            self.assertGreaterEqual(times[i] - times[i - 2], 1.1 - 0.05)

    def test_rate_limit_status_pauses_the_host(self):
        for code in (429, 403, 503):
            with self.subTest(code=code):
                boot, reg = self.make_servers(limited_code=code)
                r = OwnerResolver(enabled=True)
                ips = [f"203.0.{n}.7" for n in range(1, 4)]
                self.resolve(r, ips, 15)
                times = [t for _, t in reg.requests]
                # Nothing reached the host during its 1 s Retry-After pause.
                self.assertGreaterEqual(times[1] - times[0], 1.0)

    def test_same_block_is_queried_once(self):
        boot, reg = self.make_servers()
        r = OwnerResolver(enabled=True)
        ips = [f"203.0.{n}.{h}" for n in (1, 2, 3) for h in (7, 99, 200)]
        self.resolve(r, ips, 10)
        self.assertEqual(len(reg.requests), 3)

    def test_stale_queue_entries_cost_no_request(self):
        boot, reg = self.make_servers()
        r = OwnerResolver(enabled=True)
        with r._lock:
            r._pending.add("203.0.99.1")
            r._wanted["203.0.99.1"] = 0.0  # last asked for long ago
            r._start_workers()
        r._queue.put("203.0.99.1")
        self.assertTrue(wait_until(lambda: "203.0.99.1" not in r._pending, 2))
        self.assertEqual(reg.requests, [])

    def test_not_found_is_final_other_errors_retry(self):
        def registry(h):
            return reply(h, code=404 if "203.0.1." in h.path else 500)

        reg = self.serve(registry)
        OwnerResolver.RDAP_URL = f"{reg.base}ip/"
        r = OwnerResolver(enabled=True)
        ips = ["203.0.1.1", "203.0.2.1"]
        self.resolve(r, ips, 5)
        self.assertEqual(r._cache["203.0.1.1"], "unknown")
        self.assertEqual(r._cache["203.0.2.1"], "lookup failed")
        self.assertNotIn("203.0.1.1", r._retry_at)
        self.assertIn("203.0.2.1", r._retry_at)


class BootstrapPathTests(OfflineTestCase):
    def test_direct_to_registry_and_throttled_registry_blocks_nothing(self):
        reg_a = self.serve(lambda h: reply(h, rdap_network(third_octet(h.path), "A-Org")))
        reg_b = self.serve(lambda h: reply(h, code=429, headers=[("Retry-After", "600")]),
                           host="localhost")
        fallback = self.serve(lambda h: reply(h, code=500))
        boot = self.serve(lambda h: reply(h, {"services": [
            [["203.0.0.0/16"], [reg_a.base]],
            [["45.148.10.0/24"], [reg_b.base]],
        ]}))
        OwnerResolver.BOOTSTRAP_URLS = {4: f"{boot.base}ipv4.json"}
        OwnerResolver.RDAP_URL = f"{fallback.base}ip/"
        r = OwnerResolver(enabled=True)
        b_ips = [f"45.148.10.{i}" for i in (1, 2, 3, 4)]
        a_ips = [f"203.0.{n}.9" for n in range(1, 9)]
        # Registry B gets asked and throttles us for 10 minutes...
        self.assertTrue(wait_until(lambda: reg_b.requests and all(ip in r._retry_at for ip in b_ips),
                                   5, tick=lambda: [r.lookup(ip) for ip in b_ips]))
        # ...yet A's IPs resolve promptly and B hears nothing more.
        started = time.monotonic()
        self.assertTrue(wait_until(lambda: all(r._cache.get(ip) for ip in a_ips), 5,
                                   tick=lambda: [r.lookup(ip) for ip in b_ips + a_ips]))
        self.assertLess(time.monotonic() - started, 3)
        time.sleep(0.3)
        for ip in b_ips:
            r.lookup(ip)
        time.sleep(0.3)
        self.assertEqual(len(reg_b.requests), 1)
        self.assertEqual(len(reg_a.requests), 8)
        self.assertEqual(len(boot.requests), 1)  # bootstrap fetched once
        self.assertEqual(fallback.requests, [])
        self.assertTrue(all(r._cache.get(ip) is None for ip in b_ips))  # deferred, not failed
        self.assertTrue(all(r._cache[ip].startswith("A-Org") for ip in a_ips))

    def test_unavailable_bootstrap_falls_back(self):
        fallback = self.serve(lambda h: reply(h, rdap_network(third_octet(h.path), "Via Fallback")))
        OwnerResolver.BOOTSTRAP_URLS = {4: "http://127.0.0.1:9/ipv4.json"}  # refused
        OwnerResolver.RDAP_URL = f"{fallback.base}ip/"
        r = OwnerResolver(enabled=True)
        self.assertTrue(wait_until(lambda: r._cache.get("203.0.50.1"), 5,
                                   tick=lambda: r.lookup("203.0.50.1")))
        self.assertEqual(r._cache["203.0.50.1"], "Via Fallback (ZZ)")


class CacheIntegrationTests(OfflineTestCase):
    def test_second_run_makes_no_requests(self):
        reg = self.serve(lambda h: reply(h, rdap_network(third_octet(h.path), "Cached")))
        OwnerResolver.RDAP_URL = f"{reg.base}ip/"
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "rdap_cache.json")
        ips = [f"203.0.{n}.{h}" for n in (1, 2, 3) for h in (7, 99)]

        def run(enabled=True):
            ranges = RangeCache(path)
            loaded = ranges.load()
            r = OwnerResolver(enabled=enabled, ranges=ranges)
            first = {ip: r.lookup(ip) for ip in ips}
            if enabled:
                wait_until(lambda: all(r._cache.get(ip) for ip in ips), 10,
                           tick=lambda: [r.lookup(ip) for ip in ips])
            ranges.save()
            return loaded, first

        loaded, _ = run()
        self.assertEqual((loaded, len(reg.requests)), (0, 3))  # one query per block
        loaded, first = run()
        self.assertEqual((loaded, len(reg.requests)), (3, 3))  # no new requests
        self.assertTrue(all(v == "Cached (ZZ)" for v in first.values()))  # shown at once
        loaded, first = run(enabled=False)  # --no-lookup still reads the cache
        self.assertTrue(all(v == "Cached (ZZ)" for v in first.values()))
        self.assertEqual(len(reg.requests), 3)

    def test_offline_labels_and_forget(self):
        r = OwnerResolver(enabled=False)
        self.assertEqual(r.lookup("10.0.0.1"), "private network")
        self.assertEqual(r.lookup("127.0.0.1"), "loopback")
        self.assertEqual(r.lookup("8.8.8.8"), "")
        self.assertEqual(r.lookup("not-an-ip"), "")
        r._cache["1.2.3.4"] = "x"
        r._wanted["1.2.3.4"] = 0.0
        r._retry_at["1.2.3.4"] = 0.0
        r.forget(["1.2.3.4"])
        self.assertFalse("1.2.3.4" in r._cache or "1.2.3.4" in r._wanted or "1.2.3.4" in r._retry_at)

    def test_lookups_off_answers_are_memoised(self):
        # lookup() runs for every visible IP on every frame; with lookups off
        # the answer can't change, so the range search runs once per IP.
        ranges = RangeCache()
        ranges.put([ipa.ip_network("203.0.5.0/24")], "Cached (ZZ)")
        r = OwnerResolver(enabled=False, ranges=ranges)
        with mock.patch.object(ranges, "get", wraps=ranges.get) as get:
            for _ in range(50):
                self.assertEqual(r.lookup("203.0.5.9"), "Cached (ZZ)")
        self.assertEqual(get.call_count, 1)
        r.forget(["203.0.5.9"])
        self.assertNotIn("203.0.5.9", r._cache)

    def test_pending_guess_is_memoised_until_the_ranges_change(self):
        ranges = RangeCache()
        r = OwnerResolver(enabled=True, ranges=ranges)
        with mock.patch.object(r, "_start_workers"), \
                mock.patch.object(ranges, "get", wraps=ranges.get) as get:
            for _ in range(50):
                self.assertIsNone(r.lookup("203.0.5.9"))  # pending, nothing known
            self.assertEqual(get.call_count, 1)
            # A sibling's answer covers this block: shown on the next frame.
            ranges.put([ipa.ip_network("203.0.5.0/24")], "Sibling (ZZ)")
            for _ in range(50):
                self.assertEqual(r.lookup("203.0.5.9"), "Sibling (ZZ)")
            self.assertEqual(get.call_count, 2)
        r._cache["203.0.5.9"] = "Final (ZZ)"  # the worker's own answer
        self.assertEqual(r.lookup("203.0.5.9"), "Final (ZZ)")
        self.assertNotIn("203.0.5.9", r._provisional)


if __name__ == "__main__":
    unittest.main()
