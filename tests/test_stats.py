"""Status classification and bounded running totals (caddymon.stats), and the
exit summary built from them."""

from __future__ import annotations

import contextlib
import io
import unittest
from collections import Counter
from unittest import mock

from caddymon.logsource import Record
from caddymon.output import Display, Palette
from caddymon.rdap import OwnerResolver
from caddymon.stats import Stats, classify, marker


def rec(ip, status=404, uri="/"):
    return Record("2026-09-26 00:00:00", status, "GET", ip, uri)


class ClassificationTests(unittest.TestCase):
    def test_marker_and_color_follow_classify(self):
        p = Palette(True)
        cases = [(101, "other", "·", "DIM"), (0, "other", "·", "DIM"),
                 (200, "2xx", "✓", "GREEN"), (301, "3xx", "→", "CYAN"),
                 (404, "4xx", "✗", "YELLOW"), (503, "5xx", "✗", "BRIGHT_RED")]
        for status, cls, mark, attr in cases:
            with self.subTest(status=status):
                self.assertEqual(classify(status), cls)
                self.assertEqual(marker(status), mark)
                self.assertEqual(p.style_for(status), getattr(p, attr))

    def test_palette_off_is_empty(self):
        p = Palette(False)
        self.assertEqual(p.style_for(200), "")
        self.assertEqual(p.RESET, "")


class StatsTests(unittest.TestCase):
    def test_record_counts(self):
        st = Stats()
        st.record(rec("1.1.1.1", 403, "/wp-login.php?x=1"))
        st.record(rec("1.1.1.1", 200, "/"))
        self.assertEqual(st.total, 2)
        self.assertEqual(st.classes["4xx"], 1)
        self.assertEqual(st.denied_ips["1.1.1.1"], 1)
        self.assertEqual(st.paths["/wp-login.php"], 1)  # query string stripped
        self.assertEqual(st.ips["1.1.1.1"].hits, 2)
        self.assertEqual(st.ips["1.1.1.1"].last_seq, 2)

    @mock.patch.object(Stats, "MAX_IPS", 100)
    @mock.patch.object(Stats, "MAX_PATHS", 50)
    def test_pruning_is_bounded_and_keeps_heavy_and_recent(self):
        st = Stats()
        evicted = []
        st.on_evict = evicted.extend
        for _ in range(500):
            st.record(rec("6.6.6.6", uri="/big"))
        for i in range(1000):
            st.record(rec(f"10.0.{i // 256}.{i % 256}", uri=f"/p{i}"))
        self.assertLessEqual(len(st.ips), 100)
        self.assertLessEqual(len(st.paths), 50)
        self.assertEqual(st.total, 1500)  # totals stay exact
        self.assertEqual(st.ips["6.6.6.6"].hits, 500)  # heaviest kept
        self.assertIn("10.0.3.231", st.ips)  # newest kept, even on its first hit
        self.assertIn("10.0.0.0", evicted)  # old one-hit IPs go (ties -> recency)
        self.assertNotIn("6.6.6.6", evicted)

    def test_per_site_counts(self):
        st = Stats(per_site=True)
        for site, status in [("www", 404), ("www", 404), ("shop", 200)]:
            st.record(Record("2026-09-26 00:00:00", status, "GET", "1.1.1.1", "/", site))
        self.assertEqual(st.sites, {"www": Counter({"4xx": 2}), "shop": Counter({"2xx": 1})})
        ip = st.ips["1.1.1.1"]
        self.assertEqual(ip.hits, 3)  # the totals are unchanged
        self.assertEqual((ip.sites["www"].hits, ip.sites["www"].last_seq), (2, 2))
        self.assertEqual((ip.sites["shop"].classes, ip.sites["shop"].last_seq),
                         (Counter({"2xx": 1}), 3))

    def test_no_per_site_counts_by_default(self):
        st = Stats()
        st.record(Record("2026-09-26 00:00:00", 404, "GET", "1.1.1.1", "/", "www"))
        self.assertEqual(st.sites, {})
        self.assertEqual(st.ips["1.1.1.1"].sites, {})

    def test_summary_lists_sites(self):
        st = Stats(per_site=True)
        for site, status in [("www.example.com", 404), ("www.example.com", 404),
                             ("shop.example.com", 200)]:
            st.record(Record("2026-09-26 00:00:00", status, "GET", "1.1.1.1", "/", site))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            Display(Palette(False), "x").summary(st, OwnerResolver(enabled=False))
        text = out.getvalue()
        self.assertIn("── Per site ──", text)
        self.assertLess(text.index("2     → www.example.com  4xx:2"),
                        text.index("1     → shop.example.com 2xx:1"))  # busiest first

    @mock.patch.object(Stats, "MAX_IPS", 100)
    def test_new_ip_survives_the_prune_it_triggers(self):
        st = Stats()
        for i in range(100):
            st.record(rec(f"10.1.0.{i}"))
        st.record(rec("10.9.9.9"))
        self.assertEqual(st.ips["10.9.9.9"].hits, 1)


if __name__ == "__main__":
    unittest.main()
