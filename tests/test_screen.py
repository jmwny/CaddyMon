"""The interactive view (caddymon.screen), drawn onto a virtual terminal."""

from __future__ import annotations

import contextlib
import io
import os
import unittest
from unittest import mock

from caddymon.logsource import Record
from caddymon.output import Palette, site_width
from caddymon.rdap import OwnerResolver
from caddymon.screen import RateMeter, Screen, fmt_duration, parse_keys
from caddymon.stats import Stats
from caddymon.text import clip, fit, shorten, vlen

from helpers import Term


class HelperTests(unittest.TestCase):
    def test_parse_keys(self):
        self.assertEqual(
            parse_keys("\x1b[Aj\x1b[B\x1bOA\t\r\n\x1b[5~\x1b[6~\x1b[H\x1b[Fq\x1b[C\x1bOD\x1b"),
            ["up", "j", "down", "up", "tab", "enter", "enter", "pgup", "pgdn",
             "home", "end", "q", "right", "left", "esc"])
        self.assertEqual(parse_keys("\x1b[Z"), [])  # unknown sequence dropped

    def test_clip_and_vlen_are_ansi_aware(self):
        p = Palette(True)
        s = f"{p.RED}abcdef{p.RESET}ghij"
        self.assertEqual(vlen(s), 10)
        self.assertEqual(vlen(clip(s, 7, p.RESET)), 7)
        self.assertEqual(clip("abc", 5), "abc")
        self.assertEqual(clip("abcdef", 0), "")

    def test_shorten_and_fit_mark_cuts_the_same_way(self):
        self.assertEqual(shorten("abcdef", 4), "abc…")
        self.assertEqual(shorten("abc", 4), "abc")
        self.assertEqual(shorten("abc", 0), "")
        self.assertEqual(fit("abc", 5), "abc  ")
        self.assertEqual(fit("abcdef", 5), "abcd…")
        self.assertEqual(site_width(["www.example.com", "a"]), 15)
        self.assertEqual(site_width(["x" * 40]), 24)  # capped
        self.assertEqual(site_width([]), 0)

    def test_fmt_duration(self):
        self.assertEqual([fmt_duration(s) for s in (59, 61, 4320)], ["59s", "1m01s", "1h12m"])

    def test_rate_meter(self):
        meter = RateMeter()
        for _ in range(30):
            meter.add()
        self.assertAlmostEqual(meter.rate(), 30)
        self.assertEqual(sum(meter.bins(15)), 30)


class ScreenTests(unittest.TestCase):
    def make(self, cols=100, rows=24, **kwargs):
        self.out = io.StringIO()
        redirect = contextlib.redirect_stdout(self.out)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)
        patcher = mock.patch.object(os, "get_terminal_size",
                                    lambda *a: os.terminal_size((cols, rows)))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.stats = Stats()
        self.screen = Screen(Palette(True), self.stats, OwnerResolver(enabled=False),
                             "/var/log/caddy/access.log", **kwargs)
        self.term = Term(cols, rows)
        self.screen.start()
        return self.screen

    def feed(self, ip, status, uri="/", t="14:02:11"):
        rec = Record(f"2026-09-26 {t}", status, "GET", ip, uri)
        self.stats.record(rec)
        self.screen.add(rec)

    def traffic(self):
        for i in range(40):
            self.feed("45.148.10.23", 404, "/.env", t=f"14:00:{i:02d}")
        for _ in range(12):
            self.feed("192.168.1.20", 200, "/api", t="14:01:50")
        self.feed("66.249.66.1", 301, "/old", t="14:02:09")
        self.feed("10.9.9.9", 101, "/ws", t="14:02:13")

    def render(self):
        self.screen.draw()
        self.term.feed(self.out.getvalue())
        self.out.seek(0)
        self.out.truncate()
        return self.term.text()

    def test_split_layout(self):
        self.make()
        self.traffic()
        text = self.render()
        lines = self.term.lines()
        self.assertTrue(self.term.alt)  # alternate screen
        self.assertIn("CADDY MONITOR", lines[0])
        self.assertIn("IPs 4", text)
        self.assertIn("⚠", text)  # 40 x 404, no 2xx: likely scanner
        self.assertIn("└─ private network", text)
        self.assertIn("· 101  GET    10.9.9.9", text)  # 1xx: dim · marker
        self.assertIn("q quit", lines[-1])

    def test_header_keeps_log_name_over_sparkline(self):
        for cols in (100, 80, 64):
            with self.subTest(cols=cols):
                screen = self.make(cols=cols)
                screen.log_path = "/var/log/caddy/www.example.com.log"
                self.traffic()
                self.render()
                header = self.term.lines()[0]
                self.assertIn("www.example.com.log", header)
                self.assertNotIn("▁", header)  # sparkline gave way first
                self.assertNotIn("\033[2mwww.example.com.log", self.screen._header(cols - 1))

    def test_several_logs_add_a_site_column(self):
        self.make(layout="stream", sites=["www.example.com", "shop.example.com"])
        for site in ("www.example.com", "shop.example.com"):
            rec = Record("2026-09-26 14:02:11", 404, "GET", "45.148.10.23", "/.env", site)
            self.stats.record(rec)
            self.screen.add(rec)
        self.render()
        lines = self.term.lines()
        self.assertIn("2 sites", lines[0])
        self.assertTrue(any("GET    www.example.com  45.148.10.23" in l for l in lines))
        self.assertTrue(any("GET    shop.example.com 45.148.10.23" in l for l in lines))

    def site_traffic(self):
        self.make(sites=["www.example.com", "shop.example.com"])
        self.stats.per_site = True
        for site, ip, status in [("www.example.com", "45.148.10.23", 404)] * 3 + [
                ("shop.example.com", "45.148.10.23", 200),
                ("www.example.com", "66.249.66.1", 301)]:
            rec = Record("2026-09-26 14:02:11", status, "GET", ip, "/" + site, site)
            self.stats.record(rec)
            self.screen.add(rec)

    def test_site_filter_narrows_everything_to_one_site(self):
        self.site_traffic()
        text = self.render()
        self.assertIn("2 sites", self.term.lines()[0])
        self.assertIn("f site", self.term.lines()[-1])
        scanner = next(l for l in self.term.lines() if l.startswith("  45.148.10.23"))
        self.assertIn("2 sites", scanner)  # hit both sites
        self.assertNotIn("2 sites", next(l for l in self.term.lines() if "66.249.66.1" in l))

        self.screen.handle_input("ff")  # all -> www -> shop
        self.assertEqual(self.screen.site, "shop.example.com")
        text = self.render()
        lines = self.term.lines()
        self.assertIn("shop.example.com (2 of 2)", lines[0])
        self.assertIn("1 req", lines[0])  # the header counts this site only
        self.assertIn("IPs 1 · by recent · all codes · shop.example.com", text)
        scanner = next(l for l in lines if l.startswith("  45.148.10.23"))
        self.assertRegex(scanner, r"45\.148\.10\.23\s+1\s+1\s+·\s+·\s+·")  # its shop hits
        self.assertIn("2 sites", scanner)  # still counted across all sites
        self.assertNotIn("66.249.66.1", text)  # never hit the shop
        self.assertIn("Requests · all IPs · all codes · shop.example.com", text)
        self.assertIn("GET    45.148.10.23", text)  # no site column while narrowed
        self.assertNotIn("/www.example.com", text)

        self.screen.handle_input("f")  # back to all sites
        self.assertIsNone(self.screen.site)
        self.assertIn("2 sites", self.render().splitlines()[0])

    def test_errors_on_several_sites_flag_an_ip(self):
        sites = ["a.example.com", "b.example.com", "c.example.com"]
        for suspect_sites, flagged in ((2, {"6.6.6.6"}), (3, set()), (0, set())):
            with self.subTest(suspect_sites=suspect_sites):
                self.make(sites=sites, suspect_sites=suspect_sites)
                self.stats.per_site = True
                for ip, site, status in [
                        ("6.6.6.6", "a.example.com", 404),  # errors only, on 2 sites
                        ("6.6.6.6", "b.example.com", 404),
                        ("7.7.7.7", "a.example.com", 404),  # a 2xx on one of its 2 sites
                        ("7.7.7.7", "b.example.com", 404),
                        ("7.7.7.7", "b.example.com", 200),
                        ("8.8.8.8", "c.example.com", 404)]:  # one site only
                    rec = Record("2026-09-26 14:02:11", status, "GET", ip, "/", site)
                    self.stats.record(rec)
                    self.screen.add(rec)
                self.render()
                rows = {l.split()[0]: l for l in self.term.lines() if l.startswith("  ")
                        and l.split()[0] in ("6.6.6.6", "7.7.7.7", "8.8.8.8")}
                self.assertEqual({ip for ip, l in rows.items() if "⚠" in l}, flagged)
        # Filtered to one site, the cross-site part still counts every site.
        self.make(sites=sites)
        self.stats.per_site = True
        for site in ("a.example.com", "b.example.com"):
            rec = Record("2026-09-26 14:02:11", 404, "GET", "6.6.6.6", "/", site)
            self.stats.record(rec)
            self.screen.add(rec)
        self.screen.handle_input("f")
        self.render()
        self.assertIn("⚠", next(l for l in self.term.lines() if l.startswith("  6.6.6.6")))

    def test_site_key_needs_several_logs(self):
        self.make(sites=["access"])
        self.screen.handle_input("f")
        self.assertIsNone(self.screen.site)
        self.render()
        self.assertNotIn("f site", self.term.lines()[-1])

    def test_one_log_has_no_site_column(self):
        self.make(layout="stream", sites=["access"])
        self.feed("45.148.10.23", 404, "/.env")
        self.render()
        self.assertIn("access.log", self.term.lines()[0])
        self.assertTrue(any("GET    45.148.10.23" in l for l in self.term.lines()))

    def test_follow_filter_sort_and_escape(self):
        self.make()
        self.traffic()
        self.render()
        self.screen.handle_input("s")  # sort by hits: the scanner is first
        self.screen.handle_input("\n")  # follow the top entry
        text = self.render()
        self.assertEqual(self.screen.follow, "45.148.10.23")
        self.assertIn("Requests · 45.148.10.23", text)
        self.assertIn("◀ following", text)
        self.screen.handle_input("2")  # 2xx only: the scanner drops out
        text = self.render()
        self.assertIn("IPs 1", text)
        self.screen.handle_input("a\x1b")
        text = self.render()
        self.assertIsNone(self.screen.follow)
        self.assertIn("Requests · all IPs", text)

    def test_cursor_navigation_keeps_selection_visible(self):
        self.make(cols=80, rows=14)
        for i in range(40):
            self.feed(f"10.0.{i}.1", 404, t=f"14:00:{i:02d}")
        self.screen.handle_input("\x1b[F")
        self.assertEqual(self.screen.selected, "10.0.0.1")  # end = oldest
        self.screen.handle_input("\x1b[H")
        self.assertEqual(self.screen.selected, "10.0.39.1")  # home = newest
        self.screen.handle_input("\x1b[6~\x1b[6~")
        text = self.render()
        selected_rows = [line for line in self.term.lines() if "▶" in line]
        self.assertTrue(selected_rows and self.screen.selected in selected_rows[0], text)

    def request_uris(self):
        return [line.split()[-1] for line in self.term.lines() if "GET" in line]

    def test_request_pane_scrolls_and_holds_position(self):
        self.make(cols=80, rows=12, layout="stream")  # 9 request rows
        for i in range(30):
            self.feed("45.148.10.23", 404, f"/r{i}")
        self.render()
        self.assertEqual(self.request_uris()[-1], "/r29")  # live: newest at the bottom
        self.screen.handle_input("\x1b[A\x1b[A")  # up twice
        text = self.render()
        self.assertEqual(self.request_uris()[-1], "/r27")
        self.assertIn("paused", text)
        self.assertIn("20–28 of 30", text)  # /r0 is number 1
        self.assertIn("end latest", self.term.lines()[-1])
        self.feed("45.148.10.23", 404, "/r30")  # new arrivals don't move the view
        self.render()
        self.assertEqual(self.request_uris()[-1], "/r27")
        self.screen.handle_input("\x1b[H")  # home: oldest
        self.render()
        self.assertEqual(self.request_uris()[0], "/r0")
        self.screen.handle_input("\x1b[5~")  # page up past the top stays put
        self.render()
        self.assertEqual(self.request_uris()[0], "/r0")
        self.screen.handle_input("\x1b[6~")  # page down: one pane further on
        self.render()
        self.assertEqual(self.request_uris()[0], "/r9")
        self.screen.handle_input("\x1b[F")  # end: live again
        text = self.render()
        self.assertEqual(self.request_uris()[-1], "/r30")
        self.assertNotIn("paused", text)

    def test_filter_change_returns_request_pane_to_live(self):
        self.make(cols=80, rows=12, layout="stream")
        for i in range(30):
            self.feed("45.148.10.23", 404 if i % 2 else 200, f"/r{i}")
        self.screen.handle_input("\x1b[5~")
        self.assertTrue(self.screen._req_back)
        self.screen.handle_input("4")
        self.render()
        self.assertEqual(self.screen._req_back, 0)
        self.assertEqual(self.request_uris()[-1], "/r29")

    def test_split_arrows_switch_focus(self):
        self.make()
        self.traffic()
        self.render()
        self.assertIn("↑↓ select", self.term.lines()[-1])
        self.screen.handle_input("\x1b[C\x1b[A")  # focus requests, scroll up
        self.assertIsNone(self.screen.selected)  # the IP cursor didn't move
        self.assertEqual(self.screen._req_back, 1)
        self.render()
        self.assertIn("↑↓ scroll", self.term.lines()[-1])
        self.screen.handle_input("\x1b[D\x1b[B")  # back to the IPs, cursor down
        self.assertIsNotNone(self.screen.selected)
        self.assertEqual(self.screen._req_back, 1)
        self.screen.handle_input("\t\x1b[C")  # "ips" layout: no pane to switch to
        self.assertEqual(self.screen.focus, "ips")

    def test_layouts_cycle(self):
        self.make()
        self.traffic()
        self.screen.handle_input("\t")
        self.assertEqual(self.screen.layout, "ips")
        self.assertNotIn("Requests ·", self.render())
        self.screen.handle_input("\t")
        self.assertEqual(self.screen.layout, "stream")
        self.assertNotIn("IP ADDRESS", self.render())

    def test_narrow_terminal_fits_and_too_small_says_so(self):
        self.make(cols=64, rows=12)
        self.traffic()
        self.screen.handle_input("j")
        self.render()  # Term raises if anything would wrap
        self.assertIn("q quit", self.term.lines()[-1])
        self.assertIn("←→ pane", self.term.lines()[-1])
        self.make(cols=60, rows=10)
        self.assertIn("Terminal too small", self.render())

    def test_footer_without_keyboard(self):
        self.make(keys=False, layout="ips")
        self.assertIn("keys need a POSIX terminal", self.render())

    def test_quit_restores_terminal(self):
        self.make()
        with self.assertRaises(KeyboardInterrupt):
            self.screen.handle_input("q")
        self.screen.stop()
        self.term.feed(self.out.getvalue())
        self.assertFalse(self.term.alt)
        self.assertTrue(self.term.wrap)


if __name__ == "__main__":
    unittest.main()
