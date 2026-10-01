"""Log parsing and native following (caddymon.logsource, caddymon.text)."""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from caddymon import logsource
from caddymon.logsource import follow_many, is_rotated, parse_line, site_labels
from caddymon.stats import Stats
from caddymon.text import clean


def lines_until(gen, n):
    """Next ``n`` real lines from a one-file follow_many() generator, without
    their path and skipping idle ticks."""
    return [line for _path, line in items_until(gen, n)]


class ParseLineTests(unittest.TestCase):
    def test_normal_record(self):
        rec = parse_line('{"status":404,"ts":1790000000.5,"request":'
                         '{"method":"GET","remote_ip":"45.148.10.23","uri":"/.env"}}')
        self.assertEqual((rec.status, rec.method, rec.ip, rec.uri), (404, "GET", "45.148.10.23", "/.env"))
        self.assertRegex(rec.time, r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$")
        self.assertEqual(rec.site, "")
        self.assertEqual(parse_line('{"status":200}', "www.example.com").site, "www.example.com")

    def test_non_access_lines_are_dropped(self):
        for line in ["", "   ", "garbage", "[1,2]", '"text"', '{"msg":"no status"}',
                     '{"status":"200"}', '{"status":true}']:
            with self.subTest(line=line):
                self.assertIsNone(parse_line(line))

    def test_odd_but_valid_json_never_raises(self):
        # Each of these used to crash the monitor (in parse_line or Stats).
        odd = [
            '{"status":200,"request":{"remote_ip":["1.2.3.4"],"uri":"/"}}',
            '{"status":200,"request":{"remote_ip":"1.2.3.4","uri":5}}',
            '{"status":200,"ts":1e20,"request":{"remote_ip":"1.2.3.4"}}',
            '{"status":200,"ts":NaN,"request":{}}',
            '{"status":200,"request":{"method":{"x":1},"uri":null}}',
            "[" * 100000 + "]" * 100000,
        ]
        stats = Stats()
        for line in odd:
            with self.subTest(line=line[:40]):
                rec = parse_line(line)
                if rec is not None:
                    stats.record(rec)
                    self.assertIsInstance(rec.ip, str)
                    self.assertIsInstance(rec.uri, str)
                    self.assertIsInstance(rec.method, str)
        self.assertEqual(parse_line(odd[0]).ip, "unknown")

    def test_non_finite_status_is_dropped(self):
        for status in ["NaN", "Infinity", "-Infinity", "1e400"]:
            with self.subTest(status=status):
                self.assertIsNone(parse_line('{"status":%s}' % status))

    def test_control_characters_are_neutralised(self):
        rec = parse_line(r'{"status":200,"request":{"remote_ip":"1.2.3.4","method":"GET",'
                         r'"uri":"/x\u001b]52;c;SGk=\u0007\u009b2J"}}')
        for ch in "\x1b\x07\x9b":
            self.assertNotIn(ch, rec.uri)
        self.assertEqual(clean("a\x00b\x7fc\x85d\te"), "a?b?c?d?e")
        self.assertEqual(clean("Café ✓ 東京"), "Café ✓ 東京")  # printable text untouched


class FollowTests(unittest.TestCase):
    def setUp(self):
        # Cleanups run last-in-first-out, after each test's gen.close(), so the
        # log is closed before the directory goes (Windows won't delete an
        # open file).
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "access.log")

    def write(self, data: bytes, mode="ab"):
        with open(self.path, mode) as f:
            f.write(data)

    def test_missing_file_still_ticks(self):
        gen = follow_many([self.path], from_start=True, poll=0.01)
        self.addCleanup(gen.close)
        # Must hand control back (None) rather than block while missing.
        self.assertIsNone(next(gen))
        self.assertIsNone(next(gen))
        self.write(b"a\nb\n")
        self.assertEqual(lines_until(gen, 2), ["a", "b"])

    def test_tail_mode_skips_existing_content(self):
        self.write(b"old\n")
        gen = follow_many([self.path], from_start=False, poll=0.01)
        self.addCleanup(gen.close)
        self.assertIsNone(next(gen))
        self.write(b"new\n")
        self.assertEqual(lines_until(gen, 1), ["new"])

    def test_partial_line_waits_for_newline(self):
        self.write(b"")
        gen = follow_many([self.path], from_start=True, poll=0.01)
        self.addCleanup(gen.close)
        self.write(b"hel")
        self.assertIsNone(next(gen))
        self.write(b"lo\n")
        self.assertEqual(lines_until(gen, 1), ["hello"])

    def test_rotation_keeps_lines_written_during_the_switch(self):
        # The writer appends its last lines to the OLD file just as the path
        # is switched. Simulated through os.stat (which also reports the new
        # inode) because Windows can't rename a file that's held open.
        self.write(b"a\n")
        gen = follow_many([self.path], from_start=True, poll=0.01)
        self.addCleanup(gen.close)
        self.assertEqual(lines_until(gen, 1), ["a"])
        self.assertIsNone(next(gen))
        real_stat = os.stat
        state = {"raced": False}

        def racing_stat(p, *args, **kwargs):
            if p == self.path and not state["raced"]:
                state["raced"] = True
                self.write(b"c\nd-no-newline")
                st = real_stat(p, *args, **kwargs)
                return os.stat_result((st.st_mode, st.st_ino + 12345, st.st_dev) + tuple(st)[3:])
            return real_stat(p, *args, **kwargs)

        with mock.patch.object(logsource.os, "stat", racing_stat):
            self.assertEqual(lines_until(gen, 2), ["c", "d-no-newline"])
        self.write(b"e\n", mode="wb")  # the "new" file
        self.assertEqual(lines_until(gen, 1), ["e"])

    def test_truncation_drops_stale_partial_line(self):
        self.write(b"one\n")
        gen = follow_many([self.path], from_start=True, poll=0.01)
        self.addCleanup(gen.close)
        self.assertEqual(lines_until(gen, 1), ["one"])
        self.write(b"partial")
        self.assertIsNone(next(gen))
        self.write(b"fresh\n", mode="wb")  # truncated and rewritten, shorter
        self.assertEqual(lines_until(gen, 1), ["fresh"])

    def test_large_backlog_streams_in_chunks(self):
        with open(self.path, "wb") as f:
            for i in range(60000):  # ~4 MB: several 1 MiB reads
                f.write(b'{"status":200,"request":{"uri":"/%d"}}\n' % i)
        gen = follow_many([self.path], from_start=True, poll=0.01)
        self.addCleanup(gen.close)
        count = 0
        for item in gen:
            if item is None:
                break
            count += 1
        self.assertEqual(count, 60000)


    @mock.patch.object(logsource.Follower, "READ_CHUNK", 8)
    @mock.patch.object(logsource.Follower, "MAX_LINE", 16)
    def test_over_long_line_is_dropped_and_memory_bounded(self):
        # A file with no newlines (the wrong file, say) mustn't be buffered
        # whole: the over-long line is dropped up to its newline.
        self.write(b"a\n" + b"x" * 200 + b"\nb\n" + b"y" * 200)
        follower = logsource.Follower(self.path, from_start=True)
        self.addCleanup(follower.close)
        got, biggest = [], 0
        while True:
            lines = follower.step()
            if lines is None:
                break
            got += lines
            biggest = max(biggest, len(follower._buf))
        self.assertEqual(got, ["a", "b"])
        self.assertLessEqual(biggest, 16)
        self.write(b"\nc\n")  # the second over-long line ends; then a real one
        self.assertEqual(follower.step(), ["c"])


class FollowManyTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def path(self, name):
        return os.path.join(self.dir.name, name)

    def test_files_take_turns(self):
        # A big backlog in one log mustn't hold up the others: one chunk each.
        big, small = self.path("big.log"), self.path("small.log")
        with open(big, "wb") as f:
            for i in range(40000):  # ~4 MB: several 1 MiB reads
                f.write(b"%099d\n" % i)
        with open(small, "wb") as f:
            f.write(b"hello\n")
        gen = follow_many([big, small], from_start=True, poll=0.01)
        self.addCleanup(gen.close)
        seen = []
        for item in gen:
            if item is None:
                break
            seen.append(item[0])
        self.assertEqual(seen.count(big), 40000)
        self.assertLess(seen.index(small), 20000)  # after big's first chunk

    def test_lines_are_tagged_and_missing_files_wait(self):
        a, b = self.path("a.log"), self.path("b.log")
        gen = follow_many([a, b], from_start=True, poll=0.01)
        self.addCleanup(gen.close)
        self.assertIsNone(next(gen))  # both missing: still ticks
        with open(b, "wb") as f:
            f.write(b"from-b\n")
        self.assertEqual(items_until(gen, 1), [(b, "from-b")])
        with open(a, "wb") as f:
            f.write(b"from-a\n")
        self.assertEqual(items_until(gen, 1), [(a, "from-a")])

    def test_is_rotated(self):
        for name, rotated in [
            ("www.example.com.log", False),
            ("access.log", False),
            ("www.example.com-2026-10-01T12-00-00.000.log", True),
            ("access-2026-10-01T12-00-00.000.log.gz", True),
            ("access-2026-10-01T12-00-00.000", True),
            ("2026-10-01.log", False),
        ]:
            with self.subTest(name=name):
                self.assertEqual(is_rotated(os.path.join("/var/log/caddy", name)), rotated)

    def test_site_labels(self):
        self.assertEqual(
            site_labels(["/var/log/caddy/www.example.com.log", "/var/log/caddy/shop.example.com.log"]),
            {"/var/log/caddy/www.example.com.log": "www.example.com",
             "/var/log/caddy/shop.example.com.log": "shop.example.com"})
        # Same file name in different folders: the folder tells them apart.
        self.assertEqual(
            list(site_labels(["/srv/a.com/access.log", "/srv/b.com/access.log", "x.json"]).values()),
            ["a.com/access", "b.com/access", "x.json"])
        # Still the same one folder up: as many folders as it takes.
        self.assertEqual(
            list(site_labels(["/srv/a/logs/access.log", "/var/b/logs/access.log",
                              "/srv/a/logs/other.log"]).values()),
            ["a/logs/access", "b/logs/access", "other"])
        # Only the ".log" differs: keep it rather than give two logs one label.
        # (Full path by then, so "C:/x/..." on Windows.)
        labels = list(site_labels(["/x/a", "/x/a.log"]).values())
        self.assertNotEqual(labels[0], labels[1])
        self.assertTrue(labels[0].endswith("x/a") and labels[1].endswith("x/a.log"), labels)

    def test_site_labels_are_cleaned(self):
        # File names are outside text too: no escape sequences to the terminal.
        label = site_labels(["/var/log/evil\x1b]0;pwned\x07.log"])["/var/log/evil\x1b]0;pwned\x07.log"]
        self.assertEqual(label, "evil?]0;pwned?")


def items_until(gen, n):
    """Next ``n`` real items from a follow_many() generator, skipping idle ticks."""
    got = []
    for _ in range(500):
        item = next(gen)
        if item is not None:
            got.append(item)
            if len(got) == n:
                return got
    raise AssertionError(f"only got {got}")


if __name__ == "__main__":
    unittest.main()
