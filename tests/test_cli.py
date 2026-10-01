"""The command line (caddymon.cli): argument handling and log resolution
in-process, plus end-to-end runs of caddy_traffic_monitor.py (plain/piped
mode, no network: every run uses --no-lookup, and the cache is either off or
a temp file)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from caddymon.cli import DEFAULT_LOG, parse_args, resolve_logs
from caddymon.output import Palette

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "caddy_traffic_monitor.py")

SAMPLE = "\n".join(json.dumps(r) for r in [
    {"ts": 1790000000, "status": 200, "request": {"method": "GET", "remote_ip": "8.8.8.8", "uri": "/"}},
    {"ts": 1790000001, "status": 403, "request": {"method": "GET", "remote_ip": "1.1.1.1", "uri": "/wp-login.php"}},
    {"ts": 1790000002, "status": 403, "request": {"method": "GET", "remote_ip": "1.1.1.1", "uri": "/.env"}},
    {"ts": 1790000003, "status": 200, "request": {"method": "POST", "remote_ip": "192.168.1.20", "uri": "/api"}},
    {"ts": 1790000004, "status": 500, "request": {"method": "GET", "remote_ip": "127.0.0.1", "uri": "/boom"}},
]) + "\ngarbage line\n"


def run(*args, stdin=None, env=None, timeout=30):
    full_env = dict(os.environ, PYTHONIOENCODING="utf-8", **(env or {}))
    return subprocess.run([sys.executable, SCRIPT, *args], input=stdin, capture_output=True,
                          text=True, encoding="utf-8", env=full_env, timeout=timeout)


def run_until(*args, want, timeout=20):
    """Start a run that follows logs (so it never ends by itself), wait until
    every string in ``want`` has appeared on stdout or stderr, then kill it.
    Returns everything it printed (stdout, then stderr)."""
    proc = subprocess.Popen([sys.executable, SCRIPT, *args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, encoding="utf-8",
                            env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    out, err = [], []
    readers = [threading.Thread(target=lambda s=s, buf=buf: buf.extend(s), daemon=True)
               for s, buf in ((proc.stdout, out), (proc.stderr, err))]
    for reader in readers:
        reader.start()
    try:
        deadline = time.monotonic() + timeout
        while not all(w in "".join(out + err) for w in want):
            if proc.poll() is not None or time.monotonic() > deadline:
                raise AssertionError(f"never saw {want}:\n{''.join(out + err)}")
            time.sleep(0.05)
    finally:
        proc.kill()
        proc.wait()
        for reader in readers:
            reader.join(5)
        proc.stdout.close()
        proc.stderr.close()
    return "".join(out + err)


class ResolveLogsTests(unittest.TestCase):
    """cli.resolve_logs(), in-process: which logs get followed, and the errors
    and notes on stderr (main() returns 1 when it gives None)."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.live = self.touch("www.example.com.log")
        self.rotated = self.touch("www.example.com-2026-09-30T00-00-00.000.log")

    def touch(self, name):
        path = os.path.join(self.dir, name)
        open(path, "w").close()
        return path

    def resolve(self, paths, from_start=False):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            result = resolve_logs(paths, from_start, Palette(False))
        return result, err.getvalue()

    def test_rotated_logs_are_skipped_when_tailing(self):
        result, err = self.resolve([self.live, self.rotated])
        self.assertEqual(result, [self.live])
        self.assertIn("skipping 1 rotated log(s): www.example.com-2026", err)

    def test_rotated_logs_are_read_with_from_start(self):
        result, err = self.resolve([self.live, self.rotated], from_start=True)
        self.assertEqual(result, [self.live, self.rotated])
        self.assertEqual(err, "")

    def test_only_rotated_logs_is_an_error_when_tailing(self):
        result, err = self.resolve([self.rotated])
        self.assertIsNone(result)
        self.assertIn("--from-start", err)

    def test_one_of_several_logs_missing(self):
        result, err = self.resolve([self.live, os.path.join(self.dir, "gone.log")])
        self.assertIsNone(result)
        self.assertIn("gone.log", err)

    def test_paths_in_messages_are_cleaned(self):
        result, err = self.resolve([os.path.join(self.dir, "evil\x1b]0;pwned\x07.log")])
        self.assertIsNone(result)
        self.assertIn("evil?]0;pwned?.log", err)
        self.assertNotIn("\x07", err)

    def test_stdin_passes_through(self):
        self.assertEqual(self.resolve(["-"]), (["-"], ""))


class CliTests(unittest.TestCase):
    def test_plain_replay_and_summary(self):
        res = run("-", "--no-lookup", "--no-cache", stdin=SAMPLE)
        self.assertEqual(res.returncode, 0, res.stderr)
        out = res.stdout
        self.assertIn("✗ 403   GET    1.1.1.1         /wp-login.php", out)
        self.assertIn("SUMMARY (5 requests)", out)
        self.assertIn("── Top IPs ──", out)
        self.assertIn("└─ private network", out)
        self.assertIn("── Top denied IPs (403) ──", out)
        self.assertNotIn("garbage", out)

    def test_poll_must_be_positive(self):
        for value in ("0", "-1", "nan", "inf", "x"):
            with self.subTest(value=value):
                res = run("--poll", value, "-", stdin="")
                self.assertEqual(res.returncode, 2)
                self.assertIn("positive", res.stderr)

    def test_missing_log_fails_fast_even_with_from_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = run(os.path.join(tmp, "nope.log"), "--from-start", "--no-cache", timeout=10)
        self.assertEqual(res.returncode, 1)
        self.assertIn("not found", res.stderr)

    def test_several_logs_stream_with_a_site_column(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = []
            for site, ip in (("www.example.com", "8.8.8.8"), ("shop.example.com", "1.1.1.1")):
                paths.append(os.path.join(tmp, site + ".log"))
                with open(paths[-1], "w", encoding="utf-8") as f:
                    f.write(json.dumps({"ts": 1790000000, "status": 404, "request": {
                        "method": "GET", "remote_ip": ip, "uri": "/" + site}}) + "\n")
            out = run_until(*paths, "--from-start", "--no-lookup", "--no-cache",
                            want=["GET    www.example.com  8.8.8.8",
                                  "GET    shop.example.com 1.1.1.1"])
        self.assertIn("Logs: ", out)
        self.assertIn("SITE", out)

    def test_log_list_arguments(self):
        with mock.patch.dict(os.environ, {"CADDY_LOG_FILE": os.pathsep.join(["a.log", "b.log"])}):
            self.assertEqual(parse_args([]).log_files, ["a.log", "b.log"])
        with mock.patch.dict(os.environ, {"CADDY_LOG_FILE": ""}):
            self.assertEqual(parse_args([]).log_files, [DEFAULT_LOG])
        self.assertEqual(parse_args(["a.log", "./a.log", "b.log"]).log_files, ["a.log", "b.log"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parse_args(["-", "a.log"])

    def test_no_lookup_reads_cache_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = os.path.join(tmp, "rdap_cache.json")
            with open(cache, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "networks": {
                    "1.1.1.0/24": ["APNIC Research and Development (AU)", time.time() + 3600]}}, f)
            res = run("-", "--no-lookup", "--cache", cache, stdin=SAMPLE)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("└─ APNIC Research and Development (AU)", res.stdout)

    def test_cache_path_in_missing_directory_is_harmless(self):
        # (The save-failure path itself is covered in test_rdap.RangeCacheTests.)
        with tempfile.TemporaryDirectory() as tmp:
            res = run("-", "--no-lookup", "--cache", os.path.join(tmp, "missing", "c.json"),
                      stdin=SAMPLE)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("SUMMARY", res.stdout)

    def test_python_dash_m_matches_script(self):
        script = run("-", "--no-lookup", "--no-cache", stdin=SAMPLE).stdout
        module = subprocess.run([sys.executable, "-m", "caddymon", "-", "--no-lookup", "--no-cache"],
                                input=SAMPLE, capture_output=True, text=True, encoding="utf-8",
                                cwd=ROOT, env=dict(os.environ, PYTHONIOENCODING="utf-8")).stdout
        strip = lambda s: [line for line in s.splitlines() if "Started:" not in line]
        self.assertEqual(strip(script), strip(module))


if __name__ == "__main__":
    unittest.main()
