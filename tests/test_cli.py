"""End-to-end runs of caddy_traffic_monitor.py (plain/piped mode, no network:
every run uses --no-lookup, and the cache is either off or a temp file)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

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

    def test_obsolete_summary_option_is_harmless(self):
        res = run("-", "--no-lookup", "--no-cache", "-n", "5", stdin=SAMPLE,
                  env={"SUMMARY_EVERY": "10s"})
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("--summary-every", run("--help").stdout)

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
