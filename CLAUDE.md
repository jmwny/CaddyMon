# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Python tool that tails a Caddy JSON access log and shows live traffic in an htop-style terminal view — grouped client IPs (with each IP's owner) above the newest requests — plus an on-exit summary. Non-TTY output is a plain color-coded request stream. Standard library only — no third-party packages, no `jq`, no build system. Deployed as a set of files: the entry script plus the `caddymon/` package next to it.

| File | What lives there |
|---|---|
| `caddy_traffic_monitor.py` | Entry script (usage docstring) → `caddymon.cli.run()`. `python -m caddymon` is equivalent. |
| `caddymon/text.py` | `clean()` (control-char stripping), `vlen()`/`clip()` (ANSI-aware width). No internal deps. |
| `caddymon/logsource.py` | `Record`, `parse_line()`, `format_ts()`, `follow()`, `iter_stdin()`. |
| `caddymon/stats.py` | `CLASSES`, `classify()`, `marker()`, `IpStat`, `Stats` (bounded). |
| `caddymon/rdap.py` | Owner lookups: `RateLimiter`, `RangeCache`, `RdapBootstrap`, `OwnerResolver`, `offline_label()`. |
| `caddymon/output.py` | `Palette`, `render_row()`, `class_breakdown()`, `Display` (plain header + exit summary). |
| `caddymon/screen.py` | Interactive `Screen`, `RateMeter`, `parse_keys()`. |
| `caddymon/cli.py` | `DEFAULT_LOG`/`DEFAULT_CACHE`, `parse_args()`, `main()` (the follow loop), `run()`. |
| `tests/` | `unittest` suite (stdlib only, no network — fake local servers). |

Internal imports (keep them acyclic): `text` → none; `logsource` → text; `stats` → logsource; `rdap` → text; `output` → logsource, stats, rdap; `screen` → text, logsource, stats, rdap, output; `cli` → everything. In particular `rdap` stays independent of the display and stats layers.

(There is no longer a Bash version; this is a from-scratch Python rewrite of the original `caddy_traffic_monitor.sh`.)

## Running

```bash
sudo python3 caddy_traffic_monitor.py [LOG_FILE] [options]
python -m unittest discover -s tests        # run the tests from the project root
```

- Requires Python 3.7+ and read access to the log file. No external dependencies.
- Default log path is `/var/log/caddy/denied_access.log`. Override with the positional `LOG_FILE` argument or the `CADDY_LOG_FILE` env var. Pass `-` to read from stdin (handy for replaying a captured dump).
- Expects Caddy's JSON log format: each line is a JSON object with `.status`, `.request.method`, `.request.remote_ip`, `.request.uri`, and `.ts` (epoch seconds; an RFC3339 string is also tolerated).
- Exit with Ctrl+C; it runs an infinite native follow.
- Options: `--layout split|ips|stream` (default split; `-g/--group` = `--layout ips`), `--suspect N` (⚠ an IP with N+ 4xx and no 2xx; 0 disables), `--no-lookup` (no RDAP/reverse-DNS queries; cached owners still show), `--cache PATH` (default `rdap_cache.json` next to the entry script, i.e. the folder containing `caddymon/`), `--no-cache`, `--from-start` (read the whole file instead of tailing), `--no-color`, `--poll SECONDS` (idle poll interval). `-n/--summary-every` is still accepted but hidden and never parsed (the live header replaced periodic summaries; `SUMMARY_EVERY` is ignored). `--poll` must be positive. A log path missing at startup exits 1, with or without `--from-start`. `--help` lists everything.
- Interactive keys (POSIX TTY only — no `termios` on Windows): `↑`/`↓` (`j`/`k`), PgUp/PgDn, Home/End move the IP cursor or scroll the request pane, whichever has focus (`←`/`→` or `h`/`l` switch it in split; the stream layout always scrolls; `End` = live); `Enter` follows the selected IP in the request pane, `Esc` back to all IPs (and live); `Tab` (or `g`) cycles the layout; `a`/`0` all codes, `2`–`5` one status class; `s` toggles IP sort (recent / hits); `q` quit.

## Testing

- `python -m unittest discover -s tests` from the project root (about 15 s). Stdlib only; no test touches the network — registries, IANA bootstrap files and rdap.org are fake servers on `127.0.0.1`/`localhost` (`tests/helpers.FakeServer`), reverse DNS is stubbed, and CLI runs use `--no-lookup`.
- Screen tests replay output onto `tests/helpers.Term` (a virtual terminal that fails if anything would wrap).
- Rotation is simulated by patching `os.stat` (Windows can't rename an open file), so real rename-rotation is only exercised on Linux/macOS by hand.
- Add a test with every behaviour change; for rate-limit changes, assert on the arrival times the fake servers record.

## Architecture notes

- **Native log following (replaces `tail -Fn0`).** `follow()` opens the file in binary mode, seeks to the end on first open, and reads incrementally in bounded `READ_CHUNK` (1 MiB) pieces — never `read()` the whole file. On rotation it drains the old handle (plus any unterminated last line) before reopening; on truncation it also discards the stale partial line in `buf`; while the path is missing it still `yield None`s every poll so the UI keeps servicing keys/redraws. It survives Caddy's default log rotation by comparing the open file's `(st_dev, st_ino)` against the path's on disk — when they differ the file was rotated, so it reopens and reads the new file from the start. It also rewinds on in-place truncation (`tell() > size`) and retries with a poll delay when the path is temporarily missing. Don't reintroduce a dependency on the external `tail`; the rotation handling is the whole point.
- **Partial-line buffering.** Reads are split on `\n` with `*lines, buf = data.split(b"\n")`, so an incomplete trailing line is held in `buf` until its newline arrives. Bytes are decoded with `errors="replace"` so a garbled line can't crash the stream.
- **Counters live in `cli.main()`'s scope.** The `SIGINT`/`SIGTERM` handler raises `KeyboardInterrupt`, which unwinds into a `finally` that prints the final summary with the real running totals (`Stats.total`, `classes`, `denied_ips`, `paths`). Keep the accumulation in the same frame as the handler/`finally` so the exit summary stays accurate.
- **Status classification lives only in `classify()`.** `Palette.style_for()` (via `CLASS_STYLE`, from `CLASSES`) and `marker()` (via `CLASS_MARKER`: ✓ / → / ✗, and `·` for "other" such as 101 upgrades) derive from it — don't reintroduce range checks elsewhere.
- **One JSON parse per line, and `parse_line()` never raises.** It does `json.loads` once and drops any record without a usable numeric `.status` (mirroring the original jq `select`; NaN/Infinity, which Python's json accepts, are rejected). Fields go through `_field()`: anything that isn't a non-empty string becomes a default, so a list/number/null can't crash `Stats`. `format_ts()` swallows out-of-range timestamps.
- **Untrusted text is cleaned at ingestion with `clean()`** (C0/DEL/C1 control characters become `?`): log fields, RDAP names/country (`_vcard_fn`, `_rdap_org`, `_rdap`), reverse DNS (`_rdns`), and owners loaded from the cache file. Anything new that brings outside text in must go through `clean()` too — otherwise it can inject terminal escape sequences (OSC 52 clipboard writes, retitling, cursor moves) and break `vlen()`/`clip()` width math.
- **Stats are bounded for long runs.** `total`/`classes` are exact; `ips`, `paths`, `denied_ips` are capped at `Stats.MAX_*` and cut back to half when exceeded (`_prune_ips()` keeps a quarter by (hits, recency) plus a quarter by recency, pruning *before* inserting the new IP). `Stats.on_evict` → `OwnerResolver.forget()` drops the resolver's per-IP state for evicted IPs. `Screen._ip_entries()` is memoised on `(stats.total, filter, sort)` — treat its list as read-only.
- **403s** are tracked per-IP in `Stats.denied_ips` and surfaced as "Top denied IPs" in the summary; request paths (query string stripped) are tracked in `Stats.paths` and surfaced as "Top paths".
- **Per-IP stats:** `Stats.ips` maps IP → `IpStat` (hits, per-class `Counter`, last time, `last_seq` for "most recent" ordering). It feeds both the IP pane and the summary's "Top IPs".
- **`Screen` is frame-based (htop-style), on the alternate screen.** `_compose()` builds the whole frame as a list of lines — header, IP pane, request pane, footer, depending on `layout` (`split`/`ips`/`stream`) — and `draw()` rewrites only lines that changed since the last frame (each ends with erase-to-EOL, so no flicker). Autowrap is off for the session and every line goes through `clip()` (ANSI-aware) to `cols - 1`, so nothing can wrap or scroll; use `vlen()`, not `len()`, to measure styled text. Redraws: immediately on a key, at most every `FRAME_INTERVAL` for new data or new owners, and at least every `HEARTBEAT` so the clock/rate stay live. `start()`/`stop()` enter/leave the alternate screen and hide/restore the cursor and autowrap — `stop()` must run (it's in `main()`'s `finally`) before the summary prints.
- **IP pane:** two lines per IP (stats, then the owner on a `└─` connector; the summary's IP lists use the same layout), zeros as a dim `·`, `⚠` from `_is_suspect()`. The cursor (`selected`) and `follow` are tracked by IP string, not row index, because "recent" order reshuffles constantly; `_ip_offset` scrolls to keep the cursor visible. The request pane reads the last N matching `Record`s from `Screen.history` (5,000) at draw time (filtered by `_shows()`: status class and `follow`).
- **Pane focus and request scrolling:** `NAV_KEYS` go to `_focused()` — `focus` in split, the only pane otherwise — and are handled by `_navigate()` (IP cursor) or `_scroll()` (requests). `_req_back` counts matching requests hidden below the view (0 = live); `add()` bumps it for each new match so a scrolled view stays put, and `_request_pane()` clamps it (history evicts the oldest; the filter can shrink the set). Changing the filter or `follow` (`Enter`/`Esc`) resets it to live. Live, the pane stops scanning once it's full; scrolled back, it scans all of history for the `X–Y of N` position.
- **Keys:** `drain_keys()` passes each raw read to `Screen.handle_input()`, which uses `parse_keys()` to turn escape sequences into names (`up`, `pgdn`, `esc`, ...) — don't iterate raw characters, or arrow keys split into ESC + `[` + `A`.
- **Rolling rate:** `RateMeter` counts arrivals in 1 s buckets over 60 s (rate + sparkline). Because a `--from-start` backlog arrives all at once, `main()` calls `screen.backlog_done()` on the follower's first idle tick, which resets the meter once.
- **Resize is async-signal-safe:** the SIGWINCH handler only sets a flag; `service()` (called by the main loop after every row and idle tick) does the redraw. Never write to stdout from a signal handler or a worker thread.
- **`OwnerResolver` (IP owner lookups).** RDAP (registrant name + country; falls back to the network name) sent directly to the registry chosen by `RdapBootstrap` from IANA's bootstrap files (`BOOTSTRAP_URLS`, fetched once per run; `https://rdap.org/ip/<ip>` is only the fallback when they can't be fetched), plus `socket.gethostbyaddr`. Runs on daemon worker threads; `lookup()` never blocks — it returns cached/partial text or `None` ("resolving…") and queues the IP. Only IPs actually drawn (and the summary's top IPs) are looked up. Block owners live in `RangeCache` (below), so other IPs in the same block skip the query; concurrent lookups in the same /24 (/48) wait for the one in flight (`_inflight`, `BLOCK_WAIT`) instead of querying twice. The org is published before reverse DNS runs, because a missing PTR can stall ~10s. Ordinary failures retry after `RETRY_AFTER`. Workers must never write to stdout — they set `updated` and the main loop redraws. Private/loopback/reserved addresses get offline labels and no RDAP query. `--no-lookup` disables all network access (the local cache is still read). All RDAP traffic is rate-limited — see below.
- **`RangeCache` (persistent RDAP cache).** Network range → owner, persisted as JSON at `DEFAULT_CACHE` (`rdap_cache.json` beside the script; `--cache`/`--no-cache`). Stores **only ranges, never client IPs or hostnames** — keep it that way (privacy; registry terms forbid redistribution). TTLs: `TTL_FOUND` 30 d for a named owner, `TTL_EMPTY` 1 d for a known block with no name; failures/rate-limited answers are never stored. `put()` saves at most every `SAVE_EVERY`; `main()`'s `finally` calls `save()` after the summary. `save()` merges with the on-disk file (other instances), prunes expired, caps at `MAX_ENTRIES`, and writes a 0600 temp file + `os.replace`. A failed save sets `error` (reported on stderr at exit) and disables further saves; a missing/corrupt file loads as empty.
- **Config:** `CADDY_LOG_FILE` / positional arg for the log path. Colors auto-disable when stdout is not a TTY or `--no-color` is set.
- **UTF-8 I/O is forced in `main()`.** A redirected stdout otherwise uses the locale encoding (cp1252 on Windows), which can't encode the box-drawing/marker glyphs, so stdout is reconfigured to UTF-8 (`errors="replace"`) alongside line buffering, and stdin (the `-` replay source) is decoded as UTF-8 with replacement to match `follow()`. It runs before `parse_args()` so `--help` and usage errors are covered too; keep it before any output.

## RDAP rate limits

The registries ban clients that ignore their limits, so every RDAP request is paced. Don't add a code path that sends HTTP requests without going through this.

| Host | `RDAP_LIMITS` entry | Source |
|---|---|---|
| `rdap.org` (fallback only) | 10 per 10 s | Published: "a maximum of 10 requests in 10 seconds", 429 when exceeded (about.rdap.org). |
| `rdap.lacnic.net` | 10 per 60 s **and** 1000 per 3600 s | **Not published.** LACNIC's RDAP page only says Whois restrictions apply. Historical figures: 100/5 min + 1000/60 min (LACNIC on the IETF weirds list, Apr 2013, returned HTTP 403) and 10/min (secynic/ipwhois#104, 2016, unsourced). The entry takes the strictest of each. Update it if LACNIC ever documents limits. |
| anything else | `RDAP_DEFAULT_LIMIT` = 10 per 10 s | Conservative default for ARIN/RIPE/APNIC/AFRINIC. |

How it's enforced (all in `RateLimiter` / `OwnerResolver._fetch_json`):

- **Every request goes through `RateLimiter.slot(host)`.** Sliding windows over send times, each stretched by `MARGIN` (10%), and at most one request in flight per host.
- **Redirects are followed by hand** (`_NoRedirect` + `_fetch_json`, max `MAX_REDIRECTS`). Registries redirect for space transferred between them (e.g. ARIN → RIPE), as does the rdap.org fallback; each hop is paced against its own host. Never go back to `urlopen`'s automatic redirects, or the registry hop escapes its limit.
- **"Slow down" responses** are `RATE_LIMIT_CODES` = 429, 503, and 403 (LACNIC has used 403 for "rate limit exceeded"). They call `backoff(host, retry_after_seconds(...))` *before* the slot is released, so no other request to that host can slip in. Then `RateLimited(host, retry_in)` is raised. `Retry-After` may be seconds or an HTTP date; it defaults to 60 s when missing and is capped at 1 h.
- **Workers never park on a busy host.** Before each request `_fetch_json` checks `limiter.delay(host)`; above `MAX_WAIT` (5 s) it raises `RateLimited` without sending. `_work` treats `RateLimited` as a *deferral*: the IP leaves `_pending`, gets `_retry_at = now + retry_in`, keeps its displayed text, and `lookup()` re-queues it only once due (and only while it's on screen). No attempt counter — don't reintroduce blocking waits or a retry loop inside workers, or one throttled registry stalls all lookups.
- **Demand shaping:** the queue is LIFO (what was just drawn goes first), and entries not asked for via `lookup()` within `STALE_AFTER` (30 s) are dropped without a request. `lookup()` is called on every frame for visible IPs, which keeps them fresh.
- **Testing:** never test against the live services in a loop. Point `OwnerResolver.RDAP_URL` at a local `http.server` that redirects to a second local server (use `127.0.0.1` vs `localhost` so they count as different hosts), override `RDAP_LIMITS` with small windows, and assert on the arrival times the servers log. Set `OwnerResolver.BOOTSTRAP_URLS = {}` to exercise the rdap.org-fallback path, or point it at a local server serving a bootstrap JSON (`{"services": [[["203.0.0.0/16"], ["http://127.0.0.1:PORT/"]]]}`); use public-looking test ranges, since documentation ranges like 198.51.100.0/24 get offline labels and are never looked up. One real lookup is fine as a smoke test.
