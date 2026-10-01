# Caddy Traffic Monitor

A live, htop-style terminal view of [Caddy](https://caddyserver.com/) JSON access logs: one log, or one per site, all at once. Requests are grouped by client IP, so a scanner hammering your server shows up as one line with a running count instead of hundreds of rows. Each IP line also shows who owns the address.

```
 CADDY MONITOR  access.log  up 1h12m │ 1,284 req  4.1/s  ▁▂▁▃▇▅▂▁▁▂▃▁▁▂▁ │ 2xx 212  3xx 18  4xx 1,049  5xx 5
─ IPs 37 · by recent · all codes ──────────────────────────────────────────────────── 1–4 of 37 ─
  IP ADDRESS             HITS  2xx  3xx  4xx  5xx  LAST
▶ 45.148.10.23            412    ·    ·  412    ·  14:02:11  ⚠  ◀ following
  └─ TECHOFF SRV LIMITED (AD)
  66.249.66.1              37   35    2    ·    ·  14:02:09
  └─ Google LLC · crawl-66-249-66-1.googlebot.com
  192.168.1.20             12   12    ·    ·    ·  14:01:50
  └─ private network
─ Requests · 45.148.10.23 · all codes ──────────────────────────────────────────── esc: all IPs ─
  14:02:10  ✗ 404  GET    /wp-login.php
  14:02:11  ✗ 404  GET    /.env
  14:02:11  ✗ 404  GET    /.git/config
 ↑↓ select   ←→ pane   ⏎ follow IP   esc all IPs   tab layout   a/2-5 filter   s sort   q quit
```

It's plain Python with no dependencies: a small entry script plus the `caddymon/` package next to it. It follows the logs natively and keeps going when Caddy rotates them.

## Requirements

- Python 3.7 or newer. Standard library only; nothing to install. Copy `caddy_traffic_monitor.py` and the `caddymon/` folder together; the `tests/` folder is optional.
- Read access to the Caddy logs, so usually `sudo`.
- Caddy writing JSON access logs, for example:

  ```caddyfile
  example.com {
      log {
          output file /var/log/caddy/access.log
          format json
      }
  }
  ```

## Usage

```bash
sudo python3 caddy_traffic_monitor.py [LOG_FILE ...] [options]
```

The default log path is `/var/log/caddy/denied_access.log`. Pass one or more different paths as arguments, or set `CADDY_LOG_FILE` (several paths separated by `:`). Quit with `q` or Ctrl+C, and a summary is printed on exit.

```bash
# Watch the default log
sudo python3 caddy_traffic_monitor.py

# Watch a specific log
sudo python3 caddy_traffic_monitor.py /var/log/caddy/access.log

# Watch several sites' logs at once
sudo python3 caddy_traffic_monitor.py /var/log/caddy/www.example.com.log /var/log/caddy/shop.example.com.log
sudo python3 caddy_traffic_monitor.py /var/log/caddy/*.log

# Load the whole file first, then keep following, IPs only
sudo python3 caddy_traffic_monitor.py /var/log/caddy/access.log --from-start --layout ips

# Replay a saved log (plain output)
python3 caddy_traffic_monitor.py - < access.log.1
```

## The screen

| Area | What it shows |
|---|---|
| **Header** | The log's file name (or the number of sites), total requests, request rate over the last 60 seconds with a sparkline, counts per status class, uptime. Less important parts drop off on narrow terminals, the sparkline first and the log name last. |
| **IP pane** | One entry per client IP: hits, a count for each status class (`·` means zero), when it was last seen, and the owner on the line below. |
| **Request pane** | The newest requests, from all IPs or only the IP you're following. Scroll back through the last 5,000 requests. |
| **Footer** | The keys that work right now. |

`⚠` marks a likely scanner: an IP with at least 10 client errors (4xx) and no successful (2xx) responses. Change the threshold with `--suspect N`; 0 turns the flag off. With several logs, an IP is also flagged once it has client errors and no successful responses on 2 or more of your sites, the pattern of a scanner probing every host you serve. Change that with `--suspect-sites M`; 0 turns it off.

### Keys

| Key | Action |
|---|---|
| `↑` `↓` / `j` `k` | Move the cursor over the IPs, or scroll the requests (PgUp/PgDn and Home/End work too) |
| `←` `→` / `h` `l` | In the split layout, switch between the IP pane and the request pane. The pane with focus has a bold title. |
| `Enter` | Show only the selected IP's requests |
| `Esc` | Back to all IPs, and to the newest requests |
| `Tab` / `g` | Cycle the layout: split → IPs only → requests only |
| `2` `3` `4` `5` | Show only that status class (both panes) |
| `a` / `0` | Show all status classes |
| `f` | With several logs: show one site at a time (all sites → each site → all sites) |
| `s` | Sort IPs by most recent or by most hits |
| `q` | Quit and print the summary |

The cursor stays on the same IP even when the list reorders. In the requests-only layout the arrow keys always scroll the requests. While you're scrolled back, the request pane title says `paused` and shows your position, and new requests don't move the view. `End` jumps back to the newest requests, and so does changing the filter or the followed IP. The screen needs at least 64×12 characters and redraws itself when the window is resized.

### Several sites

If Caddy writes one log per site, give the tool all of them. Each site is named after its log file, minus `.log`, so `www.example.com.log` becomes `www.example.com`. If two files have the same name in different folders, the folder is added in front.

- The header shows how many sites you're watching, and the request pane gets a site column.
- An IP that has visited more than one of your sites is marked `N sites`, and can earn a `⚠` (see above).
- `f` narrows everything to one site: the header's totals and rate, the IP pane's counts, and the request pane. Press it again for the next site, and after the last one you're back to all sites.
- The exit summary adds a "Per site" section.

Caddy names rotated copies like `www.example.com-2026-10-01T12-00-00.000.log`, so a `*.log` wildcard picks them up too. The tool skips them, with a note, because they never change. With `--from-start` it reads them, so you can still replay an old log.

## Who owns an IP?

Owners are looked up in the background, and the table updates as answers arrive:

- **Organization and country:** from the regional internet registries (ARIN, RIPE, APNIC, …) over RDAP. Each lookup goes straight to the right registry, using the address-to-registry tables that [IANA publishes](https://data.iana.org/rdap/). The tool downloads those tables once per run. If they can't be fetched, it falls back to the public redirect service at [rdap.org](https://rdap.org).
- **Hostname:** from reverse DNS.

Only IPs that are actually on screen (or in the exit summary) are looked up, and each result is cached. One lookup covers the IP's whole network block, so a scanner rotating through a subnet costs one query. Private, loopback and reserved addresses are labelled locally without any lookup.

The tool stays within the registries' published rate limits:

| Service | Limit the tool keeps to | Source |
|---|---|---|
| rdap.org (fallback only) | 10 requests per 10 seconds | [Published by rdap.org](https://about.rdap.org/) |
| LACNIC (Latin America) | 10 per minute, and 1,000 per hour | LACNIC publishes no current figures, so these are the strictest historical ones: [LACNIC 2013](https://mailarchive.ietf.org/arch/msg/weirds/S_izVPo3GOlYsMA8T1T8Ke_sESA/) (100 per 5 min, 1,000 per hour) and a [2016 report](https://github.com/secynic/ipwhois/issues/104) (10 per minute) |
| Other registries (ARIN, RIPE, APNIC, AFRINIC) | 10 requests per 10 seconds | rdap.org's pace, as a conservative default |

- Each window gets a 10% safety margin, and only one request per service is in flight at a time.
- Registries sometimes redirect a lookup to another registry, for address space that has moved between them. Every step of a redirect counts against its own service's limit.
- If a service signals "slow down", lookups to it pause for as long as its `Retry-After` header says, or 60 seconds if it doesn't say. The signal is HTTP 429 or 503, or 403, which LACNIC has used for "rate limit exceeded".
- A paused service doesn't hold anything else up. Lookups for it are set aside and tried again once the pause ends, if the IP is still on screen, while lookups to other registries carry on.
- IPs you scroll past are dropped from the lookup queue after 30 seconds. The most recently shown IPs are looked up first.

So on a busy screen, owners can take a little while to fill in. Entries show `resolving…` until their turn comes.

### The lookup cache

Registry answers are saved to `rdap_cache.json`, in the same folder as the script, so later runs show owners immediately and don't repeat lookups. Scanners and crawlers keep coming back, so after a few days most lookups are answered from the cache.

- **Only network blocks are stored,** such as `45.148.10.0/24 → TECHOFF SRV LIMITED (AD)`. Individual client IPs and hostnames are never written to the file.
- **Entries expire:** owners after 30 days, and blocks the registry knows but has no owner name for after 1 day. Failed or rate-limited lookups aren't saved.
- **When it's saved:** at most once a minute, and again on exit. Several copies can run at once, because each merges with the file rather than overwriting it.
- **File permissions:** the file is readable only by its owner, because it's a record of which networks have visited your server. If you run the tool with `sudo`, the file belongs to root, and later runs without `sudo` can't use it.
- **When it can't be saved:** if the folder isn't writable, the tool still works, just without the cache, and prints a note on exit.
- **Keep it to yourself.** Registry terms (LACNIC's, for example) forbid redistributing their data, so don't share or publish the cache file.

`--cache PATH` stores it somewhere else, and `--no-cache` turns it off. `--no-lookup` still uses the cache: reading a local file isn't a network query.

> **Privacy:** lookups send the IP addresses you're viewing to the registries (or to rdap.org, as a fallback) and to your DNS resolver. The tool also downloads IANA's registry tables. Use `--no-lookup` to turn off all network queries. Public IPs then show their owner if it's already in the [cache](#the-lookup-cache), and `(lookups off)` otherwise.

## Options

| Option | Default | Description |
|---|---|---|
| `LOG_FILE ...` | `/var/log/caddy/denied_access.log` | Logs to follow, one or more (or `CADDY_LOG_FILE`, `:`-separated). `-` on its own reads stdin. |
| `--from-start` | off | Read the existing file first instead of only new lines. |
| `--layout {split,ips,stream}` | `split` | Starting layout. `-g`/`--group` is short for `--layout ips`. |
| `--suspect N` | `10` | 4xx count (with no 2xx) that earns the `⚠` flag; 0 disables. |
| `--suspect-sites M` | `2` | With several logs, the number of sites with 4xx and no 2xx that earns the `⚠` flag; 0 disables. |
| `--no-lookup` | off | Don't look up IP owners over the network. Owners already in the cache still show. |
| `--cache PATH` | `rdap_cache.json` next to the script | Where registry answers are kept between runs. |
| `--no-cache` | off | Don't read or write the cache file. |
| `--no-color` | off | Disable colors. They also turn off automatically when output isn't a terminal. |
| `--poll SECONDS` | `0.5` | How often to check an idle log for new data. Must be a positive number. |

If any log file doesn't exist at startup, the tool exits with an error, with or without `--from-start`. If one disappears later, for example during log rotation, the tool waits for it to come back and stays responsive meanwhile.

## Piped output and the exit summary

When output isn't a terminal (piped to `grep`, redirected to a file, run under systemd), the tool prints a plain line per request instead of the interactive screen:

```
  2026-09-26 14:02:11 ✗ 404   GET    45.148.10.23    /.env
```

With several logs, each line also names the site.

Whichever mode you use, quitting prints a summary: totals per status class (and per site, with several logs), top IPs with their owners, top denied (403) IPs and top paths:

```
  ──────────────── SUMMARY (1284 requests) ────────────────
  2xx Success:    212
  3xx Redirect:   18
  4xx Client:     1049
  5xx Server:     5
  ── Top IPs ──
  412   → 45.148.10.23    4xx:412
          └─ TECHOFF SRV LIMITED (AD)
  37    → 66.249.66.1     2xx:35 3xx:2
          └─ Google LLC · crawl-66-249-66-1.googlebot.com
```

### Long runs

The tool is meant to be left running. Overall totals stay exact indefinitely. The per-IP, per-path and denied-IP tables are capped: 20,000 IPs and 5,000 paths or denied IPs. At the cap, a table is cut back to half, keeping the busiest and the most recently seen entries. So in "Top" lists on very long runs, counts for rarely seen entries may be slightly low, and IPs that were quiet for a long time can drop out.

Anything written to the terminal is cleaned of control characters first. That covers log fields, registry answers, hostnames and the cache file, so none of them can send escape sequences to your terminal.

## Development

The code is split by concern: log reading (`caddymon/logsource.py`), stats (`stats.py`), owner lookups (`rdap.py`), plain output (`output.py`), the interactive screen (`screen.py`) and the command line (`cli.py`). To run the tests from the project folder:

```bash
python -m unittest discover -s tests
```

They take about 20 seconds and never touch the network: the registries, IANA's tables and DNS are all faked locally. `python -m caddymon` works the same as the entry script.

## Platform notes

- Built for Linux servers, and should run on any Unix-like system.
- **On Windows** the screen needs a terminal that understands ANSI escape codes, such as Windows Terminal. Keyboard input and resize detection don't work there, because they use Unix-only terminal APIs. Pick a view with `--layout` instead, and restart after resizing the window. Owner lookups work normally. Output is always UTF-8, so piping and redirecting work too.
