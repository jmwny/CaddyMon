# CaddyMon: Caddy Traffic Monitor

**Tagline:** See who's hitting your Caddy server, live, in your terminal.

**Short description (one or two sentences, for a card or listing):**
CaddyMon is a live, htop-style terminal view of a Caddy web server's access log. It groups requests by client IP, shows who owns each address, and flags likely scanners. It's a single Python tool with no dependencies.

## About

Watching a raw access log is mostly noise: one scanner probing for `/.env` and `/wp-login.php` can bury everything else under hundreds of lines. CaddyMon turns Caddy's JSON access log into a live dashboard. Each client IP gets one line, with a running count of its requests by status class, and the organization that owns the address underneath it. The newest requests scroll below. Select an IP and press Enter to see only that IP's requests.

Owners come from the regional internet registries over RDAP, plus reverse DNS. Lookups run in the background, stay within each registry's published rate limits, and are cached on disk. The cache stores network blocks only, never individual visitor IPs. When you quit, CaddyMon prints a summary of your top IPs, denied (403) IPs and most requested paths.

It's plain Python 3.7+ using only the standard library. It follows the log natively, keeps going when Caddy rotates the file, and is built to be left running for weeks.

## Features

- **Grouped by IP:** one line per client with hits, 2xx/3xx/4xx/5xx counts and the time last seen, instead of a wall of individual requests.
- **Who owns each IP:** organization and country from the registries (ARIN, RIPE, APNIC, LACNIC, AFRINIC) via RDAP, plus the reverse DNS hostname.
- **Scanner detection:** a ⚠ marks IPs with many client errors and no successful requests.
- **Keyboard driven:** move through IPs with the arrow keys, follow one IP's requests, filter by status class, sort by recent or by hits, and switch between split, IPs-only and requests-only layouts.
- **Live header:** total requests, requests per second with a 60-second sparkline, and counts per status class.
- **Exit summary:** top IPs with their owners, top denied IPs and top paths.
- **Polite lookups:** requests go straight to the right registry using IANA's bootstrap files. They respect each registry's rate limits and `Retry-After` headers, and are cached for 30 days.
- **Safe for long runs:** memory use is bounded, the tool survives log rotation, and control characters from logs or registry data are stripped before anything reaches your terminal.
- **Script friendly:** when piped or redirected, it prints one color-coded line per request instead of the interactive screen.
- **No dependencies:** standard-library Python 3.7+, with no `jq`, no `pip install` and no build step.

## Quick start

Copy `caddy_traffic_monitor.py` and the `caddymon/` folder to the server, then:

```bash
sudo python3 caddy_traffic_monitor.py /var/log/caddy/access.log
```

Caddy needs to write JSON access logs (`log { output file /var/log/caddy/access.log; format json }`). Press `q` to quit and print the summary. Use `--no-lookup` to keep everything offline.

**Source:** https://github.com/jmwny/CaddyMon

## Screenshots

The screenshots use sample data: documentation and private IP ranges with fictional owners.

| File | Caption | Alt text |
|---|---|---|
| `screenshots/caddymon-split.png` | The default split view: client IPs with their owners above, and the requests from the selected IP below. | CaddyMon terminal view listing client IPs with request counts by status class and owner names, above a list of recent requests from one IP. |
| `screenshots/caddymon-ips.png` | IPs only, sorted by hits. Two scanners from the same hosting network share one registry lookup. | CaddyMon IP list sorted by hit count, with warning markers on IPs that only receive client errors. |
| `screenshots/caddymon-stream-4xx.png` | The request stream filtered to client errors, showing what scanners are probing for. | CaddyMon request list filtered to 4xx responses, showing probes for .env, wp-login.php and .git/config. |
| `screenshots/caddymon-summary.png` | The summary printed on exit: totals, top IPs, top denied IPs and top paths. | CaddyMon exit summary with request totals per status class and top IP, denied-IP and path lists. |
| `screenshots/caddymon-piped.png` | Piped output: one color-coded line per request, ready for grep. | CaddyMon plain output piped through grep, one line per request with time, status, method, IP and path. |
