"""Colors and plain (non-interactive) output: request rows, the one-shot
header, and the exit summary."""

from __future__ import annotations

from collections import Counter
from datetime import datetime

from .logsource import Record
from .rdap import OwnerResolver
from .stats import CLASS_STYLE, CLASSES, Stats, classify, marker


URI_MAX = 40


class Palette:
    """ANSI styles. All attributes become empty strings when color is off."""

    NAMES = {
        "RED": "\033[0;31m",
        "BRIGHT_RED": "\033[1;31m",
        "YELLOW": "\033[1;33m",
        "CYAN": "\033[0;36m",
        "GREEN": "\033[0;32m",
        "WHITE": "\033[1;37m",
        "BOLD": "\033[1m",
        "DIM": "\033[2m",
        "RESET": "\033[0m",
    }

    def __init__(self, enabled: bool):
        for name, code in self.NAMES.items():
            setattr(self, name, code if enabled else "")

    def style_for(self, status: int) -> str:
        """Color for an HTTP status code, from its CLASSES entry."""
        return getattr(self, CLASS_STYLE[classify(status)])


def render_row(p: Palette, rec: Record) -> str:
    """Return the formatted request row (no trailing newline)."""
    color = p.style_for(rec.status)
    uri = rec.uri if len(rec.uri) <= URI_MAX else rec.uri[: URI_MAX - 2] + ".."
    return (
        f"  {p.DIM}{rec.time:<19}{p.RESET} "
        f"{color}{marker(rec.status)} {rec.status:<5}{p.RESET} "
        f"{p.WHITE}{rec.method:<6}{p.RESET} "
        f"{p.CYAN}{rec.ip:<15}{p.RESET} "
        f"{p.DIM}{uri}{p.RESET}"
    )


def class_breakdown(p: Palette, classes: Counter) -> str:
    """Colored ``2xx:3 4xx:12`` for the non-zero classes."""
    return " ".join(
        f"{getattr(p, attr)}{key}:{classes[key]}{p.RESET}"
        for key, _label, attr in CLASSES
        if classes.get(key, 0)
    )


class Display:
    """Plain (non-interactive) output: a one-shot header and the exit summary.
    The interactive layout lives in ``Screen``."""

    def __init__(self, p: Palette, log_path: str):
        self.p = p
        self.log_path = log_path

    def header(self) -> None:
        p = self.p
        if p.RESET:  # only clear when colors/TTY are active
            print("\033[2J\033[H", end="")
        print(f"{p.BOLD}{p.WHITE}")
        print("  ╔══════════════════════════════════════════════════════════╗")
        print("  ║              📡  CADDY TRAFFIC MONITOR  📡               ║")
        print("  ╚══════════════════════════════════════════════════════════╝")
        print(p.RESET)
        print(f"  {p.DIM}Log: {self.log_path}{p.RESET}")
        started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"  {p.DIM}Started: {started}   |   Press Ctrl+C to exit{p.RESET}")
        print()
        print(
            f"  {p.DIM}Legend:{p.RESET} {p.GREEN}■ 2xx OK{p.RESET}  "
            f"{p.CYAN}■ 3xx Redirect{p.RESET}  {p.YELLOW}■ 4xx Client Err{p.RESET}  "
            f"{p.BRIGHT_RED}■ 5xx Server Err{p.RESET}"
        )
        print(f"  {p.BOLD}{p.WHITE}{'─' * 68}{p.RESET}")
        print(
            f"  {p.BOLD}{'TIME':<19} {'STATUS':<7} {'METHOD':<6} "
            f"{'IP ADDRESS':<15} URI{p.RESET}"
        )
        print(f"  {p.BOLD}{p.WHITE}{'─' * 68}{p.RESET}")

    def summary(self, stats: Stats, resolver: OwnerResolver) -> None:
        p = self.p
        top_ips = sorted(stats.ips.items(), key=lambda kv: kv[1].hits,
                         reverse=True)[:5]
        top_denied = stats.denied_ips.most_common(5)
        # Give in-flight owner lookups a moment to land; a second Ctrl+C skips.
        try:
            resolver.wait([ip for ip, _ in top_ips + top_denied], timeout=3)
        except KeyboardInterrupt:
            pass

        def print_owner(ip: str, col: int) -> None:
            """Owner on its own line, hung off the IP (which starts at
            visible column ``col``) with a connector, as in the IP table."""
            text = resolver.lookup(ip)
            if text:
                print(f"{' ' * col}{p.DIM}└─ {text}{p.RESET}")

        print()
        print(
            f"  {p.BOLD}{p.WHITE}──────────────── SUMMARY "
            f"({stats.total} requests) ────────────────{p.RESET}"
        )
        for key, label, attr in CLASSES:
            count = stats.classes.get(key, 0)
            if key == "other" and count == 0:
                continue
            color = getattr(p, attr)
            print(f"  {color}{label:<15} {count}{p.RESET}")

        if top_ips:
            print(f"  {p.DIM}── Top IPs ──{p.RESET}")
            ip_w = max(15, max(len(ip) for ip, _ in top_ips))
            for ip, st in top_ips:
                print(
                    f"  {p.YELLOW}{st.hits:<5}{p.RESET} → {p.CYAN}{ip:<{ip_w}}{p.RESET} "
                    f"{class_breakdown(p, st.classes)}"
                )
                print_owner(ip, 10)  # "  " + 5-wide count + " → "

        if top_denied:
            print(f"  {p.DIM}── Top denied IPs (403) ──{p.RESET}")
            for ip, count in top_denied:
                print(f"  {p.YELLOW}{count:<5}{p.RESET} hits → {p.CYAN}{ip}{p.RESET}")
                print_owner(ip, 15)  # "  " + 5-wide count + " hits → "

        if stats.paths:
            print(f"  {p.DIM}── Top paths ──{p.RESET}")
            for path, count in stats.paths.most_common(5):
                shown = path if len(path) <= 50 else path[:48] + ".."
                print(f"  {p.YELLOW}{count:<5}{p.RESET} → {p.DIM}{shown}{p.RESET}")

        print(f"  {p.BOLD}{p.WHITE}{'─' * 68}{p.RESET}")
        print()
