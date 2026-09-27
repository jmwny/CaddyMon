"""Command-line entry point: argument parsing and the main follow loop."""

from __future__ import annotations

import argparse
import os
import select
import signal
import sys

from .logsource import Record, follow, iter_stdin, parse_line
from .output import Display, Palette, render_row
from .rdap import OwnerResolver, RangeCache
from .screen import Screen
from .stats import Stats


# Raw single-key input is POSIX-only (termios/tty). When unavailable (e.g. on
# Windows) the live filter keys are simply disabled; everything else still runs.
try:
    import termios
    import tty

    HAVE_TERMIOS = True
except ImportError:  # pragma: no cover - platform dependent
    HAVE_TERMIOS = False


DEFAULT_LOG = "/var/log/caddy/denied_access.log"
# RDAP results are cached next to the caddy_traffic_monitor.py entry script,
# i.e. in the folder that contains this package (see RangeCache).
DEFAULT_CACHE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rdap_cache.json")


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        number = float("nan")
    if not number > 0 or number == float("inf"):
        raise argparse.ArgumentTypeError(f"must be a positive number, not {value!r}")
    return number


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Live color-coded view of a Caddy JSON access log.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "log_file",
        nargs="?",
        default=os.environ.get("CADDY_LOG_FILE", DEFAULT_LOG),
        help="Path to the Caddy JSON access log (use '-' for stdin).",
    )
    # Obsolete (the live header replaced periodic summaries): still accepted so
    # old command lines work, but hidden and never parsed. The old
    # SUMMARY_EVERY environment variable is ignored too.
    parser.add_argument("-n", "--summary-every", help=argparse.SUPPRESS)
    parser.add_argument(
        "--from-start",
        action="store_true",
        help="Read the whole file from the beginning instead of tailing new lines.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors (also auto-disabled when stdout isn't a TTY).",
    )
    parser.add_argument(
        "--layout",
        choices=Screen.LAYOUTS,
        default="split",
        help="Interactive layout: IPs above requests, IPs only, or requests only "
        "(cycle with Tab where keys work).",
    )
    parser.add_argument(
        "-g",
        "--group",
        action="store_true",
        help="Shorthand for --layout ips.",
    )
    parser.add_argument(
        "--suspect",
        type=int,
        default=10,
        metavar="N",
        help="Flag an IP with ⚠ once it has N+ 4xx responses and no 2xx "
        "(0 disables).",
    )
    parser.add_argument(
        "--no-lookup",
        action="store_true",
        help="Don't look up IP owners (no RDAP or reverse-DNS queries); owners "
        "already in the cache are still shown.",
    )
    parser.add_argument(
        "--cache",
        default=DEFAULT_CACHE,
        metavar="PATH",
        help="File that keeps RDAP results between runs.",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Don't read or write the RDAP cache file.",
    )
    parser.add_argument(
        "--poll",
        type=_positive_float,
        default=0.5,
        help="Seconds to wait between checks when the log has no new data.",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    # Force line buffering on stdout. When stdout isn't a TTY (piped to grep/
    # tee/less, redirected to a file, or run under systemd/nohup), CPython
    # block-buffers it (~8 KB), so rows pile up unflushed and the stream looks
    # frozen until the buffer fills. Line buffering flushes on every newline,
    # which is exactly one completed row.
    #
    # Also force UTF-8. A redirected stdout uses the locale encoding (cp1252 on
    # Windows), which can't encode the box-drawing/marker glyphs and would raise
    # UnicodeEncodeError on the first header line. Likewise decode stdin (the
    # "-" replay source) as UTF-8 with replacement, matching follow(): Caddy
    # writes UTF-8, and cp1252 has undecodable bytes that would crash the loop.
    # Done before argument parsing so --help/usage errors are covered too.
    try:
        sys.stdout.reconfigure(
            line_buffering=True, encoding="utf-8", errors="replace"
        )
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    args = parse_args(argv)  # after the reconfigure: --help prints UTF-8 too

    use_stdin = args.log_file == "-"
    color = not args.no_color and sys.stdout.isatty()
    palette = Palette(color)
    display = Display(palette, "stdin" if use_stdin else args.log_file)
    if not use_stdin and not os.path.exists(args.log_file):
        # Fail fast when the log is missing at startup, with or without
        # --from-start: a typo'd path shouldn't hang silently. (A file that
        # vanishes later, mid-rotation, is waited for by follow().)
        print(
            f"{palette.RED}Error: Log file not found at {args.log_file}{palette.RESET}",
            file=sys.stderr,
        )
        return 1

    stats = Stats()
    ranges = RangeCache(None if args.no_cache else args.cache)
    ranges.load()
    resolver = OwnerResolver(enabled=not args.no_lookup, ranges=ranges)
    stats.on_evict = resolver.forget  # pruned IPs: drop their resolver state

    # Print a final summary on Ctrl+C / SIGTERM. Counters live in this function's
    # scope, so the handler sees the real running totals.
    def on_exit(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, on_exit)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, on_exit)

    # The interactive view needs an stdout TTY; the live filter keys also need
    # an stdin TTY and POSIX termios. (When the log itself is stdin, we can't
    # also read keys from it.)
    interactive = not use_stdin and sys.stdout.isatty()
    kbd_enabled = interactive and HAVE_TERMIOS and sys.stdin.isatty()
    screen = (
        Screen(palette, stats, resolver, display.log_path,
               layout="ips" if args.group else args.layout,
               suspect=args.suspect, keys=kbd_enabled)
        if interactive
        else None
    )

    def emit(rec: Record) -> None:
        """Count and display one parsed record."""
        stats.record(rec)
        if screen is not None:
            screen.add(rec)  # drawn on the next frame
        else:
            sys.stdout.write(render_row(palette, rec) + "\n")

    def drain_keys(fd: int) -> None:
        """Apply all keypresses currently buffered (non-blocking)."""
        while select.select([fd], [], [], 0)[0]:
            try:
                data = os.read(fd, 64)
            except OSError:
                return
            if not data:
                return
            # Parsed as a whole so arrow-key escape sequences stay intact.
            screen.handle_input(data.decode("utf-8", "ignore"))  # 'q' raises

    old_term = None
    fd = sys.stdin.fileno() if kbd_enabled else None
    try:
        if kbd_enabled:
            # cbreak: deliver keys unbuffered without echo, but keep ISIG so
            # Ctrl+C still raises SIGINT through on_exit.
            old_term = termios.tcgetattr(fd)
            tty.setcbreak(fd)

        if screen is not None:
            screen.start()
            if hasattr(signal, "SIGWINCH"):
                signal.signal(signal.SIGWINCH, screen.mark_resized)
        else:
            display.header()  # plain one-shot header for non-interactive output

        if use_stdin:
            for line in iter_stdin():
                rec = parse_line(line)
                if rec is not None:
                    emit(rec)
        else:
            for line in follow(args.log_file, args.from_start, args.poll, fd):
                if line is not None:
                    rec = parse_line(line)
                    if rec is not None:
                        emit(rec)
                elif screen is not None:
                    screen.backlog_done()  # idle tick: any backlog is drained
                if kbd_enabled:
                    drain_keys(fd)
                if screen is not None:
                    screen.service()  # apply a resize / draw a due frame
    except KeyboardInterrupt:
        pass
    finally:
        if screen is not None:
            screen.stop()
        if old_term is not None:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_term)
        print()
        try:
            display.summary(stats, resolver)
        finally:  # keep this run's lookups even if the summary is interrupted
            ranges.save()
            if ranges.error:  # plain text: stderr may be redirected on its own
                print(f"Note: couldn't save the RDAP cache to {ranges.path}: "
                      f"{ranges.error}", file=sys.stderr)

    return 0


def run() -> int:
    """Entry point for caddy_traffic_monitor.py and ``python -m caddymon``:
    main(), exiting quietly when piped into something that closes early
    (e.g. ``head``)."""
    try:
        return main()
    except BrokenPipeError:
        return 0
