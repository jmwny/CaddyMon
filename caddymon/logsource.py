"""Reading the access log: following a growing file natively (rotation and
truncation safe) or stdin, and parsing Caddy's JSON lines into Records."""

from __future__ import annotations

import json
import os
import select
import sys
import time
from dataclasses import dataclass
from datetime import datetime

from .text import clean


@dataclass
class Record:
    time: str
    status: int
    method: str
    ip: str
    uri: str


def _field(value, default: str) -> str:
    """A log field as clean text; anything that isn't a non-empty string
    (null, a number, a list, ...) becomes ``default``."""
    return clean(value) if isinstance(value, str) and value else default


def parse_line(line: str) -> Record | None:
    """Parse one JSON log line into a Record, or None if it isn't a usable
    access record (mirrors the original jq ``select`` on a numeric .status).
    Never raises: odd-but-valid JSON (wrong field types, NaN, huge numbers)
    is rejected or defaulted here rather than crashing the stats/display."""
    line = line.strip()
    if not line:
        return None
    try:
        rec = json.loads(line)
    except (ValueError, TypeError, RecursionError):
        return None
    if not isinstance(rec, dict):
        return None

    status = rec.get("status")
    if not isinstance(status, (int, float)) or isinstance(status, bool):
        return None
    try:
        status = int(status)  # json accepts NaN/Infinity, which int() rejects
    except (ValueError, OverflowError):
        return None

    req = rec.get("request") or {}
    if not isinstance(req, dict):
        req = {}

    return Record(
        time=format_ts(rec.get("ts")),
        status=status,
        method=_field(req.get("method"), "-"),
        ip=_field(req.get("remote_ip"), "unknown"),
        uri=_field(req.get("uri"), "-"),
    )


def format_ts(ts) -> str:
    """Caddy's ts is epoch seconds (float). Fall back to now / passthrough."""
    dt = None
    if isinstance(ts, (int, float)) and not isinstance(ts, bool):
        try:
            dt = datetime.fromtimestamp(ts)
        except (OverflowError, OSError, ValueError):  # NaN / out of range
            pass
    elif isinstance(ts, str) and ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return clean(ts[:19])
    return (dt or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")


def follow(path: str, from_start: bool, poll: float, wait_fd=None):
    """Yield complete lines from a growing file, surviving rotation/truncation.

    This replaces ``tail -Fn0``: it follows by *name*, retries if the file is
    missing, reopens when the file is replaced (rotation), and rewinds when the
    file is truncated in place. Partial trailing lines are buffered until their
    newline arrives.

    ``wait_fd`` (typically stdin) makes the idle wait interruptible: instead of
    a fixed ``time.sleep(poll)`` we ``select`` on it, so a keypress wakes the
    follower immediately for responsive filtering. Either way we ``yield None``
    once per idle period — including while the file is missing — so the caller
    can service keys/resizes and redraw.

    Reads are bounded (``READ_CHUNK``), so a multi-GB ``--from-start`` backlog
    streams instead of being loaded whole. On rotation the old file is drained
    before it's closed, so lines written just before the switch aren't lost.
    """
    READ_CHUNK = 1 << 20
    fh = None
    file_id = None
    buf = b""
    initial = True

    def idle():
        # Idle wait. With a wait_fd, return as soon as a key is pressed (or
        # poll elapses); otherwise just sleep. PEP 475 means a SIGWINCH that
        # lands here is retried transparently rather than crashing the wait.
        if wait_fd is not None:
            try:
                select.select([wait_fd], [], [], poll)
            except (InterruptedError, OSError):
                pass
        else:
            time.sleep(poll)

    try:
        while True:
            if fh is None:
                try:
                    fh = open(path, "rb")
                except FileNotFoundError:
                    idle()
                    yield None  # keep the caller's keys/redraws alive
                    continue
                st = os.fstat(fh.fileno())
                file_id = (st.st_dev, st.st_ino)
                # Skip existing content only on the very first open; a freshly
                # rotated file should be read from its start.
                if initial and not from_start:
                    fh.seek(0, os.SEEK_END)
                initial = False

            chunk = fh.read(READ_CHUNK)
            if chunk:
                buf += chunk
                *lines, buf = buf.split(b"\n")
                for raw in lines:
                    yield raw.decode("utf-8", "replace")
                continue

            # At EOF: decide whether to wait, rewind, or reopen.
            try:
                st_path = os.stat(path)
                rotated = (st_path.st_dev, st_path.st_ino) != file_id
            except FileNotFoundError:
                rotated = True

            if fh.tell() > os.fstat(fh.fileno()).st_size:
                fh.seek(0)  # truncated in place
                buf = b""  # a partial line from before the truncation is stale
                continue
            if rotated:
                # Drain anything written to the old file after our last read
                # (it may still be arriving until the writer switches over).
                while True:
                    chunk = fh.read(READ_CHUNK)
                    if not chunk:
                        break
                    buf += chunk
                    *lines, buf = buf.split(b"\n")
                    for raw in lines:
                        yield raw.decode("utf-8", "replace")
                if buf:  # the old file's last line had no newline: still a line
                    yield buf.decode("utf-8", "replace")
                fh.close()
                fh = None
                buf = b""
                continue
            idle()
            # Idle "tick": hand control back to the caller once per idle period
            # so it can service keys / a pending resize and redraw.
            # The main loop treats None as "nothing to display".
            yield None
    finally:
        if fh is not None:
            fh.close()


def iter_stdin():
    for line in sys.stdin:
        yield line.rstrip("\n")
