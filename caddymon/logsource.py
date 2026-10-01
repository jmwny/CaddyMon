"""Reading the access logs: following growing files natively (rotation and
truncation safe) or stdin, and parsing Caddy's JSON lines into Records."""

from __future__ import annotations

import json
import os
import re
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
    site: str = ""  # label of the log it came from (site_labels); "" for stdin


# A copy Caddy has rotated away: "<name>-2026-10-01T12-00-00.000.log[.gz]".
ROTATED_NAME = re.compile(r"-\d{4}-\d\d-\d\dT\d\d-\d\d-\d\d\.\d{3}(\.[^.]+)?(\.gz)?$")


def is_rotated(path: str) -> bool:
    """Whether ``path`` looks like a log Caddy has already rotated away (it
    never grows again, so following it live is pointless)."""
    return bool(ROTATED_NAME.search(os.path.basename(path)))


def site_labels(paths: list) -> dict:
    """A unique short label per log path: the file name without ``.log``
    (``www.example.com.log`` → ``www.example.com``). Names that clash, such
    as two ``access.log`` files, get as many of their folders in front as it
    takes to tell them apart. Labels are ``clean()``ed: file names are outside
    text too, and labels end up on the terminal."""
    split = {path: [p for p in os.path.abspath(path).replace("\\", "/").split("/") if p]
             for path in paths}

    def name(path, depth, strip=True):
        label = clean("/".join(split[path][-depth:]))
        return label[:-4] if strip and label.endswith(".log") else label

    depth = dict.fromkeys(paths, 1)
    while True:
        labels = {path: name(path, depth[path]) for path in paths}
        taken = list(labels.values())
        clashing = [path for path in paths if taken.count(labels[path]) > 1]
        deeper = [path for path in clashing if depth[path] < len(split[path])]
        if not deeper:
            break
        for path in deeper:
            depth[path] += 1
    # Still clashing at full depth (e.g. "/x/a" and "/x/a.log"): keep ".log".
    for path in clashing:
        labels[path] = name(path, depth[path], strip=False)
    return labels


def _field(value, default: str) -> str:
    """A log field as clean text; anything that isn't a non-empty string
    (null, a number, a list, ...) becomes ``default``."""
    return clean(value) if isinstance(value, str) and value else default


def parse_line(line: str, site: str = "") -> Record | None:
    """Parse one JSON log line into a Record (tagged with ``site``, the label
    of the log it came from), or None if it isn't a usable access record
    (mirrors the original jq ``select`` on a numeric .status).
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
        site=site,
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


class Follower:
    """One growing log file, followed by *name* (replaces ``tail -F``): it
    waits while the file is missing, reopens it when it's replaced (rotation)
    and rewinds when it's truncated in place. Partial trailing lines are
    buffered until their newline arrives.

    ``step()`` never blocks, so ``follow_many()`` can take turns between
    files and do the idle wait once for all of them. Reads are bounded
    (``READ_CHUNK``), so a multi-GB ``--from-start`` backlog streams instead of
    being loaded whole, and can't hold up the other files. On rotation the old
    file is drained before it's closed, so lines written just before the
    switch aren't lost.

    A partial line longer than ``MAX_LINE`` (real Caddy lines are a few KB;
    this is a file with no newlines, such as the wrong file) is dropped, along
    with the rest of it up to its newline, so memory stays bounded.
    """

    READ_CHUNK = 1 << 20
    MAX_LINE = 1 << 20

    def __init__(self, path: str, from_start: bool):
        self.path = path
        self._from_start = from_start
        self._fh = None
        self._file_id = None
        self._buf = b""
        self._skipping = False  # dropping the rest of an over-long line
        self._initial = True
        self._draining = False  # rotated away: reading out the old file

    def _split(self, chunk: bytes) -> list:
        self._buf += chunk
        *lines, self._buf = self._buf.split(b"\n")
        if self._skipping and lines:
            del lines[0]  # the end of the over-long line
            self._skipping = False
        if len(self._buf) > self.MAX_LINE:
            self._buf = b""
            self._skipping = True
        return [raw.decode("utf-8", "replace") for raw in lines]

    def _reset_buf(self) -> None:
        self._buf = b""
        self._skipping = False

    def step(self):
        """Read at most one chunk. Returns the complete lines it finished
        (possibly none, when it only reopened or rewound), or ``None`` when
        there's nothing new: the file is idle or missing."""
        if self._fh is None:
            try:
                self._fh = open(self.path, "rb")
            except FileNotFoundError:
                return None
            st = os.fstat(self._fh.fileno())
            self._file_id = (st.st_dev, st.st_ino)
            # Skip existing content only on the very first open; a freshly
            # rotated file should be read from its start.
            if self._initial and not self._from_start:
                self._fh.seek(0, os.SEEK_END)
            self._initial = False

        chunk = self._fh.read(self.READ_CHUNK)
        if chunk:
            return self._split(chunk)

        # At EOF: decide whether to wait, rewind, or reopen.
        if not self._draining:
            try:
                st_path = os.stat(self.path)
                rotated = (st_path.st_dev, st_path.st_ino) != self._file_id
            except FileNotFoundError:
                rotated = True

            if self._fh.tell() > os.fstat(self._fh.fileno()).st_size:
                self._fh.seek(0)  # truncated in place
                self._reset_buf()  # a partial line from before the truncation is stale
                return []
            if not rotated:
                return None
            # Rotated: drain anything written to the old file after our last
            # read (it may still be arriving until the writer switches over).
            # Sticky, so later steps keep draining until the old file is done.
            self._draining = True
            chunk = self._fh.read(self.READ_CHUNK)
            if chunk:
                return self._split(chunk)
        # The old file is done. Its last line had no newline: still a line
        # (unless it's the end of an over-long one).
        lines = ([self._buf.decode("utf-8", "replace")]
                 if self._buf and not self._skipping else [])
        self.close()
        self._reset_buf()
        self._draining = False
        return lines

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None


def _idle(poll: float, wait_fd) -> None:
    """Idle wait. With a ``wait_fd``, return as soon as a key is pressed (or
    ``poll`` elapses); otherwise just sleep. PEP 475 means a SIGWINCH that
    lands here is retried transparently rather than crashing the wait."""
    if wait_fd is not None:
        try:
            select.select([wait_fd], [], [], poll)
        except (InterruptedError, OSError):
            pass
    else:
        time.sleep(poll)


def follow_many(paths: list, from_start: bool, poll: float, wait_fd=None):
    """Yield ``(path, line)`` for complete lines from several growing files
    (see ``Follower``), taking turns one chunk per file so a big backlog in
    one doesn't starve the others.

    ``wait_fd`` (typically stdin) makes the idle wait interruptible: instead of
    a fixed ``time.sleep(poll)`` we ``select`` on it, so a keypress wakes the
    loop immediately for responsive filtering. Either way we ``yield None``
    once per idle period (when no file had anything new, including while they
    are missing) so the caller can service keys/resizes and redraw.
    """
    followers = [Follower(path, from_start) for path in paths]
    try:
        while True:
            busy = False
            for follower in followers:
                lines = follower.step()
                if lines is None:
                    continue
                busy = True
                for line in lines:
                    yield follower.path, line
            if not busy:
                _idle(poll, wait_fd)
                # Idle "tick": the main loop treats None as "nothing to
                # display" and uses it to service keys / a pending resize.
                yield None
    finally:
        for follower in followers:
            follower.close()


def iter_stdin():
    for line in sys.stdin:
        yield line.rstrip("\n")
