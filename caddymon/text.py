"""Terminal-safe text helpers: neutralising control characters in text from
outside the program, and measuring/clipping ANSI-styled strings."""

from __future__ import annotations

import re


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def clean(text: str) -> str:
    """Neutralise control characters (C0, DEL, C1) in text from outside the
    program — log fields, RDAP answers, reverse DNS, the cache file — so it
    can't send escape sequences to the terminal (retitle it, write the
    clipboard via OSC 52, move the cursor) or throw off width math."""
    return _CONTROL_RE.sub("?", text)


_ANSI_RE = re.compile(r"(\x1b\[[0-9;?]*[A-Za-z])")


def vlen(s: str) -> int:
    """Visible length of ``s`` (ANSI SGR/CSI sequences don't count)."""
    return len(_ANSI_RE.sub("", s))


def clip(s: str, width: int, reset: str = "") -> str:
    """Truncate ``s`` to ``width`` visible columns, ANSI-aware, marking the
    cut with an ellipsis."""
    if width <= 0:
        return ""
    if vlen(s) <= width:
        return s
    out, used = [], 0
    for part in _ANSI_RE.split(s):
        if not part:
            continue
        if part.startswith("\x1b"):
            out.append(part)
            continue
        room = width - 1 - used
        if room <= 0:
            break
        out.append(part[:room])
        used += min(len(part), room)
    return "".join(out) + reset + "…"
