"""Shared test helpers: local fake HTTP servers and a virtual terminal.

Nothing here touches the network: RDAP registries, IANA's bootstrap files and
rdap.org are all replaced by servers on 127.0.0.1 / localhost (two names for
the same machine, so the rate limiter treats them as different hosts)."""

from __future__ import annotations

import http.server
import json
import re
import socket
import threading
import time


class FakeServer:
    """A local HTTP server whose GET handler is ``respond(handler)``. Every
    request is logged as ``(path, monotonic_time)`` in ``requests``."""

    def __init__(self, respond, host="127.0.0.1"):
        self.requests = []
        self.host = host
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                server.requests.append((self.path, time.monotonic()))
                respond(self)

        # Bind to the address the client will try first for this host name.
        # For "localhost" that's often ::1; binding only 127.0.0.1 would make
        # every request wait out a failed IPv6 attempt (~2 s on Windows).
        family, _, _, _, sockaddr = socket.getaddrinfo(
            host, None, type=socket.SOCK_STREAM)[0]

        class Server(http.server.ThreadingHTTPServer):
            address_family = family

        self.httpd = Server((sockaddr[0], 0), Handler)
        self.port = self.httpd.server_port
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def base(self) -> str:
        return f"http://{self.host}:{self.port}/"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def reply(handler, obj=None, code=200, headers=()):
    handler.send_response(code)
    for key, value in headers:
        handler.send_header(key, value)
    handler.end_headers()
    if obj is not None:
        handler.wfile.write(json.dumps(obj).encode())


def rdap_network(n: int, org: str) -> dict:
    """An RDAP ip-network answer for 203.0.<n>.0/24 owned by ``org``."""
    return {
        "country": "ZZ",
        "startAddress": f"203.0.{n}.0",
        "endAddress": f"203.0.{n}.255",
        "entities": [{"roles": ["registrant"],
                      "vcardArray": ["vcard", [["fn", {}, "text", org]]]}],
    }


def read_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def third_octet(path: str) -> int:
    """203.0.<n>.x at the end of an RDAP path -> n."""
    return int(path.rsplit("/", 1)[-1].split(".")[2])


def wait_until(predicate, timeout: float, poll: float = 0.05, tick=None) -> bool:
    """Poll ``predicate`` until true or ``timeout``; ``tick`` runs each poll
    (e.g. to keep IPs "on screen" by calling resolver.lookup)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if tick:
            tick()
        if predicate():
            return True
        time.sleep(poll)
    return predicate()


class Term:
    """Replays Screen's output onto a character grid, enough to check layout:
    cursor positioning, erase-to-EOL, clear, and the alt-screen/autowrap modes.
    Raises if anything is written past the last column (it would wrap)."""

    TOKEN = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\n|[^\x1b\n]")

    def __init__(self, cols: int, rows: int):
        self.cols, self.rows = cols, rows
        self.grid = [[" "] * cols for _ in range(rows)]
        self.r = self.c = 0
        self.alt = False
        self.wrap = True

    def feed(self, data: str) -> None:
        for tok in self.TOKEN.findall(data):
            if tok == "\n":
                self.r = min(self.r + 1, self.rows - 1)
                self.c = 0
            elif tok.startswith("\x1b["):
                cmd, args = tok[-1], tok[2:-1]
                if args == "?1049" and cmd in "hl":
                    self.alt = cmd == "h"
                elif args == "?7" and cmd in "hl":
                    self.wrap = cmd == "h"
                elif cmd == "H":
                    row, col = ([int(x) for x in args.split(";")] if args else [1, 1])
                    self.r, self.c = row - 1, col - 1
                elif cmd == "J":
                    self.grid = [[" "] * self.cols for _ in range(self.rows)]
                elif cmd == "K":
                    for x in range(self.c, self.cols):
                        self.grid[self.r][x] = " "
            elif not tok.startswith("\x1b"):
                if self.c >= self.cols:
                    raise AssertionError(f"write past last column on row {self.r + 1}")
                self.grid[self.r][self.c] = tok
                self.c += 1

    def lines(self) -> list:
        return ["".join(row).rstrip() for row in self.grid]

    def text(self) -> str:
        return "\n".join(self.lines())
