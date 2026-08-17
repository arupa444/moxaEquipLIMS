"""Live weight readings from a Radwag balance via a MOXA NPort 5150.

    Radwag  --RS-232-->  NPort 5150  --TCP 4001-->  this script

Two modes:

    poll        ask the balance for a reading on an interval (default)
    continuous  tell the balance to stream (Radwag C1), then just listen

Examples:
    python radwag_read.py
    python radwag_read.py --mode continuous
    python radwag_read.py --command S --interval 1.0   # stable readings only

Radwag reply frames look like:

    S A      0.0000 g\r\n         stable
    S I      1.2345 g\r\n         still settling
    SI ?     ------ g\r\n         no stable value yet

The parser is deliberately tolerant of column layout, because it varies
between Radwag families (PS/AS/WLC/PUE).
"""

import argparse
import re
import socket
import sys
import time
from dataclasses import dataclass

HOST = "192.168.127.254"
PORT = 4001

# Stability markers used across Radwag families.
STABILITY = {
    "A": "stable",
    "I": "unstable",
    "^": "over range",
    "v": "under range",
    "E": "error",
    "?": "no stable value",
}

FRAME = re.compile(
    r"^\s*(?P<cmd>S[IU]{0,2}|[A-Z]{1,3})?\s*"
    r"(?P<flag>[AI^v?E])?\s*"
    r"(?P<value>[-+]?\d+(?:[.,]\d+)?)\s*"
    r"(?P<unit>[a-zA-Z%/]{1,4})?\s*$"
)

# This balance (AS R2 PLUS) answers `S` and `SU` with TWO frames: an
# acknowledgement carrying the stability flag, then the measurement itself:
#     S A
#     S       0.00000 g
# So the flag has to be carried forward onto the next measurement frame.
# `SUI` replies in a single frame with no flag at all.
ACK = re.compile(r"^\s*(?P<cmd>[A-Z]{1,5})\s+(?P<flag>[AI^v?E])\s*$")

# One "<number> <unit>" reading, used only to rescue the unterminated
# continuous-transmission stream described in Balance.lines().
TOKEN = re.compile(rb"[-+]?\d+(?:[.,]\d+)?\s*[a-zA-Z%]{1,3}")


@dataclass
class Reading:
    value: float
    unit: str
    stability: str
    raw: str

    def __str__(self) -> str:
        return f"{self.value:>12.4f} {self.unit:<3} [{self.stability}]"


def parse_frame(line: str) -> tuple[str, object]:
    """Classify one frame: ('reading', Reading) | ('ack', flag) |
    ('error', text) | ('other', raw)."""
    line = line.strip("\r\n\x00 ")
    if not line:
        return ("other", line)
    if line.upper() in ("ES", "ERR"):
        return ("error", line)

    ack = ACK.match(line)
    if ack:
        return ("ack", ack.group("flag"))

    match = FRAME.match(line)
    if match:
        try:
            value = float(match.group("value").replace(",", "."))
        except (TypeError, ValueError):
            return ("other", line)
        flag = match.group("flag") or ""
        return (
            "reading",
            Reading(
                value=value,
                unit=match.group("unit") or "",
                stability=STABILITY.get(flag, "") if flag else "",
                raw=line,
            ),
        )
    return ("other", line)


class Balance:
    def __init__(self, host: str, port: int, timeout: float = 5.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.sock: socket.socket | None = None
        self.buf = bytearray()

    def connect(self) -> None:
        self.close()
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(0.3)
        self.buf.clear()
        print(f"connected to {self.host}:{self.port}")

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def send(self, command: str) -> None:
        assert self.sock is not None
        self.sock.sendall(command.encode("ascii") + b"\r\n")

    def lines(self):
        """Yield complete frames as they arrive.

        Normally frames are CR/LF terminated. But this balance's *continuous
        transmission* uses a printout template with no terminator at all, so it
        emits `0.00000 g0.00000 g0.00000 g...` as one unbroken run with zero
        control bytes. Rather than choke on that, fall back to pulling out whole
        `<number> <unit>` tokens when no terminator is in sight.
        """
        assert self.sock is not None
        try:
            chunk = self.sock.recv(4096)
        except socket.timeout:
            return
        if not chunk:
            raise ConnectionResetError("NPort closed the connection")
        self.buf.extend(chunk)

        if b"\r" not in self.buf and b"\n" not in self.buf and len(self.buf) > 48:
            # Unterminated stream. Yield every complete token but the last,
            # which may still be mid-transmission.
            matches = list(TOKEN.finditer(bytes(self.buf)))
            if len(matches) > 1:
                for m in matches[:-1]:
                    yield m.group(0).decode("ascii", errors="replace")
                del self.buf[: matches[-1].start()]
            elif len(self.buf) > 8192:
                del self.buf[:-64]          # never grow without bound
            return

        while True:
            # Split on the FIRST terminator present. Using max() here was a bug:
            # when frames are separated by a lone LF but a CR appears later in
            # the buffer, max() jumps past every frame in between and glues them
            # into one line. Take the minimum of the positions actually found.
            found = [i for i in (self.buf.find(b"\r"), self.buf.find(b"\n")) if i >= 0]
            if not found:
                break
            idx = min(found)
            # Consume up to and including the whole CR/LF run.
            end = idx
            while end < len(self.buf) and self.buf[end] in (13, 10):
                end += 1
            raw, self.buf[:] = self.buf[:idx], self.buf[end:]
            text = raw.decode("ascii", errors="replace")
            if text.strip():
                yield text


def run(args) -> int:
    bal = Balance(args.host, args.port)
    bal.connect()
    if args.mode == "continuous":
        print("enabling continuous transmission (C1)")
        bal.send("C1")
    elif args.mode == "listen":
        print("listen-only: sending nothing, waiting for the balance to push data")
    next_poll = 0.0
    last = None
    pending_flag = None

    try:
        while True:
            now = time.monotonic()
            if args.mode == "poll" and now >= next_poll:
                bal.send(args.command)
                next_poll = now + args.interval

            try:
                for line in bal.lines():
                    kind, payload = parse_frame(line)

                    if kind == "ack":
                        pending_flag = payload          # applies to the next reading
                        continue
                    if kind == "error":
                        print(f"    balance rejected the command ({payload}) -- "
                              f"try --command SUI")
                        continue
                    if kind != "reading":
                        if payload:
                            print(f"    info: {payload}")
                        continue

                    reading = payload
                    if not reading.stability and pending_flag:
                        reading.stability = STABILITY.get(pending_flag, "unknown")
                    pending_flag = None
                    if not reading.stability:
                        reading.stability = "unknown"

                    if args.changes_only and last is not None and reading.value == last:
                        continue
                    last = reading.value
                    print(f"{time.strftime('%H:%M:%S')}  {reading}")
            except (ConnectionResetError, OSError) as exc:
                print(f"link lost ({exc}); reconnecting in 2s")
                time.sleep(2)
                bal.connect()
                if args.mode == "continuous":
                    bal.send("C1")
            time.sleep(0.05)
    except KeyboardInterrupt:
        print("\nstopping")
        if args.mode == "continuous":
            try:
                bal.send("C0")
            except OSError:
                pass
    finally:
        bal.close()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument(
        "--mode",
        choices=["poll", "continuous", "listen"],
        default="poll",
        help="poll: ask on an interval. continuous: send C1 and stream. "
             "listen: send NOTHING, just parse whatever the balance pushes "
             "(use when continuous transmission is enabled in the balance menu).",
    )
    ap.add_argument("--command", default="SUI",
                    help="poll command. SUI works on this AS R2 PLUS; plain SI is "
                         "rejected with ES on its firmware. S/SU wait for stability.")
    ap.add_argument("--interval", type=float, default=0.5, help="seconds between polls")
    ap.add_argument("--changes-only", action="store_true", help="print only when the value changes")
    return run(ap.parse_args())


if __name__ == "__main__":
    sys.exit(main())
