"""Passive listener on the MOXA NPort TCP port.

Sends nothing. Dumps every byte that arrives from the serial side, with
timestamps and hex, so we can tell the difference between:

  * total silence  -> nothing is reaching the MOXA's RX pin
                      (cable wiring, balance not transmitting, dead port)
  * garbage bytes  -> the wire is fine but the baud/framing is wrong
  * clean ASCII    -> serial link is healthy; only the command protocol
                      or the print trigger needs work

Run it, then press PRINT / UNITS on the balance a few times.
"""

import argparse
import socket
import sys
import time

HOST = "192.168.127.254"
PORT = 4001


def printable(chunk: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)


def dump(chunk: bytes, offset: int) -> None:
    for i in range(0, len(chunk), 16):
        row = chunk[i : i + 16]
        hexpart = " ".join(f"{b:02X}" for b in row).ljust(47)
        print(f"    {offset + i:06X}  {hexpart}  |{printable(row)}|")


def classify(data: bytes) -> str:
    """Guess whether the bytes look like text or like a baud mismatch."""
    if not data:
        return "NO DATA"
    text = sum(1 for b in data if 32 <= b < 127 or b in (0x0A, 0x0D, 0x09))
    ratio = text / len(data)
    if ratio > 0.9:
        return f"looks like clean ASCII ({ratio:.0%} printable)"
    if ratio < 0.5:
        return f"looks like GARBAGE ({ratio:.0%} printable) -> suspect baud/framing mismatch"
    return f"mixed ({ratio:.0%} printable) -> possibly marginal baud or noise"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--seconds", type=float, default=60.0)
    args = ap.parse_args()

    print(f"Connecting to {args.host}:{args.port} ...")
    s = socket.create_connection((args.host, args.port), timeout=5)
    s.settimeout(0.5)
    print("Connected. Listening passively (sending nothing).")
    print(">>> Now press PRINT on the balance, and put something on the pan. <<<")
    print(f"Listening for {args.seconds:.0f}s. Ctrl-C to stop early.\n")

    deadline = time.monotonic() + args.seconds
    total = bytearray()
    start = time.monotonic()

    try:
        while time.monotonic() < deadline:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                print("!! MOXA closed the TCP connection.")
                break
            stamp = time.monotonic() - start
            print(f"[{stamp:7.2f}s] {len(chunk)} byte(s):")
            dump(chunk, len(total))
            total.extend(chunk)
    except KeyboardInterrupt:
        print("\nStopped by user.")
    finally:
        s.close()

    print("\n" + "=" * 62)
    print(f"TOTAL RECEIVED: {len(total)} byte(s)")
    print(f"VERDICT: {classify(bytes(total))}")
    print("=" * 62)

    if not total:
        print(
            "\nZero bytes. The MOXA never saw a single start bit.\n"
            "That is a physical/wiring problem, not a protocol problem:\n"
            "  - balance TXD is not reaching MOXA RXD (straight-through cable\n"
            "    between two DTE devices does exactly this), or\n"
            "  - the balance's serial output is disabled in its menu, or\n"
            "  - no common ground / wrong connector."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
