"""Evidence gatherer: log EVERYTHING that arrives on the NPort, timestamped.

Phase-1 instrumentation for the "capture printouts as .txt" work. It answers one
question: when a user presses PRINT on the balance, does the printout appear on
the Computer port (COM1, where our MOXA is), or does it go only to the physical
printer on another port?

Continuous transmission floods the line with unterminated mass tokens
(`0.00000 g0.00000 g...`). Those are separated out as NOISE so anything
structured stands out immediately.

    python capture_print.py --out capture.log

Then press PRINT on the balance. Anything non-noise is printed live and the raw
bytes are appended to the log with hex, so the exact framing can be studied
afterwards.
"""

import argparse
import re
import socket
import sys
import time
from datetime import datetime

HOST = "192.168.127.254"
PORT = 4001

# The balance's code page (per its Communication settings). Printouts may carry
# Central-European characters, so decode as cp1250 rather than ASCII.
CODEPAGE = "cp1250"

# A chunk is continuous-transmission noise ONLY if the WHOLE chunk is bare
# "<number> <unit>" runs with no line terminator anywhere.
#
# An earlier version used re.sub() to strip this pattern out of every chunk.
# That was destructive: `0.01999 g` inside a real printout line matches it, so
# the filter silently deleted the measurements and left `Current result` followed
# by empty padding. Never subtract from the payload -- classify whole chunks.
NOISE_WHOLE = re.compile(rb"^(?:[-+]?\d+(?:[.,]\d+)?\s*[a-zA-Z%]{1,3})+$")


def is_pure_noise(chunk: bytes) -> bool:
    if b"\r" in chunk or b"\n" in chunk:
        return False
    return bool(NOISE_WHOLE.match(chunk.strip()))


def hexdump(data: bytes, width: int = 16) -> str:
    out = []
    for i in range(0, len(data), width):
        row = data[i : i + width]
        h = " ".join(f"{b:02X}" for b in row).ljust(width * 3 - 1)
        t = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        out.append(f"    {i:06X}  {h}  |{t}|")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--out", default="capture.log")
    ap.add_argument("--seconds", type=float, default=0.0, help="0 = until Ctrl-C")
    args = ap.parse_args()

    sock = socket.create_connection((args.host, args.port), timeout=5)
    sock.settimeout(0.5)
    log = open(args.out, "a", encoding="utf-8")

    banner = f"\n===== capture started {datetime.now():%Y-%m-%d %H:%M:%S} ====="
    print(banner)
    log.write(banner + "\n")
    print("Press PRINT on the balance now. Also try an internal adjustment.")
    print("Noise (continuous mass stream) is counted, not printed.\n")

    noise_bytes = 0
    total = 0
    deadline = time.monotonic() + args.seconds if args.seconds else None

    try:
        while deadline is None or time.monotonic() < deadline:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                continue
            if not chunk:
                print("!! NPort closed the connection")
                break

            total += len(chunk)
            stamp = f"{datetime.now():%H:%M:%S.%f}"[:-3]
            log.write(f"[{stamp}] +{len(chunk)}B raw:\n{hexdump(chunk)}\n")

            if is_pure_noise(chunk):
                noise_bytes += len(chunk)
                continue

            # Show the chunk EXACTLY as received -- nothing subtracted.
            text = chunk.decode(CODEPAGE, errors="replace")
            print(f"[{stamp}] {len(chunk)} bytes:")
            for line in text.split("\n"):
                line = line.rstrip("\r")
                if line.strip():
                    print(f"    | {line}")
            print(hexdump(chunk))
            log.write(f"[{stamp}] DECODED:\n{text}\n")
            log.flush()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        sock.close()
        summary = (f"total {total} B   noise {noise_bytes} B   "
                   f"structured {total - noise_bytes} B")
        print("\n" + "=" * 62)
        print(summary)
        if total and total == noise_bytes:
            print("ONLY the mass stream arrived -- no printout reached this port.")
            print("That means PRINT output goes to the balance's PRINTER device,")
            print("not to its COMPUTER device where the NPort is connected.")
        print(f"raw log: {args.out}")
        print("=" * 62)
        log.write(summary + "\n")
        log.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
