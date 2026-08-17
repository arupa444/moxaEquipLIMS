"""Dump every balance printout to a .txt, verbatim.

    Radwag XA 4Y --RS-232--> NPort 5150 --TCP 4001--> this service --> .txt

Run it and leave it running. Whenever the balance transmits -- header, footer,
weight, adjustment report, anything -- the bytes are written to a timestamped
.txt exactly as received.

    python print_logger.py --outdir records

NO PARSING. Deliberately.

Every earlier version interpreted the stream, and every interpretation lost or
mangled something real:

  * a noise filter stripped `<number> <unit>` patterns and so deleted the
    measurements out of the middle of `Current result` lines
  * a dedupe pass collapsed blocks it judged to be repeats
  * an unglue pass moved a stray mass token to a different position
  * a classifier renamed records, and mislabelled headers as measurements
  * a pairer held bursts back and combined them

The raw text IS the record. This version adds nothing and removes nothing, so
what lands on disk is precisely what the balance sent. Interpretation, if it is
ever wanted, belongs downstream of an intact transcript.

The only transformation is decoding bytes to text using the balance's code page
(cp1250), which is required to produce a .txt at all. Raw bytes are preserved
byte-for-byte alongside if --keep-bin is passed.

Records are separated by an idle gap (--gap seconds of silence), because the
balance transmits no record separator of any kind.
"""

import argparse
import json
import os
import socket
import sys
import time
from datetime import datetime

HOST = "192.168.127.254"
PORT = 4001
CODEPAGE = "cp1250"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--outdir", default="records")
    ap.add_argument("--gap", type=float, default=1.5,
                    help="seconds of silence that ends a record")
    ap.add_argument("--keep-bin", action="store_true",
                    help="also write the raw bytes as a .bin next to the .txt")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    print(f"writing records to {os.path.abspath(args.outdir)}/")
    print("raw passthrough -- no parsing. Ctrl-C to stop.\n")

    buf = bytearray()
    started: datetime | None = None
    last_rx = 0.0
    sock = None

    def flush() -> None:
        nonlocal buf, started
        if not buf:
            return
        when = started or datetime.now()
        stamp = when.strftime("%Y%m%d-%H%M%S")
        path = os.path.join(args.outdir, f"{stamp}.txt")
        n = 1
        while os.path.exists(path):          # two records in the same second
            n += 1
            path = os.path.join(args.outdir, f"{stamp}-{n}.txt")

        text = bytes(buf).decode(CODEPAGE, errors="replace")
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        if args.keep_bin:
            with open(path[:-4] + ".bin", "wb") as fh:
                fh.write(bytes(buf))

        with open(os.path.join(args.outdir, "index.jsonl"), "a",
                  encoding="utf-8") as fh:
            fh.write(json.dumps({
                "file": os.path.basename(path),
                "received": when.isoformat(timespec="seconds"),
                "bytes": len(buf),
                "lines": text.count("\n"),
            }) + "\n")

        print(f"[{datetime.now():%H:%M:%S}] {len(buf):5} bytes, "
              f"{text.count(chr(10)):2} lines -> {os.path.basename(path)}")
        buf = bytearray()
        started = None

    try:
        while True:
            if sock is None:
                try:
                    sock = socket.create_connection((args.host, args.port),
                                                    timeout=5)
                    sock.settimeout(0.3)
                    print(f"connected to {args.host}:{args.port}")
                except OSError as exc:
                    print(f"connect failed ({exc}); retrying in 3s")
                    time.sleep(3)
                    continue

            try:
                chunk = sock.recv(8192)
                if not chunk:
                    raise ConnectionResetError("NPort closed the connection")
            except socket.timeout:
                chunk = b""
            except OSError as exc:
                print(f"link lost ({exc}); reconnecting")
                sock.close()
                sock = None
                time.sleep(2)
                continue

            if chunk:
                if not buf:
                    started = datetime.now()
                buf.extend(chunk)
                last_rx = time.monotonic()

            if buf and last_rx and (time.monotonic() - last_rx) > args.gap:
                flush()

            if not chunk:
                time.sleep(0.05)
    except KeyboardInterrupt:
        flush()
        print("\nstopped")
    finally:
        if sock:
            sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
