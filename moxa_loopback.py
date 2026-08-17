"""Loopback test - isolates cable faults from balance faults.

Physical RS-232 has no error reporting, so the only way to prove which side
is broken is to short TXD to RXD and see whether our own bytes come back.

Test A - loopback AT THE MOXA
    Unplug the cable from the NPort. On the NPort's DB9, short pin 2 to
    pin 3 (a paperclip or bent wire works).
    Passes -> the NPort's UART, baud setting and TCP path are all healthy.
    Fails  -> the NPort port itself is misconfigured or faulty.

Test B - loopback AT THE FAR END OF THE CABLE
    Reconnect the cable to the NPort, unplug it from the balance, and short
    pin 2 to pin 3 on the connector that would plug into the balance.
    Fails  -> the cable is the fault: a broken conductor or a missing data
              line. Replace it.
    Passes -> the cable has both data lines intact end to end.

    NOTE: test B passing does NOT prove the cable is the right *type*.
    Shorting pin 2 to pin 3 at the far end loops NPort TXD back to NPort RXD
    whether the cable is straight-through (2-2, 3-3) or crossover (2-3, 3-2),
    so both wirings pass identically. The test proves continuity, not polarity.
    Straight vs crossover can only be told apart with a continuity meter, or
    empirically by trying a null-modem adapter. See CABLE.md.

Run:  python moxa_loopback.py --label "test A"
"""

import argparse
import socket
import sys
import time

from moxa_web import NPort, strip_html

HOST = "192.168.127.254"
PORT = 4001
PROBE = b"MOXA-LOOPBACK-TEST-0123456789\r\n"


def read_counters(host: str):
    """Return (TxTotalCnt, RxTotalCnt, DSR, CTS, DCD) straight from the NPort."""
    try:
        np = NPort(host)
        if not np.login():
            return None
        text = strip_html(np.page("Mn_asyn.htm"))
        parts = text.split()
        # ... DCD  1  <TxCnt> <RxCnt> <TxTotal> <RxTotal> <DSR> <CTS> <DCD>
        idx = parts.index("DCD")
        f = parts[idx + 1 : idx + 9]
        return {
            "TxCnt": f[1], "RxCnt": f[2],
            "TxTotal": f[3], "RxTotal": f[4],
            "DSR": f[5], "CTS": f[6], "DCD": f[7],
        }
    except Exception as exc:
        print(f"    (could not read NPort counters: {exc})")
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--label", default="loopback test")
    ap.add_argument("--wait", type=float, default=3.0)
    args = ap.parse_args()

    print(f"=== {args.label} ===")
    before = read_counters(args.host)
    if before:
        print(f"before: TxTotal={before['TxTotal']} RxTotal={before['RxTotal']} "
              f"DSR={before['DSR']} CTS={before['CTS']} DCD={before['DCD']}")

    sock = socket.create_connection((args.host, args.port), timeout=5)
    sock.settimeout(0.4)
    try:
        sock.recv(4096)          # discard anything stale
    except socket.timeout:
        pass

    print(f"sending {len(PROBE)} bytes: {PROBE!r}")
    sock.sendall(PROBE)

    got = bytearray()
    end = time.monotonic() + args.wait
    while time.monotonic() < end and len(got) < len(PROBE):
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            break
        got.extend(chunk)
    sock.close()

    after = read_counters(args.host)
    if after:
        print(f"after : TxTotal={after['TxTotal']} RxTotal={after['RxTotal']} "
              f"DSR={after['DSR']} CTS={after['CTS']} DCD={after['DCD']}")

    print(f"\nechoed back: {len(got)} byte(s): {bytes(got)!r}")
    print("=" * 62)
    if bytes(got) == PROBE:
        print("PASS - exact echo. TX and RX are connected end to end at 9600 8N1.")
    elif got:
        print("PARTIAL - bytes came back but corrupted.")
        print("The wire is fine; this is a BAUD/FRAMING mismatch.")
    else:
        print("FAIL - nothing came back. TXD is not reaching RXD on this path.")
    print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
