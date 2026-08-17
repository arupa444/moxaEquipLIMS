"""Fetch everything the Radwag XA 4Y will actually report over RS-232.

Every command here was verified against this balance (serial 718623,
firmware LL1.9 S). Read-only: nothing changes instrument state.

    python radwag_info.py            # human-readable report
    python radwag_info.py --json     # machine-readable, for logging

CAVEAT on GET_AMBIENT: its <TIME=...> and sensor values were observed FROZEN --
identical across reads 20 s apart. Treat it as a stale snapshot, not a live
clock or live ambient feed. Timestamp your records from the host clock instead;
`captured_utc` below is the host time at capture.
"""

import argparse
import json
import re
import socket
import sys
import time
from datetime import datetime, timezone

HOST = "192.168.127.254"
PORT = 4001

# Strip unterminated continuous-transmission noise ("0.00000 g0.00000 g...").
NOISE = re.compile(r"^(?:[-+]?\d+(?:[.,]\d+)?\s*[a-zA-Z%]{1,3})+")

# command -> (label, parser key)
QUERIES = [
    ("SUI",         "mass"),
    ("OT",          "tare"),
    ("UG",          "unit_current"),
    ("UI",          "units_available"),
    ("SN",          "serial_number"),
    ("RV",          "firmware"),
    ("OMG",         "operating_mode"),
    ("OMI",         "operating_modes_available"),
    ("PID",         "product_id"),
    ("WP",          "printout_template"),
    ("WINFO",       "device"),
    ("GET_AMBIENT", "ambient"),
]


def ask(sock: socket.socket, cmd: str, wait: float = 1.6) -> str:
    deadline = time.monotonic() + 0.8
    while time.monotonic() < deadline:
        try:
            if not sock.recv(8192):
                break
        except socket.timeout:
            break
    sock.sendall(cmd.encode("ascii") + b"\r\n")
    buf = b""
    end = time.monotonic() + wait
    while time.monotonic() < end:
        try:
            buf += sock.recv(8192)
        except socket.timeout:
            pass
    frames = [
        NOISE.sub("", f).strip()
        for f in re.split(r"[\r\n]+", buf.decode("ascii", errors="replace"))
    ]
    return " ".join(f for f in frames if f)


def kv_fields(reply: str) -> dict:
    """Parse Radwag's <KEY=VALUE><KEY=VALUE> style replies."""
    return dict(
        (k, v) for k, v in (p.split("=", 1) for p in re.findall(r"<([^>]*)>", reply) if "=" in p)
    )


def strip_prefix(cmd: str, reply: str) -> str:
    """Peel the echoed command, a bare A/I status flag, and a trailing OK."""
    out = reply
    if out.upper().startswith(cmd.upper()):
        out = out[len(cmd):]
    out = out.strip()
    if out.upper().endswith(" OK"):
        out = out[:-3].strip()
    # `RV A "LL1.9 S"` -> drop the standalone status flag before the payload.
    m = re.match(r'^[AI]\s+(?=["\d])', out)
    if m:
        out = out[m.end():]
    # Unquote only when the WHOLE value is quoted -- a blanket strip('"') turned
    # `1 "Weighing"` into `1 "Weighing` and left a dangling quote.
    if len(out) >= 2 and out[0] == '"' and out[-1] == '"':
        out = out[1:-1]
    return out.strip()


def collect(host: str, port: int) -> dict:
    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(0.4)
    data = {"captured_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    try:
        for cmd, key in QUERIES:
            reply = ask(sock, cmd)
            if not reply or reply.upper().startswith("ES"):
                data[key] = None
                continue
            if "<" in reply:
                data[key] = kv_fields(reply)
            else:
                data[key] = strip_prefix(cmd, reply)
    finally:
        sock.close()
    return data


def report(d: dict) -> None:
    dev = d.get("device") or {}
    amb = d.get("ambient") or {}

    print("=" * 62)
    print("  RADWAG BALANCE INFO")
    print("=" * 62)
    print(f"  captured (host clock) : {d['captured_utc']}")
    print()
    print("  IDENTITY")
    print(f"    device name         : {dev.get('DEVICE_NAME', '-')}")
    print(f"    device type         : {dev.get('DEVICE_TYPE', '-')}")
    print(f"    serial number       : {d.get('serial_number', '-')}")
    print(f"    firmware            : {d.get('firmware', '-')}")
    print(f"    MAC address         : {dev.get('MAC_ADDRESS', '-')}")
    print(f"    platforms           : {dev.get('NUMBER_OF_PLATFORMS', '-')}")
    print(f"    product id          : {d.get('product_id', '-')}")
    print()
    print("  MEASUREMENT")
    print(f"    mass                : {d.get('mass', '-')}")
    print(f"    tare                : {d.get('tare', '-')}")
    print(f"    current unit        : {d.get('unit_current', '-')}")
    print(f"    units available     : {d.get('units_available', '-')}")
    print(f"    operating mode      : {d.get('operating_mode', '-')}")
    print(f"    modes available     : {d.get('operating_modes_available', '-')}")
    print()
    print("  AMBIENT  (STALE - see module docstring)")
    print(f"    temperature 1       : {amb.get('IS_TEMP', '-')} C")
    print(f"    temperature 2       : {amb.get('IS_TEMP2', '-')} C")
    print(f"    humidity            : {amb.get('IS_HUM', '-')} %")
    print(f"    pressure            : {amb.get('IS_PRESSURE', '-')} hPa")
    print(f"    air density         : {amb.get('DENSITY', '-')}")
    print(f"    balance timestamp   : {amb.get('TIME', '-')}   <-- frozen, do not trust")
    print()
    print("  PRINTOUT TEMPLATE")
    print(f"    weighing template   : {d.get('printout_template', '-')}")
    print("    (this is why the stream carries only mass and no CR/LF)")
    print("=" * 62)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    data = collect(args.host, args.port)
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        report(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
