"""Ask the Radwag what metadata it can report.

Sends only READ-ONLY / informational commands. Deliberately excluded because
they act on the instrument rather than report from it:

    IC, IC0, IC1        internal calibration -- never send casually
    Z, T, NT            zero / tare
    K0, K1              keypad lock
    C0, C1              continuous transmission on/off
    B0, B1, B2, BP, BN  beeper
    LOGOUT, PSW, PSWG   session / password
    US, *S setters      "S" suffix is usually Set (PARS, ARS, ...)
    SOUT, GOUT          output control
    RBT.*, CMP_*, MA.*  robot / comparison / mass-automation procedures

Continuous transmission floods the line with unterminated `0.00000 g` tokens,
so replies get that noise prefixed. We strip it before reporting.
"""

import argparse
import re
import socket
import sys
import time

HOST = "192.168.127.254"
PORT = 4001

# Unterminated continuous-transmission noise: bare "<number> <unit>" runs.
NOISE = re.compile(r"^(?:[-+]?\d+(?:[.,]\d+)?\s*[a-zA-Z%]{1,3})+")

QUERIES = [
    ("SN",          "balance serial number"),
    ("RV",          "firmware / program version"),
    ("GIN",         "device info"),
    ("PINFO",       "printout / program info"),
    ("WINFO",       "weighing info"),
    ("CONFIG.DESC", "configuration description"),
    ("PROFILE",     "active profile name"),
    ("UG",          "current unit"),
    ("UI",          "available units"),
    ("OT",          "current tare value"),
    ("DH",          "date / time"),
    ("DT",          "date"),
    ("TV",          "tare value / variable"),
    ("PID",         "product identifier"),
    ("GET_AMBIENT", "ambient temperature / humidity"),
    ("PARG",        "parameters (get)"),
    ("ARG",         "auto-range (get)"),
    ("FIG",         "filter (get)"),
    ("OMG",         "operating mode (get)"),
    ("OMI",         "operating mode list"),
    ("EVG",         "event settings (get)"),
    ("IPG",         "IP / interface (get)"),
    ("PSHG",        "screensaver-or-similar (get)"),
    ("VG",          "value / version (get)"),
    ("GM",          "give mass"),
    ("GF",          "give filter / factor"),
    ("UH",          "unit (h)"),
    ("UT",          "unit (t)"),
    ("UW",          "unit (w)"),
    ("LS",          "list"),
    ("WILST",       "working-item list"),
    ("WP",          "working parameters"),
    ("NB",          "unknown - probing"),
    ("SM",          "unknown - probing"),
    ("LW",          "unknown - probing"),
    ("LWI",         "unknown - probing"),
]


def clean(frame: str) -> str:
    """Drop leading continuous-transmission noise from a reply frame."""
    return NOISE.sub("", frame).strip()


def ask(sock: socket.socket, cmd: str, wait: float) -> list[str]:
    # Drain whatever the stream has queued, with a hard cap so an endless
    # stream cannot trap us in this loop.
    deadline = time.monotonic() + 1.0
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
            chunk = sock.recv(8192)
        except socket.timeout:
            continue
        if not chunk:
            break
        buf += chunk
        if b"\r" in buf or b"\n" in buf:
            # Give a multi-frame reply a moment to finish arriving.
            time.sleep(0.35)
            try:
                buf += sock.recv(8192)
            except socket.timeout:
                pass
            break

    text = buf.decode("ascii", errors="replace")
    out = []
    for frame in re.split(r"[\r\n]+", text):
        c = clean(frame)
        if c:
            out.append(c)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--wait", type=float, default=1.6)
    args = ap.parse_args()

    sock = socket.create_connection((args.host, args.port), timeout=5)
    sock.settimeout(0.4)

    supported, rejected, silent = [], [], []
    try:
        for cmd, note in QUERIES:
            frames = ask(sock, cmd, args.wait)
            if not frames:
                silent.append(cmd)
                print(f"  {cmd:12} {note:34} (no reply)")
                continue
            joined = " | ".join(frames)
            if joined.strip().upper().startswith("ES"):
                rejected.append(cmd)
                print(f"  {cmd:12} {note:34} ES (not supported / needs args)")
                continue
            supported.append((cmd, note, joined))
            print(f"  {cmd:12} {note:34} {joined[:120]}")
    finally:
        sock.close()

    print("\n" + "=" * 70)
    print(f"ANSWERED: {len(supported)}   REJECTED(ES): {len(rejected)}   SILENT: {len(silent)}")
    if supported:
        print("\nUsable metadata sources:")
        for cmd, note, val in supported:
            print(f"  {cmd:12} {note}")
            print(f"               -> {val[:160]}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
