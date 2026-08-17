"""Active command prober for a Radwag balance behind a MOXA NPort.

The original test script sent b'P\\r\\n'. Two problems with that:

  1. 'P' is the Mettler/Ohaus print command. Radwag's protocol uses
     S / SI / SU / SUI. A Radwag balance answers 'P' with either nothing
     or an error, depending on model.
  2. If the literal two-character sequence backslash-r is in the source
     (b'P\\\\r\\\\n'), no CR/LF is ever sent, so the balance never sees a
     terminated command at all.

This walks the real Radwag command set over a single TCP connection and
reports exactly what came back for each.
"""

import argparse
import socket
import sys
import time

HOST = "192.168.127.254"
PORT = 4001

# (command, what it should do) - Radwag protocol, CR LF terminated.
RADWAG = [
    ("SI", "send immediate mass (no stability wait) - best first test"),
    ("S", "send mass once stable"),
    ("SUI", "send immediate mass in current unit"),
    ("SU", "send stable mass in current unit"),
    ("PC", "list all commands the balance implements"),
    ("UG", "report current unit"),
    ("OT", "report tare value"),
]

# Other vendors' print commands, in case the balance is not speaking Radwag.
FOREIGN = [
    ("P", "Mettler/Ohaus print"),
    ("SIR", "Mettler SICS continuous-immediate"),
    ("IP", "Sartorius print"),
]


def printable(chunk: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)


def drain(sock: socket.socket, wait: float) -> bytes:
    """Collect everything that arrives within `wait` seconds."""
    out = bytearray()
    end = time.monotonic() + wait
    while time.monotonic() < end:
        sock.settimeout(max(0.05, end - time.monotonic()))
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            break
        out.extend(chunk)
    return bytes(out)


def try_command(sock: socket.socket, cmd: str, note: str, wait: float) -> bytes:
    payload = cmd.encode("ascii") + b"\r\n"
    print(f"\n--> {cmd!r:8} ({note})")
    print(f"    sending {payload!r}  = {' '.join(f'{b:02X}' for b in payload)}")
    sock.sendall(payload)
    reply = drain(sock, wait)
    if reply:
        print(f"    <-- {len(reply)} byte(s): {reply!r}")
        print(f"        hex : {' '.join(f'{b:02X}' for b in reply)}")
        print(f"        text: |{printable(reply)}|")
    else:
        print("    <-- (nothing)")
    return reply


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--wait", type=float, default=2.0, help="seconds to wait per command")
    ap.add_argument("--foreign", action="store_true", help="also try other vendors' commands")
    args = ap.parse_args()

    print(f"Connecting to {args.host}:{args.port} ...")
    sock = socket.create_connection((args.host, args.port), timeout=5)
    print("Connected.")

    # Anything the balance was already streaming before we said a word.
    pre = drain(sock, 1.5)
    if pre:
        print(f"\nBalance was already streaming unprompted: {pre!r}")

    results = {}
    try:
        for cmd, note in RADWAG:
            results[cmd] = try_command(sock, cmd, note, args.wait)
        if args.foreign:
            for cmd, note in FOREIGN:
                results[cmd] = try_command(sock, cmd, note, args.wait)
    except (BrokenPipeError, ConnectionResetError) as exc:
        print(f"\n!! connection dropped: {exc}")
    finally:
        sock.close()

    answered = [c for c, r in results.items() if r]
    print("\n" + "=" * 62)
    if answered:
        print(f"COMMANDS THAT GOT A REPLY: {', '.join(answered)}")
    else:
        print("NO COMMAND GOT ANY REPLY.")
        print(
            "\nThe balance is not hearing us, or we are not hearing it.\n"
            "Since TCP is fine, the break is on the RS-232 side. Run\n"
            "moxa_listen.py and press PRINT by hand: if that is also silent,\n"
            "it is wiring (or the balance's serial output is off)."
        )
    print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
