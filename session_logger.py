"""Session logger: one .txt per weighing session, written only on FOOTER.

    header -> weight -> weight -> ... -> footer   ==>   ONE .txt

Nothing is written until the footer arrives. The file contains every burst
concatenated verbatim, in the order received.

MULTIPLE MOXA SERVERS: each host keeps its OWN independent queue. A header on
one balance never mixes with weights from another, and each writes its own file
when its own footer arrives.

    python session_logger.py --outdir sessions
    python session_logger.py --host 192.168.127.254 --host 192.168.127.253

Filename:  <MoxaServerName>_<INST-ID>_<RegNo>.txt

Burst types are told apart by content: INST-ID/Balance S/N -> header,
Date+Time only -> footer, anything else -> weight.
"""

import argparse
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime

PORT = 4001
CODEPAGE = "cp1250"


def moxa_name(host: str) -> str:
    try:
        r = subprocess.run(["snmpget", "-v1", "-c", "public", "-t", "2", "-r", "1",
                            "-Oqv", host, "1.3.6.1.2.1.1.5.0"],
                           capture_output=True, text=True, timeout=6)
        return r.stdout.strip().strip('"') or f"NPort-{host.replace('.', '-')}"
    except Exception:
        return f"NPort-{host.replace('.', '-')}"


def kind_of(text: str) -> str:
    if re.search(r"Adjust|Calibrat", text, re.I):
        return "adjustment"
    if re.search(r"INST-ID|Balance S/N|Balance type", text, re.I):
        # An adjustment report carries the balance block but NO INST-ID and no
        # Reg No -- those only exist on a weighing header. That absence is what
        # tells the two apart, and it is written out immediately rather than
        # waiting for a footer that never comes.
        if not re.search(r"INST-ID", text, re.I) and not re.search(r"Reg No", text, re.I):
            return "adjustment"
        return "header"
    if re.search(r"^\s*Date\b", text, re.M) and re.search(r"^\s*Time\b", text, re.M):
        return "footer"
    return "weight"


SPLIT_AT = re.compile(
    r"(?m)^(?=[-.]*\s*(?:Weighing|Adjustment)\b[^\n]*)|^(?=\s*Current result\b)")


def split_bursts(text: str) -> list[str]:
    """Split one TCP burst into the separate printouts it contains.

    Split ONLY at a titled rule (`--- Weighing ---`, `--- Adjustment ---`) or a
    `Current result` line. An earlier version also split at any bare `-----`
    rule, which cut blocks apart internally and turned the leftover
    `Signature`/rule tail into phantom `weight` segments -- weights nobody
    pressed. Bare rules are decoration inside a block, never a boundary.
    """
    parts, buf = [], []
    for line in text.splitlines(keepends=True):
        if buf and SPLIT_AT.match(line) and "".join(buf).strip():
            parts.append("".join(buf))
            buf = []
        buf.append(line)
    if buf:
        parts.append("".join(buf))
    return [s for s in parts if s.strip()]


def is_noise(text: str) -> bool:
    """Rules, blank lines and a lone `Signature` carry no record content."""
    body = [l.strip() for l in text.splitlines() if l.strip()]
    if not body:
        return True
    for l in body:
        if re.fullmatch(r"[-.\s]*", l):        # a rule
            continue
        if re.fullmatch(r"(?i)signature", l):
            continue
        return False
    return True


def field(text: str, label: str) -> str:
    m = re.search(rf"^\s*{re.escape(label)}:?\s{{2,}}(\S.*?)\s*$", text, re.M)
    return m.group(1).strip() if m else ""


def safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-") or "NA"


class Station:
    """One MOXA server: its own socket, buffer and session queue."""

    def __init__(self, host: str, port: int, outdir: str, gap: float):
        self.host, self.port, self.outdir, self.gap = host, port, outdir, gap
        self.name = moxa_name(host)
        self.sock: socket.socket | None = None
        self.buf = bytearray()
        self.last_rx = 0.0
        self.session: list[str] = []
        self.inst_id = ""
        self.reg_no = ""
        self.weights = 0

    def log(self, msg: str) -> None:
        print(f"[{datetime.now():%H:%M:%S}] {self.name:22} {msg}")

    def connect(self) -> None:
        if self.sock:
            return
        try:
            self.sock = socket.create_connection((self.host, self.port), timeout=5)
            self.sock.settimeout(0.05)
            self.log("connected")
        except ConnectionRefusedError:
            # The NPort allows ONE TCP client. Refused nearly always means
            # another tool already holds port 4001, not that it is unreachable.
            self.log("busy: port 4001 already in use by another client "
                     "(NPort Max connection = 1) - retrying in 5s")
            self.sock = None
            time.sleep(5)
        except OSError as exc:
            self.log(f"offline: {exc.strerror or exc} - retrying in 5s")
            self.sock = None
            time.sleep(5)

    def write_session(self) -> None:
        if not self.session:
            return
        os.makedirs(self.outdir, exist_ok=True)   # dir can vanish between writes
        base = f"{safe(self.name)}_{safe(self.inst_id or 'NA')}_{safe(self.reg_no or 'NA')}"
        path = os.path.join(self.outdir, base + ".txt")
        n = 1
        while os.path.exists(path):
            n += 1
            path = os.path.join(self.outdir, f"{base}_{n}.txt")
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write("".join(self.session))
        self.log(f"SESSION WRITTEN ({len(self.session)} bursts) -> {os.path.basename(path)}")
        self.session, self.inst_id, self.reg_no, self.weights = [], "", "", 0

    def pump(self) -> None:
        self.connect()
        if not self.sock:
            return
        try:
            chunk = self.sock.recv(8192)
            if not chunk:
                raise ConnectionResetError("NPort closed")
        except socket.timeout:
            chunk = b""
        except OSError as exc:
            self.log(f"link lost ({exc}); reconnecting")
            self.sock.close()
            self.sock = None
            return

        if chunk:
            self.buf.extend(chunk)
            self.last_rx = time.monotonic()

        if self.buf and self.last_rx and (time.monotonic() - self.last_rx) > self.gap:
            whole = bytes(self.buf).decode(CODEPAGE, errors="replace")
            self.buf = bytearray()
            segments = split_bursts(whole)
            if len(segments) > 1:
                self.log(f"burst contained {len(segments)} printouts - split")
            for text in segments:
                self._handle(text)

    def _handle(self, text: str) -> None:
            if is_noise(text):
                return                       # rules / blank / "Signature" only
            kind = kind_of(text)
            lines = len([l for l in text.splitlines() if l.strip()])

            if kind == "adjustment":
                # Standalone: no footer follows, so write it straight out and
                # leave any open weighing session untouched.
                sn = field(text, "Balance S/N") or field(text, "Balance SN")
                os.makedirs(self.outdir, exist_ok=True)
                base = f"{safe(self.name)}_{safe(sn or 'NA')}_CAL"
                path = os.path.join(self.outdir, base + ".txt")
                n = 1
                while os.path.exists(path):
                    n += 1
                    path = os.path.join(self.outdir, f"{base}_{n}.txt")
                with open(path, "w", encoding="utf-8", newline="") as fh:
                    fh.write(text)
                self.log(f"ADJUSTMENT {lines:3} lines  S/N={sn} "
                         f"-> {os.path.basename(path)}")
            elif kind == "header":
                if self.session:
                    # A second header means the previous flow never reached a
                    # footer. header -> ... -> header is not a valid session, so
                    # the incomplete one is discarded, not written.
                    self.log(f"DISCARDED incomplete session "
                             f"({len(self.session)} bursts, no footer)")
                    self.session, self.inst_id, self.reg_no, self.weights = [], "", "", 0
                self.inst_id = field(text, "INST-ID") or self.inst_id
                self.reg_no = field(text, "Reg No") or self.reg_no
                self.session.append(text)
                self.log(f"header {lines:3} lines  INST-ID={self.inst_id} RegNo={self.reg_no}")
            elif kind == "weight":
                if not self.session:
                    # No header has opened a session, so this weight has no
                    # metadata to belong to. Discard it rather than start a
                    # session from the middle.
                    self.log(f"DISCARDED weight {lines:3} lines (no header yet)")
                    return
                self.session.append(text)
                self.weights += 1
                self.log(f"weight {lines:3} lines  ({len(self.session)} bursts held)")
            else:
                if not self.session:
                    self.log(f"DISCARDED footer {lines:3} lines (no header yet)")
                    return
                if not self.weights:
                    # header -> footer with nothing weighed between them is not a
                    # valid session. Discard the whole flow rather than store an
                    # empty record.
                    self.log(f"DISCARDED session: header -> footer with no weight")
                    self.session, self.inst_id, self.reg_no = [], "", ""
                    self.weights = 0
                    return
                self.session.append(text)
                self.log(f"footer {lines:3} lines")
                self.write_session()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", action="append", default=None,
                    help="MOXA host. Repeat for several, or comma-separate.")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--outdir", default="sessions")
    ap.add_argument("--gap", type=float, default=1.5)
    args = ap.parse_args()

    hosts: list[str] = []
    for h in (args.host or ["192.168.127.254"]):
        hosts += [x.strip() for x in h.split(",") if x.strip()]

    os.makedirs(args.outdir, exist_ok=True)
    stations = [Station(h, args.port, args.outdir, args.gap) for h in hosts]

    print(f"writing sessions to {os.path.abspath(args.outdir)}/")
    for st in stations:
        print(f"  queue: {st.name:22} <- {st.host}:{args.port}")
    print("\nheader -> weight... -> FOOTER writes that station's file. Ctrl-C to stop.\n")

    try:
        while True:
            for st in stations:
                st.pump()
            time.sleep(0.02)
    except KeyboardInterrupt:
        for st in stations:
            if st.session:
                st.log("Ctrl-C with an open session - writing what we have")
                st.write_session()
        print("stopped")
    finally:
        for st in stations:
            if st.sock:
                st.sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
