"""Tell a straight-through DB9 cable from a null-modem one, with no meter.

The pin 2 - pin 3 loopback cannot do this: shorting the two data pins at the
far end loops TXD back to RXD identically for both wirings. We need an
ASYMMETRIC short, and a signal we can switch from software.

The NPort raises BOTH RTS (pin 7) and DTR (pin 4) whenever a TCP client
connects to port 4001, and drops them on disconnect -- verified on this unit.
Those are our stimuli; DSR (pin 6) and CTS (pin 8) are our sensors.

Bridge ALL FOUR holes of the bottom row together -- pins 6, 7, 8, 9. Shorting
the whole row means there is nothing to miscount, which matters because female
DB9s are numbered mirrored and picking two specific holes is error-prone.

Pin 4 (DTR) and pin 5 (GND) are in the TOP row, so they stay out of it.

    straight-through (6-6, 7-7, 8-8, 9-9)
        the short ties NPort DSR(6), RTS(7), CTS(8), RI(9) together
        RTS is asserted, so it drives both inputs
        => DSR ON and CTS ON

    null modem (7-8, 8-7, 4-6, 6-4)
        far 6 <- NPort DTR(4);  far 7 <- NPort CTS(8);  far 8 <- NPort RTS(7)
        the short ties NPort DTR, CTS and RTS together
        NPort DSR(6) goes to far pin 4, which is in the top row and NOT shorted
        => CTS ON, DSR stays off

    3-wire cable (only 2, 3, 5 carried)
        nothing in the bottom row is connected => both stay off

Safe in both cases: at worst one asserted NPort output drives some inputs, or
two simultaneously-asserted outputs (RTS and DTR) are tied together.

Signal states are read over SNMP, not the web console, so this does NOT care
whether the console is open in a browser.

WIRING IT UP
    1. Cable stays plugged into the NPort. Unplug the balance end.
    2. On the free (female) connector, bridge the ENTIRE BOTTOM ROW -- all four
       holes shorted to each other. A bared wire laid along the row and pushed
       into each hole works, or a folded strip of kitchen foil.
       The bottom row is the row of FOUR (the top row has five).
    3. Stop any other script that talks to port 4001 (radwag_read, watch_rx,
       moxa_listen). The NPort allows only one TCP client, and this test needs
       to open and close that connection itself.
    4. Run this script.
"""

import argparse
import re
import socket
import subprocess
import sys
import time

HOST = "192.168.127.254"
PORT = 4001

SIG_NAME = {1: "RTS", 2: "CTS", 3: "DSR", 4: "DTR", 6: "DCD"}
SIG_STATE = {1: "none", 2: "ON", 3: "off"}

# A broad walk of the whole RS-232 subtree is reliable on this firmware.
# Walking .10.33.5 or .10.33.6 directly is NOT -- it returns a single bogus
# row that contradicts the broad walk. Do not "optimise" this.
RS232_ROOT = "1.3.6.1.2.1.10.33"
ROW = re.compile(
    r"\s*\.1\.3\.6\.1\.2\.1\.10\.33\.(5|6)\.1\.3\.1\.(\d+)\s*=\s*INTEGER:\s*(\d+)"
)


def read_signals(host: str):
    """(inputs, outputs) as {'CTS': 'off', ...} read over SNMP."""
    proc = subprocess.run(
        ["snmpwalk", "-v1", "-c", "public", "-t", "2", "-r", "2", "-On", host, RS232_ROOT],
        capture_output=True,
        text=True,
    )
    ins, outs = {}, {}
    for line in proc.stdout.splitlines():
        m = ROW.match(line)
        if not m:
            continue
        table, idx, val = m.group(1), int(m.group(2)), int(m.group(3))
        target = ins if table == "5" else outs
        target[SIG_NAME.get(idx, str(idx))] = SIG_STATE.get(val, "?")
    return ins, outs


def show(tag: str, ins: dict, outs: dict) -> None:
    print(f"    {tag:16}  OUT RTS={outs.get('RTS','-'):4} DTR={outs.get('DTR','-'):4}"
          f"   |   IN CTS={ins.get('CTS','-'):4} DSR={ins.get('DSR','-'):4} "
          f"DCD={ins.get('DCD','-'):4}")


def verdict(idle: dict, live: dict) -> str:
    dsr_rose = idle.get("DSR") == "off" and live.get("DSR") == "ON"
    cts_rose = idle.get("CTS") == "off" and live.get("CTS") == "ON"

    # Works for either bridge style, because DSR can only rise if far pin 6 is
    # wired to NPort pin 6 -- i.e. straight through:
    #   bridge 6-7 only   : straight -> DSR on, CTS off ; crossover -> CTS on
    #   bridge whole row  : straight -> DSR on, CTS on  ; crossover -> CTS on
    # So ANY DSR rise means straight-through; CTS rising alone means crossover.
    if dsr_rose:
        both = " and CTS" if cts_rose else ""
        return (
            "STRAIGHT-THROUGH cable.\n\n"
            f"DSR{both} rose, and DSR can only rise if far-end pin 6 is wired to\n"
            "NPort pin 6 -- that is straight-through wiring.\n\n"
            "Between two DTE devices -- which the NPort and the balance both\n"
            "are -- this cable CANNOT work on its own. TXD is wired to TXD.\n\n"
            "FIX: use a null-modem cable, or put a null-modem adapter inline.\n"
            "Note: chaining this cable with another does NOT flip polarity."
        )
    if cts_rose:
        return (
            "NULL-MODEM (crossover) cable.\n\n"
            "CTS rose while DSR stayed off -- the crossed-handshake signature.\n"
            "NPort DSR is wired to far pin 4, up in the top row, so the bridge\n"
            "could not reach it.\n\n"
            "The cable is CORRECT. The remaining suspect is the balance: which\n"
            "physical socket is really COM1, or whether it is transmitting at all."
        )
    return (
        "NO HANDSHAKE LINES - neither DSR nor CTS moved.\n\n"
        "With the whole bottom row shorted there is nothing left to miscount,\n"
        "so this is now a believable result: a 3-wire cable carrying only TXD,\n"
        "RXD and GND. That is electrically fine here (no flow control in use).\n\n"
        "IMPORTANT: straight vs crossover CANNOT be determined from the NPort on\n"
        "a 3-wire cable. Any bridge between the far end's three live holes is\n"
        "symmetric, and grounding RXD reads as idle MARK rather than as data, so\n"
        "no software test can tell the two apart. Use a continuity meter\n"
        "(pin 2<->2 vs pin 2<->3), or try a null-modem adapter both ways."
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    args = ap.parse_args()

    print(__doc__.split("WIRING IT UP")[1].strip())
    print("\n" + "=" * 64)

    ins, outs = read_signals(args.host)
    if not ins and not outs:
        print("No SNMP response. Is the NPort reachable at " + args.host + "?")
        return 1

    if outs.get("RTS") == "ON":
        print("\n!! RTS is already asserted, so something is connected to port 4001.")
        print("!! Stop radwag_read.py / watch_rx.py / moxa_listen.py and rerun,")
        print("!! otherwise there is no idle baseline to compare against.")
        return 1

    show("idle (no TCP)", ins, outs)

    try:
        sock = socket.create_connection((args.host, args.port), timeout=5)
    except ConnectionRefusedError:
        print("\nPort 4001 refused the connection - another client holds it.")
        print("Stop the other script and rerun.")
        return 1

    try:
        time.sleep(2.5)                       # let the lines settle
        live_ins, live_outs = read_signals(args.host)
        show("TCP connected", live_ins, live_outs)
    finally:
        sock.close()

    if live_outs.get("RTS") != "ON":
        print("\nRTS did not assert on connect - cannot run the test on this unit.")
        return 1

    print("=" * 64)
    print(verdict(ins, live_ins))
    print("=" * 64)
    return 0


if __name__ == "__main__":
    sys.exit(main())
