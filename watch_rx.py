"""Live view of the NPort's serial byte counters.

The front-panel Tx/Rx LED only flickers during traffic, so it is easy to miss
and tells you nothing about direction. This polls the console's Monitor ->
Async page and prints a line whenever a counter moves.

Use it as a bench instrument: start it, then plug the balance in, press PRINT,
change the load on the pan. The moment RxTotal moves off zero, the physical
layer is solved.

    python watch_rx.py

Close the NPort console tab in your browser first -- the 5150 allows only one
web session.
"""

import argparse
import sys
import time

from moxa_web import NPort, strip_html


def read(np: NPort):
    parts = strip_html(np.page("Mn_asyn.htm")).split()
    idx = parts.index("DCD")
    f = parts[idx + 1 : idx + 9]
    return {
        "TxTotal": int(f[3]), "RxTotal": int(f[4]),
        "DSR": f[5], "CTS": f[6], "DCD": f[7],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.127.254")
    ap.add_argument("--interval", type=float, default=1.5)
    args = ap.parse_args()

    np = NPort(args.host)
    if not np.login():
        print("Could not log in. Close the NPort console tab in your browser.")
        return 1

    # The counters are cumulative since the NPort booted and never reset, so
    # they already hold bytes from earlier loopback echoes. Baseline against
    # the value at startup and only report genuinely NEW inbound bytes.
    try:
        baseline = read(np)["RxTotal"]
    except Exception:
        baseline = 0
    print(f"watching  (Ctrl-C to stop)   RxTotal baseline = {baseline}")
    print("    counting only bytes received from here on\n")
    print("    time      TxTotal   RxTotal   new-Rx   DSR  CTS  DCD")
    print("    " + "-" * 55)

    last = None
    first_rx = False
    try:
        while True:
            try:
                cur = read(np)
            except Exception:
                if not np.login():
                    print("    lost console session; is the browser tab open?")
                    time.sleep(3)
                    continue
                continue

            if cur != last:
                new_rx = cur["RxTotal"] - baseline
                print(f"    {time.strftime('%H:%M:%S')}  {cur['TxTotal']:8}  "
                      f"{cur['RxTotal']:8}  {new_rx:7}   "
                      f"{cur['DSR']:4} {cur['CTS']:4} {cur['DCD']:4}")
                if new_rx > 0 and not first_rx:
                    first_rx = True
                    print("\n    *** NEW inbound bytes on the serial port ***")
                    print("    *** if you are not running a loopback, the balance is")
                    print("    *** transmitting - physical layer SOLVED, run radwag_read.py\n")
                last = cur
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
