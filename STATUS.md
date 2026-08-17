# RESOLVED — 2026-08-17

The link works end to end:

    Radwag AS R2 PLUS --RS-232--> NPort 5150 --TCP 4001--> Python on macOS

**Root cause:** both original DB9 cables were **straight-through**. The NPort and
the balance are both DTE, so TXD met TXD and no byte could ever cross. Replacing
them with a female-to-female **null-modem (crossover)** cable fixed it. `DSR` went
`ON` for the first time the moment it was plugged in — the balance had been alive
and asserting DTR all along.

Confirmed working with `S`, `SU`, `SUI`, `UG`, `OT` and `PC` (the balance returned
its full 98-command list), plus live streaming readings.

Two firmware quirks found on this unit, both handled in `radwag_read.py`:

1. **`SI` is rejected with `ES`.** Use **`SUI`** for an immediate reading — it is
   now the default `--command`. `S`/`SU` work too but wait for stability.
2. **Continuous transmission emits no terminators.** Its printout template lacks
   CR/LF, so the stream arrives as `0.00000 g0.00000 g0.00000 g…` with zero
   control bytes. `lines()` falls back to extracting `<number> <unit>` tokens.
   For clean framing *and* stability flags, switch continuous transmission **off**
   in the balance menu and use `--mode poll` instead.

Everything below is the investigation record that led here.

---

# Where this investigation stood

## Proven working (by measurement, not assumption)

| Thing | Evidence |
|---|---|
| Mac → NPort network | ping + `nc`, `Mn_line.htm` shows the session connected |
| NPort TCP server on 4001 | connections accepted, data path verified |
| NPort UART, both directions | **loopback at the NPort's own DB9 echoed 31/31 bytes exactly** |
| NPort serial config | 4800 8/N/1, no flow control, RS-232 — confirmed live via SNMP |
| NPort raises RTS + DTR on TCP connect | SNMP: both `off` → `ON` → `off` |
| Radwag menu config | Computer → COM1, Printer → COM1, COM1 = 4800 8/N/1, continuous TX on |
| Byte accounting | `TxTotalCnt` matched sent bytes exactly, every time (40, then 28) |

## The one number that has never moved

    RxTotalCnt = 0

Not one start bit has ever arrived on the NPort's RXD pin from the balance,
across every configuration we have tried. `DSR`, `CTS` and `DCD` have been
`OFF` throughout.

## What that rules out

- **Baud rate.** A mismatch still increments `RxTotalCnt` with garbage. Ours
  stays at exactly 0. Matching 9600 → 4800 changed nothing, as predicted.
- **Command protocol.** Tried Radwag (`SI/S/SU/SUI/PC/UG/OT`), Mettler and
  Sartorius. Also irrelevant while continuous transmission is on — the balance
  should stream unprompted.
- **Flow control.** Off on both sides; verified on the NPort.
- **The NPort itself.** The loopback exonerates it completely.
- **TCP / network / Python.** All verified.

## What is left

Something physical between the balance's TXD pin and the NPort's RXD pin.

## ROOT CAUSE FOUND

`cable_id.py` reports **straight-through for BOTH cables** — the female-to-female
one and the male-to-female one.

A straight-through cable between two DTE devices wires **TXD to TXD** and
**RXD to RXD**. The NPort is DTE. The balance is DTE. So neither cable can carry
a single byte in either direction, no matter how the software is configured.
That accounts for `RxTotalCnt = 0` through every permutation we tried.

An earlier run reported "3-wire" for the F-F cable. That is **superseded**, and
the asymmetry matters: a DSR *rise* cannot be a false positive, because DSR only
rises when far-end pin 6 is wired to NPort pin 6. DSR *failing* to rise is weak
evidence — a bridge that does not quite contact is indistinguishable from a
missing conductor. Trust the positive result.

It also explains why chaining the two cables changed nothing: straight + straight
= straight. Polarity never flipped.

## Fix

A **DB9 female-to-female null-modem (crossover) cable**. One is on order
(Waveshare, 1.5 m). On arrival:

```bash
.venv/bin/python watch_rx.py          # new-Rx should climb
.venv/bin/python radwag_read.py --mode listen
```

## Still worth confirming on the balance

The cable fault is sufficient to explain everything, but it could be masking a
second, independent problem. While waiting for delivery, check:

- `Peripherals → Computer → Continuous transmission` — a real *mode* selected,
  not "none".
- `Printouts → Weighing printout template` — **not empty**. An enabled continuous
  transmission with a blank template sends nothing.

## Also proven since

- Balance socket is **male**; the cable in use is **female-to-female** — correct
  gender pairing.
- That F-F cable **does carry TXD and RXD end to end**: centre-hole + right-hand
  neighbour loopback echoed 31/31 bytes, `RxTotal` 0 → 31.
- An earlier `FAIL` on that same cable was a **pin-counting error**, not a fault.
  Female DB9s are numbered mirrored; pin 3 is the centre hole of the top row.
  See the counting trap in CABLE.md.

## Untested assumptions

- The `cable_id.py` "no handshake lines" verdict is **not trustworthy** — it ran
  before the counting error came to light, so the pin 7/6 bridge was probably on
  pins 9/8. Re-run it using the orientation the passing loopback established.

## Next test, and why it is the right one

Bridge **pin 2 to pin 3** on the cable end that currently plugs into the
balance, and run `moxa_loopback.py`.

This is worth doing before anything else because it answers two questions at
once:

- if it **echoes**, the bridging technique works *and* this cable's data lines
  are intact — which retroactively validates the `cable_id.py` 3-wire verdict,
  and narrows everything to cable polarity
- if it **does not echo**, we cannot trust any bridge result so far, and the
  cable is either broken or not carrying data lines

## Most likely fix

A DB9 **null-modem adapter** inline at the balance end, or a cable Radwag
specifies for PC connection. A straight-through cable between two DTE devices
cannot work no matter how the software is configured.
