# Is this cable straight-through or crossover?

## This rig: female-to-female

Confirmed 2026-08-10 — both ends of the white cable are **female** DB9.

That matters. The NPort's port is male, and Radwag balances are normally male
too. A cable made to join two male ports is, in practice, always sold as a
**null-modem cable** — a female-to-female straight-through exists but is an
oddity. So the cable is *probably already correct*, which moves suspicion onto
the balance.

"Probably" is not "proven", so run `cable_id.py` (method 1) to settle it.

## Why the loopback test can't answer this

Shorting pin 2 to pin 3 at the far end connects NPort TXD back to NPort RXD
**either way**:

| Cable type | NPort pin 3 (TXD) goes to | NPort pin 2 (RXD) goes to | Short 2-3 at far end |
|---|---|---|---|
| Straight-through | far pin 3 | far pin 2 | loops TXD→RXD ✓ |
| Crossover (null modem) | far pin 2 | far pin 3 | loops TXD→RXD ✓ |

Both pass. Test B proves the conductors are intact, nothing more.

## The counting trap (read this before bridging anything)

Female connectors are numbered **mirrored** relative to male ones. Counting the
top row left-to-right instead of right-to-left does not give you pins 2 and 3 —
it gives you pins **4 and 3** (DTR and TXD, two NPort *outputs*). Bridging two
outputs echoes nothing, which looks exactly like a dead cable.

So a failed 2-3 loopback on a female end has two explanations, and you cannot
tell them apart from software.

**Use this instead of counting.** The top row has five holes, so **pin 3 is
always the centre hole of that row** — it is the third from either end, so the
mirroring cannot catch you out. Pin 2 is one of its two neighbours:

1. Bridge the **centre hole of the top row to its RIGHT-hand neighbour**.
   That is pins 3 and 2 — the correct pair.
2. If that fails, bridge the **centre hole to its LEFT-hand neighbour**.
   That is pins 3 and 4, which is what you get if the mirroring caught you out
   — and it proves nothing, because both are NPort outputs.

If **neither** echoes, the cable genuinely does not carry both data lines.

Orient the connector with the **wider edge of the D-shape upward**; the row of
five is on that wider side. Look for tiny moulded `1` and `5` digits at the ends
of that row — if you can read them, trust those over any counting rule.

### Once the 2-3 loopback passes, you have a verified reference

A passing centre-hole + right-neighbour loopback proves **pin 1 is at the RIGHT
end of the top row** on this connector. Use that to find the bottom row, which
has only four holes so the centre trick does not apply:

- **pin 6 = rightmost hole of the bottom row** (same side as pin 1)
- **pin 7 = second from the right**

Do not re-derive the orientation from scratch for the bottom row — carry it over
from the test that passed.

## DB9 pin numbering

Look at the connector face. There are tiny moulded digits at the corners —
usually `1`, `5`, `6`, `9`. If you can read them, use those and skip this.

- **Male** (pins), viewed from the front: top row is **1 2 3 4 5 left to right**,
  bottom row is 6 7 8 9 left to right.
- **Female** (sockets), viewed from the front: mirrored, so the top row is
  **1 2 3 4 5 right to left**. Pin 3 is the centre hole of the top row and
  pin 2 is the hole immediately to its right.

Pins 2 and 3 are always in the **top row** (the row of five).

## NPort 5150 serial pinout (DB9 male, DTE)

| Pin | Signal | Direction |
|-----|--------|-----------|
| 1 | DCD | in |
| 2 | RXD | in |
| 3 | TXD | out |
| 4 | DTR | out |
| 5 | GND | — |
| 6 | DSR | in |
| 7 | RTS | out |
| 8 | CTS | in |
| 9 | RI | in |

## Method 1 — `cable_id.py` (no meter needed)

The NPort asserts **RTS (pin 7)** whenever a TCP client connects — verified on
this unit. That gives us a signal we can switch from software, so an
*asymmetric* short becomes a real test.

Bridge far-end **pin 7 to pin 6** with a U of stripped wire. Both are in the
bottom row of four; on a female face they run 6 7 8 9 **right to left**, so
pin 6 is the rightmost hole and pin 7 its left-hand neighbour. Then:

```bash
.venv/bin/python cable_id.py
```

| Result | Meaning |
|---|---|
| DSR turns ON | **straight-through** — pin 7→7, 6→6. Needs a null-modem adapter. |
| CTS turns ON | **null modem** — handshakes crossed. Cable is correct; fault is the balance. |
| neither moves | 3-wire cable (TXD/RXD/GND only). Fine for this job, but type undetermined — use method 2. |

Close the NPort console tab in your browser first; the 5150 allows only one
web session and the browser will otherwise evict the script's login.

## Method 2 — continuity meter (definitive)

Set the meter to continuity / diode-beep. Probe one end against the other:

| Probe A | Probe B | Beeps ⇒ |
|---|---|---|
| end-1 pin 2 | end-2 pin 2 | **straight-through** |
| end-1 pin 2 | end-2 pin 3 | **crossover** |
| end-1 pin 5 | end-2 pin 5 | ground is through (must beep for both types) |

Confirm with pin 3 as well — it should mirror pin 2. A full null-modem cable
also swaps 7↔8 (RTS/CTS) and 4↔6 (DTR/DSR); a "partial" null modem only
crosses 2↔3 and passes 5, which is all this job needs.

If pin 5 does **not** beep end to end, stop — the cable has no signal ground
and will never work regardless of type.

## Method 3 — connector gender (heuristic, not proof)

The NPort's port is **male**, so the cable end that plugs into it is female.

- **Female on both ends** → almost always a **null-modem/crossover** cable.
  Two DTE devices both have male ports, and that is the cable made to join them.
  *This is what we have.*
- **Male on one end, female on the other** → almost always a **straight-through
  extension** cable, built to extend a port, not to join two DTEs.

## Method 3.5 — chain two cables to flip polarity for free

Polarity **adds** when you put cables in series. With a male-to-female cable and
a female-to-female cable you can reach the balance two different ways:

    NPort(male) --[F-F cable]-- balance(male)                  = polarity(F-F)
    NPort(male) --[M-F cable]--[F-F cable]-- balance(male)     = polarity(M-F) XOR polarity(F-F)

| M-F cable | F-F cable | Chain of both | Useful? |
|---|---|---|---|
| straight | straight | straight | no — same as F-F alone |
| straight | crossover | crossover | no — same as F-F alone |
| **crossover** | straight | **crossover** | **yes — this is the free fix** |
| crossover | crossover | straight | no |

So chaining only helps if the M-F cable is a crossover. It costs nothing to
try, and it is a genuine 50/50 shot at fixing the link with no purchase.

### Testing the M-F cable is easy — its free end is MALE

Plug the M-F cable's **female** end into the NPort, leaving the **male** end
free. Bridging male pins is far easier than female sockets — just lay a wire
across two pins, exactly as worked on the NPort's own port.

Male pin numbering is **not** mirrored: viewed from the front, the top row runs
**1 2 3 4 5 left to right** and the bottom row **6 7 8 9 left to right**. So
pin 6 is the LEFTMOST of the bottom row — the opposite end from a female
connector. The numbers are usually moulded into the plastic; trust those.

Bridge pins 6 and 7 on that male end, then run `cable_id.py`.

## Method 4 — just try it (fastest if no meter)

A DB9 null-modem adapter is a couple of dollars and is the standard fix.

1. Plug the cable straight into the balance. Run `radwag_read.py`.
2. No data? Insert the null-modem adapter at the balance end. Run it again.

One of the two works. Check `RxTotalCnt` on the NPort console
(Monitor → Async) after each attempt — the moment it goes above zero, the
physical layer is solved and everything left is baud rate and command syntax.

## What to rule out at the same time

Zero RX can also be the balance, not the cable. On the Radwag, confirm:

- RS-232 output is **enabled** and the port isn't assigned to a different
  peripheral (menu is usually under *Communication* / *Peripherals* → *RS232*).
- The printer/output device is set to the **RS232 port**, not USB or none.
- Its **baud rate** — note it, and match the NPort to it rather than the reverse.
- You are in the balance's **RS-232 socket**, not an RS-485, USB or Ethernet one.
