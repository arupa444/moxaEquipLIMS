# Configuring the Radwag XA 4Y to talk over RS-232

Balance on this bench, per its own `WINFO` reply:

| | |
|---|---|
| device name | **XA 4Y** |
| device type | 4Y |
| serial number | 718623 |
| firmware | LL1.9 S |
| MAC address | B8-27-EB-85-6D-EA |
| platforms | 1 |

(An earlier note in this repo guessed "AS R2 PLUS" from a photo. Wrong — the
balance reports XA 4Y. The `B8-27-EB` MAC prefix is Raspberry Pi Foundation, so
the 4Y terminal runs on a Pi.)

## Verified metadata commands

All read-only, all confirmed working on this unit — see `radwag_info.py`.

| Data | Command |
|---|---|
| mass + unit | `SUI` (immediate), `S` / `SU` (wait for stability) |
| tare | `OT` |
| current unit / all units | `UG` / `UI` (16 units) |
| serial number | `SN`, also `NB` |
| firmware version | `RV` |
| device name, type, MAC, platform count | `WINFO` |
| product id | `PID` |
| operating mode / available modes | `OMG` / `OMI` |
| temp x2, humidity, pressure, air density | `GET_AMBIENT` |
| current printout template | `WP` |

### Not obtainable by query

- **Live date/time.** `GET_AMBIENT` carries a `<TIME=...>` field, but it was
  observed **frozen** — unchanged across three reads 40 s apart, with static
  temperature and humidity too. It is a cached snapshot. Timestamp records from
  the host clock instead.
- **Operator / user name.** Nothing in the 98-command `PC` list returns it.

Both come through the **printout template** instead, not through queries.

### Commands NOT to send casually

`IC`/`IC0`/`IC1` (internal calibration), `Z`/`T`/`NT` (zero/tare),
`OD`/`CD`/`ODH`/`OUH`/`OC` (automatic draft-shield doors — this model has them),
`K0`/`K1` (keypad lock), `C0`/`C1` (continuous transmission), `B*` (beeper),
`LOGOUT`, `PSW*`, and any `RBT.*` / `CMP_*` / `MA.*` procedure.

Menu wording shifts a little between firmware versions, so treat the paths
below as "look for something named like this" rather than exact keystrokes.

## The setting that is most likely missing

On Radwag R-series balances the serial port and the *thing that uses* the
serial port are configured **separately**. Setting the baud rate alone does
nothing — you must also tell the balance that its "Computer" (and/or
"Printer") lives on the RS-232 port. Out of the box that assignment is
frequently unset, and the symptom is exactly ours: the balance ignores every
command and never transmits, so the NPort's RxTotalCnt stays at 0.

    SETUP -> Peripherals (or "Devices") -> Computer -> Port -> RS 232 (1)

That is the first thing to check.

## Full checklist

### 1. Port parameters — must match the NPort exactly

    SETUP -> Communication -> RS 232 (1)

| Setting | Value |
|---|---|
| Baud rate | **9600** |
| Data bits | 8 |
| Parity | None |
| Stop bits | 1 |

The NPort is currently 9600 8/N/1, no flow control. If the balance is easier
to leave at some other speed, that is fine — just tell me the number and we
change the NPort to match instead.

### 2. Assign the computer to that port

    SETUP -> Peripherals -> Computer
        Port                    -> RS 232 (1)
        Address                 -> leave default
        Continuous transmission -> Off for now (see below)

### 3. Assign the printer too, if you want the PRINT key to output

    SETUP -> Peripherals -> Printer -> Port -> RS 232 (1)

Without this the PRINT key does nothing on the serial line, which is why
pressing it produced no bytes earlier.

## Fastest proof of life: continuous transmission

This is the best next test, because it removes the command protocol from the
equation entirely — the balance just streams, so nothing depends on us sending
the right string.

    SETUP -> Peripherals -> Computer -> Continuous transmission -> On
    (set Interval to ~1 second if the menu offers one)

Then, on the Mac:

```bash
.venv/bin/python watch_rx.py
```

Watch the **new-Rx** column. The instant it moves off zero, the whole physical
chain is proven — cable, wiring polarity, baud, everything.

Then swap to the parser, which sends nothing in this mode:

```bash
.venv/bin/python radwag_read.py --mode listen
```

Turn continuous transmission back **Off** afterwards if you would rather poll
on demand — `radwag_read.py --mode poll` then asks with `SI` on an interval.

## Which physical socket

The R2 PLUS terminal is a separate unit from the weighing chamber, and some
configurations put RS 232 (1) on the terminal and RS 232 (2) elsewhere. Make
sure the cable is in the socket whose number matches the one you selected in
the menu — an easy mismatch to make.

Also confirm the socket is RS-232 and not the USB or Ethernet port.

## Cable reminder

The NPort's port is male, so the cable end plugging into it must be female.
Which cable you need at the balance end depends on the balance socket's gender:

- balance socket **male** -> use the female-to-female cable
- balance socket **female** -> use the male-to-female cable (female end to the
  NPort, male end to the balance)

See [CABLE.md](CABLE.md) for identifying straight-through vs null-modem.
