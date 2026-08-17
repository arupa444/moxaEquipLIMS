# Printout structure to reproduce

Transcribed from the two thermal-printer receipts. This is the target format for
the `.txt` files.

## Record type 1 — `Weighing` (user presses PRINT)

```
---------------- Weighing ------------------
Date                            17.Aug.2026
Time                               11:07:39
Balance type                          XA 4Y
Balance S/N                          582975
Operator                    MLO823 G Rakesh
INST-ID                       ML/AB-18/0469
Reg No:                                  NA
Current result                   0.01999  g
Current result                 199.9991   g
Date                            17.Aug.2026
Time                               11:15:16
--------------------------------------------

Signature
```

Observations that matter for parsing:

- **Label / value layout**: label left-aligned, value right-aligned, padded with
  spaces. So parsing is `label = line[:N].strip()`, `value = line[N:].strip()`,
  or more robustly split on runs of 2+ spaces.
- **`Date` and `Time` appear TWICE.** The first pair is when the record was
  started, the second pair is when it was closed/printed. In receipt 2 they are
  13:09:32 and 13:12:14 — nearly 3 minutes apart. A parser must not overwrite
  the first with the second; keep them as `start` and `end`.
- **`Current result` appears TWICE** — 0.01999 g then 199.9991 g in receipt 1;
  0.00000 g then 4.00359 g in receipt 2. Reads like tare/first reading then final
  reading. Must be kept as a list, not a single field.
- **`Reg No:`** carries a trailing colon in the label itself, unlike the others.
  Receipt 1 shows `NA`, receipt 2 shows `01195/26/ML`. Per the user this is set
  in **Var 2** on the balance.
- **`INST-ID`** = `ML/AB-18/0469`, same on both receipts.
- **Operator** differs between receipts: `MLO823 G Rakesh`, `MLO710 E Binnu`.
  Format looks like `<operator code> <initial> <name>`.
- **Date format** is `17.Aug.2026` — day.MonthAbbrev.year, NOT ISO. Needs an
  explicit parse; month names are locale-dependent on the balance.
- Trailing `Signature` line plus blank space for a wet signature.

## Record type 2 — `Adjustment: Internal` (calibration)

```
---------- Adjustment: Internal ------------
Date                            17.Aug.2026
Time                               11:07:23
Balance type                          XA 4Y
Balance S/N                          582975
Operator                    MLO823 G Rakesh
--------------------------------------------

Signature
```

Same header block, but **no** INST-ID / Reg No / Current result, and only ONE
Date/Time pair. Per the user this is run about once a day, though not on a fixed
schedule.

## Record separator seen between records

A dotted rule appears between records on the paper roll:

```
............................................
--------------------------------------------
```

Whether those characters actually travel over the wire, or are the printer's own
formatting, is **unverified** — it must be confirmed from a real capture.

## Open questions blocking implementation

1. **Does this output reach the Computer port at all?** On Radwag 4Y the PRINT
   key targets the *Printer* device; our NPort is on the *Computer* device. If
   they are different ports, none of this arrives and no parser can help.
2. **Serial-number mismatch.** These receipts say `Balance S/N 582975`. The
   balance on our MOXA reports `718623` via `SN`, `NB` and `WINFO` alike. Either
   the receipts came from a different physical balance, or "Balance S/N" is a
   user-set template variable rather than the true serial.
3. **Exact byte framing** — line terminators (CR, LF, or CRLF), whether a form
   feed or other control character marks record boundaries, and the true column
   width. Only a raw capture answers this.
