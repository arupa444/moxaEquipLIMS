# RADWAG XA 4Y over LAN -> Central Hub

End-to-end configuration and fault-finding for the direct Ethernet path, with
the Moxa NPort removed from the chain.

Bench facts this document is written against (from the balance's own `WINFO`
reply and the Ethernet menu photo):

| | |
|---|---|
| model | **XA 4Y** (terminal runs on a Raspberry Pi, MAC prefix `B8-27-EB`) |
| firmware | LL1.9 S |
| balance IP | **192.168.1.97** |
| subnet mask | 255.255.255.0 |
| default gateway | **0.0.0.0 — not set** |
| DHCP | No (static) |
| MAC | B8-27-EB-85-6D-EA |

Substitute your own values throughout. Where a step depends on information I
do not have, it is marked **[NEED]**.

---

## 0. The one fact that decides everything

**The Central Hub is a TCP client. It never listens.**

In [balance_server.py:1373](balance_server.py:1373), `_connect()` does
`s.connect((host, port))` and nothing in the file ever calls `listen()`. Every
"gateway" row in the Hub spawns a `Station` thread that *dials out* to
`host:port`, then passively reads whatever arrives on that socket.

Consequences, and they are not negotiable:

- The balance **must be a TCP server** — it listens, the Hub connects. This is
  the RADWAG 4Y factory default (port 4001), so it is also the easy path.
- If the balance is configured as a **TCP client** (dialling out to a PC), the
  Hub will **never** receive a byte, no matter how the network is set up. There
  is no code path for it. Diagnose it with **Listen for inbound** in the Raw
  panel (section 7, stage 3b).
- UDP is not supported by the Hub either. TCP only.

Because the Hub holds that one socket whenever it is running, the Hub itself is
the only place that can watch the traffic without a fight over the slot. All
the diagnostics therefore live in the Hub, on each gateway row's **Raw**
button: the received bytes, a read-only query bar, and an inbound listener for
the TCP-client case. No separate tool, and nothing to stop and restart.

The `BALANCE_HOST=127.0.0.1` / `BALANCE_PORT=8000` in `.env` are the **web UI**,
not the instrument link. Confusing the two is a common false lead.

---

## 1. Data flow when PRINT is pressed

```
   [ XA 4Y balance ]                      [ Central Hub PC ]
   192.168.1.97                           192.168.1.50
   TCP server, port 4001                  balance_server.py, Station thread

   (1) Hub boots, reads its gateway rows from the DB
   (2) Hub  -- TCP SYN 192.168.1.50:eph -> 192.168.1.97:4001 -->  balance
   (3) balance accepts; occupies its ONE connection slot
       Hub marks the row "connected"   <-- you are here today
   (4) operator presses PRINT
   (5) balance renders the *weighing printout template* into text
   (6) balance writes that text to whichever device the *Printer* peripheral
       is assigned to.   <-- THE USUAL POINT OF FAILURE
   (7) if that device is Ethernet/Tcp, bytes go down the open socket from (3)
   (8) Hub's sock.recv() appends to a buffer; after BURST_GAP_SECONDS (1.5 s)
       of silence the buffer is treated as one burst
   (9) split_bursts() cuts it at "Weighing" / "Adjustment" / "Current result"
  (10) kind_of() labels each piece header / weight / footer / adjustment
  (11) header ... weight(s) ... footer  ->  _flush()  ->  outbox -> Supabase
```

Step (3) succeeding is exactly what "the connection appears established" means.
It proves layers 1-4 only. It says **nothing** about whether the balance will
ever choose to write printout text into that socket. Your symptom — connected,
no data — is the signature of a break at step (6).

---

## 2. Balance configuration (XA 4Y, firmware LL1.x)

Menu wording shifts slightly between firmware builds, so read these as "find
the item named roughly this".

### 2.1 Ethernet parameters — `SETUP -> Communication -> Ethernet`

This is the screen in your photo. It is already correct, with one caveat.

| Item | Value | Note |
|---|---|---|
| DHCP | `No` | correct — a fixed IP is required for the Hub to dial it |
| IP address | `192.168.1.97` | must be reserved on the client's DHCP scope |
| Subnet mask | `255.255.255.0` | must match the Hub's mask |
| Default gateway | `0.0.0.0` | **fine only if the Hub is on 192.168.1.x** |
| MAC address | read-only | |

**The gateway caveat.** `0.0.0.0` means the balance can reach *only* its own
/24. If the Hub PC is at, say, 192.168.10.20, the balance can accept the
inbound connection (the switch delivers the SYN) but its reply packets have no
route back, and the session dies or stalls. Either put the Hub on
192.168.1.0/24, or set the balance's default gateway to the real router
(commonly `192.168.1.1`). **[NEED]** the Hub PC's IP, mask and gateway.

After changing anything here the 4Y usually needs a **power cycle**, not just a
menu exit. Do it.

### 2.2 TCP port — `SETUP -> Communication -> Tcp`

| Item | Value |
|---|---|
| Port | **4001** |

This is the port the balance *listens on*. 4001 is the RADWAG default, and it
happens to match the Hub's `MOXA_DEFAULT_PORT=4001`, so the Add-gateway form
needs no change. If your unit shows something else, either change it to 4001 or
enter the actual number in the Hub.

If this submenu is absent on your firmware, the port is fixed at 4001.

### 2.3 Route the PRINT key to Ethernet — `SETUP -> Peripherals -> Printer`

**This is almost certainly your fault.** On RADWAG the port and the *thing that
uses* the port are configured separately — the exact trap already documented for
RS-232 in [RADWAG.md](RADWAG.md). Configuring the Ethernet page does not make
PRINT emit over Ethernet.

```
SETUP -> Peripherals -> Printer -> Port -> Ethernet      (or "Tcp")
```

Options on this menu typically include `RS 232 (1)`, `RS 232 (2)`, `USB`,
`Ethernet` / `Tcp`, `WiFi`, `USB Free Link`, `Pendrive`, `E2R`. If it still
reads `RS 232 (1)` from the Moxa era, PRINT is writing into a dead serial port
and the LAN socket stays silent forever. That is a perfect match for your
symptom.

### 2.4 Confirm the printout template is not empty

```
SETUP -> Printouts -> Weighing printout template
   (on some builds: Peripherals -> Printer -> Printouts)
```

A blank or all-whitespace template produces bytes that the Hub's `is_noise()`
at [balance_server.py:1111](balance_server.py:1111) discards silently. The
template must yield the block documented in
[PRINTOUT_SPEC.md](PRINTOUT_SPEC.md) — `Weighing` rule line, `Balance type`,
`Balance S/N`, `Operator`, `INST-ID`, `Reg No:`, `Current result`, closing
`Date` / `Time`.

Also check `SETUP -> Printouts -> Header` and `Footer`: on the 4Y these are
emitted by *separate* keys, not by PRINT. If the operator's `INST-ID` and
`Reg No` live in the header template and nobody presses the header key, the Hub
receives a weight with no header and logs *"discarded weight (no header yet)"*
([balance_server.py:1607](balance_server.py:1607)). That is a different bug with
the same outward appearance — no records — so always read the gateway status
text before concluding nothing arrived.

### 2.5 Command channel — `SETUP -> Peripherals -> Computer`

Only needed if you want query commands (`SUI`, `WINFO`) to work over LAN:

```
Port                    -> Ethernet   (same 4001 socket)
Continuous transmission -> OFF
Address                 -> default
```

Leave continuous transmission **off** in production: it floods the socket with
unterminated `0.00000 g` tokens which the Hub buffers and `is_noise()` throws
away, and it can prevent the 1.5 s burst gap from ever elapsing — which would
make real printouts never flush. Turn it on only as a proof-of-life test, then
turn it back off.

---

## 3. Client-side network configuration

Ask the client's IT for these and write them down. **[NEED]** all of it.

| Item | Example | Why it matters |
|---|---|---|
| Balance IP | 192.168.1.97 | must be a **DHCP reservation or exclusion**, not a free-pool address, or a printer will eventually take it |
| Hub PC IP | 192.168.1.50 | should be static or reserved; the Hub's outbound source IP must be routable back |
| Mask | 255.255.255.0 | identical on both |
| Gateway | 192.168.1.1 | needed only if the two are on different subnets |
| VLAN | same VLAN for both | an "instrument VLAN" with an ACL is the classic silent killer |
| Switch ports | access ports, 100 Mb full duplex | the 4Y is 100 Mb; a port forced to 1 Gb or half duplex gives a link that pings but corrupts under load |

The clean design is **balance and Hub on the same /24, same VLAN, no router in
between**. Every routed hop is one more ACL that can drop port 4001.

---

## 4. Central Hub configuration

1. Start it: double-click `start-hub.bat`. Open `http://127.0.0.1:8000`.
2. Sign in with `BALANCE_PASSWORD`.
3. **Add equipment / gateway** with:
   - **IP**: `192.168.1.97` (the balance itself — *not* a Moxa address)
   - **Port**: `4001`
   - **Instrument type**: `balance`
   - **Equipment ID**: the LIMS instrument id, e.g. `ML/AB-18/0469`
4. The row's status should turn **Connected** within ~2 s (the UI polls
   `/api/gateways` every second).

5. Click **Raw** on the row to watch the actual bytes arrive. This is the
   primary diagnostic — see stage 3.

Notes specific to this Hub:

- Every gateway row has a **Raw** button. It opens the whole diagnostics panel,
  all of it running over the collector's existing socket — nothing else has to
  connect, which matters because the balance accepts exactly one TCP client:
  - **the received bytes**, last 64 KB, decoded and in hex, refreshing while
    open (`Station._tap()`,
    [balance_server.py:1454](balance_server.py:1454)). Bytes the parser
    *rejects* are visible here and nowhere else.
  - **a query bar** — fifteen read-only RADWAG commands; the reply lands in the
    same panel (stage 3c).
  - **Listen for inbound** — a two-minute listener that detects an instrument
    stuck in TCP-client mode (stage 3b).
- The Hub tries an SNMP name lookup on UDP 161
  ([balance_server.py:1029](balance_server.py:1029)) to auto-name the device. The
  balance will not answer; the Hub falls back to `NPort-192-168-1-97`. Harmless
  — purely cosmetic. Rename the row.
- The Hub **ICMP-pings** the balance after 20 s of silence
  ([balance_server.py:1356](balance_server.py:1356)). Two consecutive failures
  drop and rebuild the socket. If the client's network blocks ICMP between these
  hosts, the Hub will churn the connection every 30 s and can be mid-reconnect
  at the moment PRINT is pressed. **Confirm ICMP is permitted balance <-> Hub.**
- TCP keepalive is on with a 5 s idle probe. On a switch with a short session
  timeout this is what keeps the idle socket alive between weighings.
- `BURST_GAP_SECONDS=1.5` in `.env` — the silence that ends a burst. If the
  balance dribbles the printout slowly (long template, slow rendering), raise it
  to `3.0` rather than debugging phantom split records.
- `BALANCE_CODEPAGE=cp1250` — correct for RADWAG.

---

## 5. What must match on both sides

| Parameter | Balance | Hub | Must match? |
|---|---|---|---|
| Transport | TCP | TCP | yes — no UDP support |
| Role | **server** (listens) | **client** (connects) | yes — opposite roles |
| IP | 192.168.1.97 | dials 192.168.1.97 | yes, exactly |
| Port | Tcp -> Port 4001 | gateway row port 4001 | yes, exactly |
| Subnet / mask | 192.168.1.0/24 | 192.168.1.0/24 | same L2 domain strongly preferred |
| Concurrent clients | **1** | 1 Station thread | only one tool may hold the socket |
| Character encoding | balance code page | `cp1250` | mismatch = mojibake, not silence |
| Line endings | CRLF (typical) | tolerant | no |

---

## 6. Firewall and network causes of "connected but silent"

Because the Hub **dials out**, the usual firewall suspects mostly do not apply.
Work through them in this order:

1. **Windows Firewall inbound on the Hub — NOT a factor** in server mode. The
   printout arrives on an established outbound connection, and stateful
   firewalls always permit the return path. Do not spend an afternoon here.
   It *becomes* the whole problem the moment you switch the balance to
   TCP-client mode — then `python.exe` needs an inbound allow rule on 4001.
2. **Third-party endpoint security** (Sophos, CrowdStrike, Symantec, Trellix) on
   the Hub PC. These do inspect established sockets and will happily hold or
   drop an unrecognised industrial protocol. Test with protection paused for
   five minutes. This is the one that catches people out.
3. **Inter-VLAN ACL or firewall between subnets.** Allows the SYN, drops the
   asymmetric return, or ages the idle session out between weighings. Symptom:
   works for the first minute after connecting, dies when idle.
4. **ICMP blocked** — triggers the Hub's own liveness watchdog into tearing down
   a perfectly good socket (see section 4).
5. **Duplicate IP.** Another host answering for 192.168.1.97 gives a healthy TCP
   connection to the wrong device. Check `arp -a 192.168.1.97` against
   `B8-27-EB-85-6D-EA`. Thirty seconds, and it catches a real class of failure.
6. **Someone else is already connected.** The 4Y holds one client. A forgotten
   PuTTY, Hercules, or a second Hub instance takes the socket and receives the
   printout instead of you. `stop-hub.bat`, close every terminal, retry.
7. **Idle-session timeout on a switch or firewall** — half-open socket, `recv()`
   never errors, the Hub still thinks it is connected. Keepalive plus the ICMP
   watchdog are the mitigations already in the code.

---

## 7. Verification, stage by stage

Run these in order. Stop at the first one that fails; that is your fault
boundary.

### Stage 1 — link and L3

```bash
ping -n 4 192.168.1.97
```

Reply = the balance is on the network and its IP is right. Timeout = wrong IP,
wrong VLAN, dead port, or ICMP filtered.

```bash
arp -a 192.168.1.97
```

The MAC must read `b8-27-eb-85-6d-ea`. Anything else is an IP conflict.

### Stage 2 — is the TCP port open?

```bash
Test-NetConnection 192.168.1.97 -Port 4001
```

`TcpTestSucceeded : True` means the balance is listening. `False` means its TCP
server is not up on 4001 — recheck section 2.2, then power-cycle the balance.

### Stage 3 — does PRINT push bytes? (the decisive test)

Use the Hub's own **Raw** panel. The Hub already holds the only TCP slot the
balance offers, so tapping that socket is strictly better than opening a second
one — nothing has to be stopped, and this works in production, not just at
commissioning.

1. Hub running, gateway row showing **Connected**.
2. Click **Raw** on that row. A panel opens beneath it and refreshes every
   second.
3. **Press PRINT on the balance.**

| What the panel shows | Meaning | Go to |
|---|---|---|
| Decoded text plus hex | balance and network are both fine | stage 5 |
| Stays `(nothing received yet)` | **transport good, balance not emitting** — Printer peripheral not on Ethernet, or empty template. **Most likely outcome for you.** | section 2.3, then 2.4 |
| Mojibake / wrong characters | code page mismatch, not a transport fault | `BALANCE_CODEPAGE` |
| `no live station for that gateway` | the Station thread is not running | stage 4 |

The panel shows the last 64 KB (200 chunks) per gateway, held in memory only —
it is a live view, not a log. Read the framing here to check the template
against [PRINTOUT_SPEC.md](PRINTOUT_SPEC.md): the hex column is where you
confirm CR vs LF vs CRLF.

Implementation: `Station._tap()` at
[balance_server.py:1454](balance_server.py:1454), served by
[`/api/raw`](balance_server.py:2464).

### Stage 3b — is the instrument dialling US? (TCP-client mode)

If the row never reaches **Connected** and stage 2 says the port is closed, the
balance may be configured as a TCP *client*. The collector only ever dials out,
so it can never receive that -- and the row just says `disconnected` with no
hint why.

In the Raw panel, click **Listen for inbound**. The Hub opens a temporary
listener on the gateway's port for two minutes. Press PRINT on the balance.

- **A connection is reported** -> the balance is in TCP-client mode. Switch it
  to server mode: `SETUP -> Communication -> Tcp -> Port 4001`. The panel also
  shows what it sent, which proves the printout template at the same time.
- **Nothing dials in** -> client mode is ruled out. The fault is reachability;
  recheck the IP, mask and VLAN (section 3).

Windows Firewall **does** apply here, because this listener is genuinely
inbound. If it reports no connections and you suspect the firewall:

```bash
netsh advfirewall firewall add rule name="RADWAG diag 4001" dir=in action=allow protocol=TCP localport=4001
```

Delete that rule afterwards -- normal operation does not need it.

### Stage 3c — query the balance directly

The Raw panel's dropdown sends one read-only command down the collector's
existing socket; the reply appears in the panel below, interleaved with the
`--> sent` marker. Requires section 2.5 (Computer -> Port -> Ethernet).

`WINFO` is the best single check -- it returns model, type, MAC and platform
count, proving two-way traffic and confirming you are talking to the balance you
think you are. `SUI` returns the live mass. `WP` dumps the current printout
template, which is the fastest way to settle a section 2.4 dispute.

Only the fifteen read-only commands from [RADWAG.md](RADWAG.md) are offered.
Calibration, tare, zero, door, keypad-lock, continuous-transmission and reboot
commands are refused by a whitelist in the collector (`SAFE_COMMANDS` at
[balance_server.py:1432](balance_server.py:1432)), so no web button can disturb
a validated instrument.

### Stage 4 — is the Hub actually talking to the right target?

The Hub does not listen, so verify the *outbound* session instead. With the Hub
running:

```bash
netstat -ano | findstr "192.168.1.97:4001"
```

Expect one `ESTABLISHED` line, and the PID must be the hub's `python.exe`
(`tasklist /fi "pid eq <PID>"`). No line means the Station thread is not running
— the gateway row is missing, disabled, or has the wrong IP or port.

Confirm the web UI separately:

```bash
netstat -ano | findstr ":8000"
```

That is the UI on 127.0.0.1 only, unrelated to instrument data.

### Stage 5 — did the Hub accept the record?

Read the gateway row's status text in the UI. It is written by `_status()` and
is unusually informative:

| Status text | Meaning |
|---|---|
| `connected` | socket up, nothing received yet |
| `saved weighing: ...` | full record stored |
| `queued (DB offline): ...` | parsed fine, Supabase unreachable — check `outbox\` |
| `discarded weight (no header yet)` | **bytes arrived**; template emits no header block (section 2.4) |
| `discarded session (no weight between header and footer)` | header + footer, no `Current result` line |
| `discarded incomplete session (N blocks)` | a new header arrived before the previous footer |
| `refused: port 4001 busy ...` | another client holds the slot |
| `disconnected` | cannot reach the balance |

Anything starting with `discarded` is **very good news**: the LAN path works and
you are down to a printout-template problem. Open the **Raw** panel to see the
text that was rejected — the status line names the reason, the Raw panel shows
the evidence.

### Stage 6 — packet-level proof, if you still disbelieve everything

```bash
pktmon start --capture --pkt-size 0 --file radwag.etl
```

Press PRINT, then:

```bash
pktmon stop
```

```bash
pktmon etl2txt radwag.etl --out radwag.txt
```

Search for `192.168.1.97`. Data segments from the balance mean it transmitted
and something on the PC ate them (antivirus). Only bare ACKs mean the balance
never sent anything.

Wireshark with filter `ip.addr==192.168.1.97 && tcp.port==4001` is nicer if it
is available.

---

## 8. Troubleshooting procedure, condensed

Run top to bottom. Each row names the section that fixes a failure.

| # | Check | Pass criterion | If it fails |
|---|---|---|---|
| 1 | Balance Ethernet cable, link LED at both ends | LED lit | cable / switch port |
| 2 | `ping 192.168.1.97` | replies | 2.1, 3 |
| 3 | `arp -a` MAC matches `B8-27-EB-85-6D-EA` | matches | IP conflict, 6.5 |
| 4 | `Test-NetConnection ... -Port 4001` | True | 2.2, power-cycle |
| 5 | Hub running, gateway row | `Connected` | 4; if never connects, stage 3b |
| 6 | `netstat` shows ESTABLISHED to :4001 | one line, hub PID | 4, 6.6 |
| 7 | Click **Raw**, press PRINT | bytes appear | **2.3 Printer -> Ethernet**, then 2.4 |
| 8 | Watch the row's status text | `saved weighing:` | 2.4 template, stage-5 table |
| 9 | Record visible in LIMS / Supabase | row present | `outbox\`, Supabase credentials |

**Prediction for your unit:** steps 1-6 already pass — that is what "connection
successful" means — and step 7 will show the Raw panel stuck at
`(nothing received yet)`. The fix is then
`SETUP -> Peripherals -> Printer -> Port -> Ethernet`, followed by a power
cycle. It is the same trap that bit the RS-232 build, moved one layer up.

---

## 9. Information needed to close the remaining gaps

1. Hub PC's **IP, mask, gateway** — to confirm it shares 192.168.1.0/24 with the
   balance, and whether the balance's `0.0.0.0` gateway matters.
2. Whether `SETUP -> Communication -> Tcp` exists on this firmware, and the
   **port number** it shows.
3. The exact list of options under `SETUP -> Peripherals -> Printer -> Port`,
   and which one is currently selected. (A photo, like the Ethernet one.)
4. Whether the client's network has **VLAN separation or ICMP filtering**
   between the balance and the Hub PC.
5. Which **endpoint security product** runs on the Hub PC.
6. What the **Raw** panel shows when PRINT is pressed (stage 3) — that single
   result splits the remaining possibilities in half. A screenshot of the panel
   is ideal, since the hex column settles the framing question too.
