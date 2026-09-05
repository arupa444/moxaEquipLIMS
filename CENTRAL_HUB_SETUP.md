# Central Hub — Setup Guide

The **Central Hub** (`balance_server.py`) is the collector service that captures printouts
from **Radwag balances** and **LabIndia pH meters** — either through a **MOXA NPort**
serial‑to‑Ethernet gateway or **directly over the instrument's LAN port** — and writes the
records to **Supabase**, where the LIMS reads them.

It runs as a small local web app on **`http://127.0.0.1:8000`** (Balance / pH Meter / Settings tabs).

---

## 0. Requirements (once per machine)

- **Windows 10 or 11, 64‑bit** (Windows Server 2016+ also works).
- **Python 3.11 x64** — download from <https://www.python.org/downloads/> and tick
  **"Add python.exe to PATH"** during install. *(3.10 is the minimum; 3.11 recommended.)*
- **Network:**
  - The hub PC must reach the **instruments / MOXA** (same LAN/subnet).
  - The hub PC must reach **Supabase** (the self‑hosted API gateway, e.g. `http://10.1.11.98:8000`, or the cloud project).
- The Supabase **database tables must already exist** (apply the migrations — see Step 5).

---

## 1. Download the repository

**Option A — Git (recommended):**
```bash
git clone https://github.com/arupa444/moxaEquipLIMS.git
```
This creates a `moxaEquipLIMS` folder.

**Option B — ZIP (no Git):**
1. Open <https://github.com/arupa444/moxaEquipLIMS>
2. Click the green **`Code`** button → **Download ZIP**.
3. Right‑click the downloaded ZIP → **Extract All…** → choose a location.

Place the folder somewhere permanent, e.g. **`C:\LIMSBalanceHub`** or `C:\Users\<you>\moxaEquipLIMS`.

---

## 2. Start the hub (one click — it sets everything up)

Double‑click **`start-hub.bat`** in the repo folder.

On the **first run** it automatically:
- creates the Python virtual environment (`.venv`),
- installs all required packages (`requirements.txt`),
- starts the hub **hidden in the background**, serving **`http://127.0.0.1:8000`**,
- writes logs to **`hub.out.log`** and **`hub.err.log`**.

On later runs it just starts the hub (packages are installed only when `requirements.txt` changes).

> To stop the hub: double‑click **`stop-hub.bat`**.
> The hub refuses to start a second copy while one is already running.

*(Manual alternative, for a visible console:)*
```bash
.venv\Scripts\python.exe balance_server.py
```

---

## 3. Get the admin token and sign in

The hub is protected by a per‑install **admin token** (no password to set), generated on
first run and saved to **`data\admin_token.txt`**.

1. Read your token:
   ```bash
   type C:\LIMSBalanceHub\data\admin_token.txt
   ```
2. Open **`http://127.0.0.1:8000`** in a browser.
3. Paste the token into **Admin token** → **Sign in**.

Notes:
- The session expires after **20 minutes of inactivity** — just paste the token again.
- To **rotate** the token: delete `data\admin_token.txt` and restart the hub (a new one is generated).
- To pin a fixed token across machines: set the `HUB_ADMIN_TOKEN` environment variable.

---

## 4. (First deployment only) Apply the database migrations

The hub reads/writes Supabase over the REST API and expects the integration tables to exist.
In the **Supabase SQL Editor** (self‑hosted at your API URL, or the cloud project), apply the
migrations that create/extend:

- `moxaServers`, `balance_integration_data`, `ph_meter_data`
- the worksheet‑link and pH set‑merge columns

*(These live in the LIMS repo under `supabase/migrations/…`. If a table is missing, the hub's
Settings page will say so on Save.)*

---

## 5. Configure Supabase (mandatory — nothing is captured until this is done)

In the hub, go to **Settings** and fill in the connection:

**Deployment:**
- **Self‑hosted Supabase (via API URL)** — the usual choice. Connects through the Supabase
  REST API at **`SUPABASE_URL`** (e.g. `http://10.1.11.98:8000`) with the service‑role key.
- **Cloud Supabase** — same, pointed at your `*.supabase.co` project.

**Fields:**
| Field | Value |
|---|---|
| **SUPABASE_URL** | your API gateway URL, e.g. `http://10.1.11.98:8000` |
| **Service role key** | the Supabase service‑role key |
| **Publishable / anon key** | the anon key |
| **Session secret** | any random string, **min 32 chars** |

*(The Postgres host/port/db/user/password fields are only a fallback used when no `SUPABASE_URL`
is set — normally leave them and rely on the URL.)*

Click **Save & connect**. Secrets are stored **encrypted at rest** (Windows DPAPI) in the
git‑ignored `.cred` file; they display only as a **`set`** badge afterward.

---

## 6. Add the equipment (MOXA gateway or direct‑LAN instrument)

On the **Balance** (or **pH Meter**) tab, use **Add equipment**:

| Field | What to enter |
|---|---|
| **IP** | the device's IP — the **MOXA NPort's IP** (e.g. `192.168.127.150`) or the **instrument's own LAN IP** |
| **Port** | the data port — `4001` for a MOXA NPort's serial port 1 (`400X` for port *X*), or the instrument's TCP‑server port |
| **Instrument type** | **Balance** or **pH Meter** |
| **Name of the Device** | leave blank to auto‑fetch the MOXA's server name via SNMP, or type a name |

Requirements for the device side:
- **MOXA NPort:** Operating Settings → the serial port must be **Operation mode = TCP Server**,
  Local TCP Port = `4001`. Serial params match the instrument (Radwag ≈ 9600 8‑N‑1).
- **Direct‑LAN instrument:** it must run in **TCP Server** mode on that port and **route its
  printout to the Ethernet channel** (not to a separate network‑printer address).

The gateway row shows a live **Status** (auto‑refreshes every second):
- **Connected** — link is up.
- **Disconnected — "Not Connected to the Server. Please plug in the Ethernet cable."** — device unreachable.
- **Not ready** — reachable but the port is busy / not in TCP‑Server mode (clears itself; keeps retrying).

The hub auto‑reconnects on cable/power loss — **no need to re‑add the device or restart the MOXA.**

---

## 7. Verify end to end

1. On the balance: print a session — **Header → Weight(s) → Footer**. On the pH meter: print a
   **Calibration/Readings/Verification** set, then a **Sample**.
2. The gateway status detail changes from `idle` → `saved …`.
3. In the **LIMS** (Balance Integration / PH Meter Integration pages), click **Refresh** — the
   record appears under **Department → Instrument ID → Weight / Adjustment** (balance) or
   **Calibration & Verification / Sample** (pH), with Operator, Reg No and auto Sample Name.

---

## 8. Run automatically at boot (optional)

To keep the hub running across reboots, register `start-hub.bat` with **Task Scheduler**:
- Trigger: **At startup** (or **At log on**)
- Action: **Start a program** → the full path to `start-hub.bat`
- Run whether the user is logged on or not.

---

## 9. Troubleshooting

| Symptom | Cause / Fix |
|---|---|
| **"Supabase configuration is required"** | Fill in Settings (Step 5). |
| **Gateway shows "Disconnected"** | Device unreachable. `ping <device IP>` from the hub PC; check cable/link LED, subnet, and that the device IP ≠ the PC's IP. |
| **"Not ready / port 4001 busy"** | Device reachable but not in TCP‑Server mode, or holding a stale session. Set the NPort/instrument to **TCP Server**; it clears on its own (or set NPort **Max Connection = 2**). |
| **"bad host"** when adding | The IP has an invalid character (space/backtick). Re‑type a clean IP like `192.168.1.100`. |
| **Connected but no records after Print** | The instrument's **print output isn't routed to the LAN channel the hub reads** — e.g. Radwag Printer set to a network‑printer address. Point the print at the hub / the server port the hub uses. |
| **Can't reach `http://127.0.0.1:8000`** | The hub isn't running — double‑click `start-hub.bat`; check `hub.err.log`. |
| **See raw bytes a device sends** | Run `python capture_lan.py 9100` on the hub, point the device's print output at the PC's IP:9100, press Print. |

---

## 10. Security notes

- Access is gated by the **admin token** (`data\admin_token.txt`); the dashboard idle‑expires after 20 minutes.
- Supabase secrets are **DPAPI‑encrypted at rest** in `.cred` — never commit `.cred` or the `data\` folder (both are git‑ignored).
- The instrument Ethernet link carries **instrument data only** — it is not used for internet access.
- Removing a gateway requires the **admin token** as confirmation.

---

*Hub URL: `http://127.0.0.1:8000` · Start: `start-hub.bat` · Stop: `stop-hub.bat` · Token: `data\admin_token.txt`*
