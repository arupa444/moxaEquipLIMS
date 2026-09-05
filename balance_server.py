"""LIMS Balance Integration collector -- multi-MOXA capture, FastAPI + Supabase.

    .venv\\Scripts\\python balance_server.py           # Windows
    .venv/bin/python balance_server.py                 # macOS / Linux
    uvicorn balance_server:app --host 127.0.0.1 --port 8000

No local database. Every device and every weighing session is stored directly
in Supabase:

    "moxaServers"              one row per connected MOXA NPort gateway
    balance_integration_data  one row per completed weighing / adjustment,
                              related to "moxaServers" by moxa_id (FK)

Supabase configuration is MANDATORY -- the collector will not capture anything
until it is set (Settings page, or .cred). Two modes are supported:

  * self_hosted -- direct Postgres connection (host/port/db/user/password).
                  The collector creates the two tables itself on first connect.
  * cloud       -- a hosted *.supabase.co project reached over PostgREST
                  (SUPABASE_URL + service-role key + publishable key). PostgREST
                  cannot run DDL, so the tables must be created by applying the
                  migration (pharma-cis-ocr-L4/supabase/migrations/*
                  _moxa_and_balance_integration.sql) to the project first.

Secrets are stored encrypted at rest (Windows DPAPI where available, otherwise
an authenticated HMAC-SHA256 keystream keyed from SESSION_SECRET_CURRENT). MOXA
device passwords are stored ENCRYPTED in Supabase, never in plaintext.

SECURITY
  * binds 127.0.0.1 by default (--host 0.0.0.0 only if you mean it)
  * PBKDF2-SHA256 login password, 200k iterations, per-install random salt
  * random 256-bit session token, HttpOnly + SameSite=Strict cookie, 8h expiry
  * constant-time credential compare; login rate-limited per IP
  * every SQL statement parameterised; every value HTML-escaped on output
  * CSP forbids external-script loading; no third-party assets at all
  * POST endpoints require a CSRF token bound to the session
  * the LIMS front-end reads these tables read-only (column-scoped) over RLS;
    the collector writes them with the service/admin role
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import json
import os
import platform
import re
import secrets
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

# psycopg is only needed for self-hosted (direct Postgres) mode. Import lazily so
# a pure-cloud deployment can run without the driver present.
try:
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row
    from psycopg.types.json import Json
    from psycopg_pool import ConnectionPool
    _HAVE_PSYCOPG = True
except Exception:                                     # pragma: no cover
    _HAVE_PSYCOPG = False

# --------------------------------------------------------------- config ---
# Real environment variables always win; then .cred; then .env. Secret fields
# in .cred may be stored as "dpapi:<b64>" (Windows DPAPI) or "enc:<b64>"
# (portable, keyed from SESSION_SECRET). SESSION_SECRET itself is never "enc:"
# (it cannot encrypt itself); it is plaintext or "dpapi:".

CRED_PATH = os.environ.get("CRED_FILE", ".cred")
ENV_PATH = os.environ.get("ENV_FILE", ".env")
AUTH_STATE = os.environ.get("AUTH_STATE_FILE", ".authstate.json")

# ---- Admin token (replaces the login password; mirrors the Printer hub) ------
# A per-install secret generated on first run and stored in data/admin_token.txt.
# The operator pastes it to sign in -- no password to set or leak.
DATA_DIR = os.environ.get("HUB_DATA_DIR") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data")
try:
    os.makedirs(DATA_DIR, exist_ok=True)
except Exception:
    pass
ADMIN_TOKEN_FILE = os.path.join(DATA_DIR, "admin_token.txt")


def _load_or_create_secret(path: str, env: str | None = None) -> str:
    """Secret resolution: env var -> persisted file -> generate & store on first
    run (secrets.token_urlsafe(24)). Mirrors the Printer hub's admin-token model."""
    if env:
        v = os.environ.get(env, "").strip()
        if v:
            return v
    try:
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as fh:
                tok = fh.read().strip()
            if tok:
                return tok
    except Exception:
        pass
    tok = secrets.token_urlsafe(24)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(tok)
    except Exception:
        pass
    return tok


ADMIN_TOKEN = _load_or_create_secret(ADMIN_TOKEN_FILE, "HUB_ADMIN_TOKEN")


def check_admin_token(tok: str) -> bool:
    return bool(tok) and secrets.compare_digest(str(tok), ADMIN_TOKEN)

SECRET_FIELDS = (
    "SUPABASE_DB_PASSWORD",
    "SUPABASE_SERVICE_ROLE_KEY_CURRENT",
    "SUPABASE_PUBLISHABLE_KEY",
    "SESSION_SECRET_CURRENT",
)

_CFG: dict[str, str] = {}          # resolved (decrypted) config from files
_CFG_RAW: dict[str, str] = {}      # verbatim values as stored in .cred


def _is_windows() -> bool:
    return platform.system() == "Windows"


# ------------------------------------------------------- DPAPI (Windows) ---

def _dpapi(data: bytes, unprotect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    def to_blob(b: bytes) -> BLOB:
        buf = ctypes.create_string_buffer(b, len(b))
        return BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))

    in_blob, out_blob = to_blob(data), BLOB()
    fn = (ctypes.windll.crypt32.CryptUnprotectData if unprotect
          else ctypes.windll.crypt32.CryptProtectData)
    ok = fn(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob))
    if not ok:
        raise OSError("DPAPI operation failed")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)


# ------------------------------------------- portable secret encryption ---
# Used for secrets that must survive being moved between machines -- notably
# MOXA passwords stored in Supabase (a DPAPI blob would be machine-bound and
# useless elsewhere). Authenticated encrypt-then-MAC over an HMAC-SHA256
# keystream, keyed from SESSION_SECRET.

def _master_key() -> bytes:
    sec = get("SESSION_SECRET_CURRENT")
    if not sec or len(sec) < 16:
        raise ValueError("SESSION_SECRET_CURRENT is not set (min 32 chars) in .cred")
    return hashlib.pbkdf2_hmac("sha256", sec.encode(), b"balance-secret", 200_000)


def _keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    out, ctr = b"", 0
    while len(out) < n:
        out += hmac.new(key, nonce + ctr.to_bytes(8, "big"), hashlib.sha256).digest()
        ctr += 1
    return out[:n]


def encrypt_secret(plain: str) -> str:
    if not plain:
        return ""
    key = _master_key()
    nonce = secrets.token_bytes(16)
    data = plain.encode()
    ct = bytes(a ^ b for a, b in zip(data, _keystream(key, nonce, len(data))))
    tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()[:16]
    return base64.b64encode(nonce + ct + tag).decode()


def decrypt_secret(blob: str) -> str:
    if not blob:
        return ""
    key = _master_key()
    raw = base64.b64decode(blob)
    nonce, ct, tag = raw[:16], raw[16:-16], raw[-16:]
    if not hmac.compare_digest(hmac.new(key, nonce + ct, hashlib.sha256).digest()[:16], tag):
        raise ValueError("secret failed integrity check (wrong SESSION_SECRET?)")
    return bytes(a ^ b for a, b in zip(ct, _keystream(key, nonce, len(ct)))).decode()


def fingerprint(plain: str) -> str:
    return hashlib.sha256(plain.encode()).hexdigest()[:12] if plain else ""


def mask(plain: str) -> str:
    if not plain:
        return ""
    return plain[:4] + "…" + plain[-4:] if len(plain) > 12 else "•" * len(plain)


# ----------------------------------------- at-rest protect/unprotect (UI) ---

def protect(plain: str) -> str:
    """Encrypt a secret for storage in .cred. DPAPI on Windows, else keystream."""
    if not plain:
        return ""
    if _is_windows():
        try:
            return "dpapi:" + base64.b64encode(_dpapi(plain.encode(), False)).decode()
        except OSError:
            pass
    return "enc:" + encrypt_secret(plain)


def unprotect(stored: str) -> str:
    if not stored:
        return ""
    if stored.startswith("dpapi:"):
        return _dpapi(base64.b64decode(stored[6:]), True).decode()
    if stored.startswith("enc:"):
        return decrypt_secret(stored[4:])
    return stored          # plaintext (hand-edited)


# --------------------------------------------------------- config loader ---

def _parse_envfile(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return out


def load_config() -> None:
    """Populate _CFG (resolved) and _CFG_RAW (verbatim .cred). Two-pass so that
    SESSION_SECRET is available before other 'enc:' fields are decrypted."""
    global _CFG, _CFG_RAW
    env = _parse_envfile(ENV_PATH)
    cred = _parse_envfile(CRED_PATH)
    _CFG_RAW = dict(cred)
    merged = {**env, **cred}          # .cred wins over .env

    # Pass 1: SESSION_SECRET (needed to decrypt the rest).
    raw_sec = merged.get("SESSION_SECRET_CURRENT", "")
    sec = unprotect(raw_sec) if raw_sec.startswith("dpapi:") else raw_sec
    resolved = {**merged, "SESSION_SECRET_CURRENT": sec}

    # Pass 2: the remaining secret fields. Temporarily expose SESSION_SECRET so
    # decrypt_secret() can key off it.
    prev = os.environ.get("SESSION_SECRET_CURRENT")
    if sec:
        os.environ["SESSION_SECRET_CURRENT"] = sec
    try:
        for k in SECRET_FIELDS:
            if k == "SESSION_SECRET_CURRENT":
                continue
            v = merged.get(k, "")
            if v.startswith(("dpapi:", "enc:")):
                try:
                    resolved[k] = unprotect(v)
                except Exception:
                    resolved[k] = ""
            else:
                resolved[k] = v
    finally:
        if prev is None:
            os.environ.pop("SESSION_SECRET_CURRENT", None)
        else:
            os.environ["SESSION_SECRET_CURRENT"] = prev

    _CFG = resolved


def get(key: str, default: str = "") -> str:
    v = os.environ.get(key)
    if v not in (None, ""):
        return v
    return _CFG.get(key, default)


def save_cred(updates: dict[str, str]) -> None:
    """Write .cred. Secret fields get protect()ed; blank secret keeps existing.

    Other 'enc:' secrets are keyed from the session secret, so if the session
    secret is being changed in the same save we must encrypt against the NEW
    value. SESSION_SECRET itself cannot self-encrypt via the keystream, so on
    non-Windows it is stored plaintext (DPAPI handles it on Windows)."""
    out = dict(_CFG_RAW)
    eff_sec = updates.get("SESSION_SECRET_CURRENT", "") or get("SESSION_SECRET_CURRENT")
    prev = os.environ.get("SESSION_SECRET_CURRENT")
    if eff_sec:
        os.environ["SESSION_SECRET_CURRENT"] = eff_sec
    try:
        for k, v in updates.items():
            if k in SECRET_FIELDS:
                if v == "":
                    continue                   # keep existing stored value
                if k == "SESSION_SECRET_CURRENT" and not _is_windows():
                    out[k] = v                 # plaintext fallback (cannot self-encrypt)
                else:
                    out[k] = protect(v)
            else:
                out[k] = v
    finally:
        if prev is None:
            os.environ.pop("SESSION_SECRET_CURRENT", None)
        else:
            os.environ["SESSION_SECRET_CURRENT"] = prev
    order = ["SUPABASE_MODE", "SUPABASE_DB_HOST", "SUPABASE_DB_PORT",
             "SUPABASE_DB_NAME", "SUPABASE_DB_USER", "SUPABASE_DB_PASSWORD",
             "SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY_CURRENT",
             "SUPABASE_PUBLISHABLE_KEY", "SESSION_SECRET_CURRENT",
             "BALANCE_PASSWORD", "COLLECTOR_ID", "MOXA_DEFAULT_PORT",
             "BURST_GAP_SECONDS", "BALANCE_CODEPAGE", "BALANCE_HOST", "BALANCE_PORT"]
    lines = ["# .cred -- managed by balance_server.py. Secrets are encrypted",
             "# (dpapi:/enc:). Edit values by hand or via the Settings page.", ""]
    for k in order:
        if k in out:
            lines.append(f"{k}={out[k]}")
    for k, v in out.items():
        if k not in order:
            lines.append(f"{k}={v}")
    with open(CRED_PATH, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    load_config()


# ----------------------------------------------------------- constants ---

load_config()
CODEPAGE = get("BALANCE_CODEPAGE", "cp1250")
# The LabIndia pH meter frames its tables with IBM/OEM box-drawing characters,
# so pH data must be decoded as CP437 (else the borders become AAAA / ł junk).
PH_CODEPAGE = get("PH_CODEPAGE", "cp437")
DEFAULT_PORT = int(get("MOXA_DEFAULT_PORT", "4001") or "4001")
GAP = float(get("BURST_GAP_SECONDS", "1.5") or "1.5")
COLLECTOR_ID = get("COLLECTOR_ID", "collector-01")


def mode() -> str:
    m = (get("SUPABASE_MODE", "self_hosted") or "self_hosted").lower()
    return "cloud" if m == "cloud" else "self_hosted"


def _via_rest() -> bool:
    """True when the data layer should talk to Supabase through the PostgREST API
    at SUPABASE_URL with the service-role key. This is used for BOTH cloud and
    self-hosted Supabase (the self-hosted stack is reached via its API gateway,) -- mirroring the Printer hub. The direct-Postgres
    path is used only when no SUPABASE_URL / service-role key is configured."""
    return bool(get("SUPABASE_URL") and get("SUPABASE_SERVICE_ROLE_KEY_CURRENT"))


def configured() -> bool:
    if not get("SESSION_SECRET_CURRENT"):
        return False
    # REST path (cloud OR self-hosted via the Supabase URL): the URL + keys are
    # all that's needed to reach and write the data.
    if _via_rest():
        return all(get(k) for k in ("SUPABASE_URL",
                                    "SUPABASE_SERVICE_ROLE_KEY_CURRENT",
                                    "SUPABASE_PUBLISHABLE_KEY"))
    # Fallback: direct Postgres (only when no Supabase URL is set).
    if not _HAVE_PSYCOPG:
        return False
    return all(get(k) for k in ("SUPABASE_DB_HOST", "SUPABASE_DB_PORT",
                                "SUPABASE_DB_NAME", "SUPABASE_DB_USER",
                                "SUPABASE_DB_PASSWORD"))


# --------------------------------------------------- data layer (self) ---
# Direct-Postgres path (self_hosted). Only touched when mode()=="self_hosted".

_pool = None
_pool_key: str | None = None
_pool_lock = threading.Lock()


def _conninfo() -> str:
    return make_conninfo(
        host=get("SUPABASE_DB_HOST"),
        port=get("SUPABASE_DB_PORT", "5432"),
        dbname=get("SUPABASE_DB_NAME"),
        user=get("SUPABASE_DB_USER"),
        password=get("SUPABASE_DB_PASSWORD"),
        sslmode=get("SUPABASE_DB_SSLMODE", "prefer"),
        connect_timeout=8,
        application_name="balance-collector",
    )


def pool():
    global _pool, _pool_key
    if not _HAVE_PSYCOPG:
        raise RuntimeError("psycopg is not installed (needed for self-hosted mode)")
    info = _conninfo()
    with _pool_lock:
        if _pool is None or _pool_key != info:
            if _pool is not None:
                try:
                    _pool.close()
                except Exception:
                    pass
            _pool = ConnectionPool(info, min_size=1, max_size=8, timeout=10, open=True)
            _pool_key = info
        return _pool


def reset_pool() -> None:
    global _pool, _pool_key
    with _pool_lock:
        if _pool is not None:
            try:
                _pool.close()
            except Exception:
                pass
        _pool, _pool_key = None, None


def q(sql: str, params: tuple = ()) -> list[dict]:
    with pool().connection() as c, c.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def q1(sql: str, params: tuple = ()) -> dict | None:
    with pool().connection() as c, c.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def ex(sql: str, params: tuple = ()) -> None:
    with pool().connection() as c, c.cursor() as cur:
        cur.execute(sql, params)


DDL = """
CREATE TABLE IF NOT EXISTS public."moxaServers" (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  host          text NOT NULL UNIQUE,
  port          integer NOT NULL DEFAULT 4001,
  name          text,
  instrument_type text NOT NULL DEFAULT 'balance',
  enabled       boolean NOT NULL DEFAULT true,
  status        text DEFAULT 'idle',
  last_seen     timestamptz,
  snmp_community text,
  moxa_password_enc text,
  collector_id  text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public."moxaServers"
  ADD COLUMN IF NOT EXISTS instrument_type text NOT NULL DEFAULT 'balance';
ALTER TABLE public."moxaServers"
  ADD COLUMN IF NOT EXISTS equipment_id text;

CREATE TABLE IF NOT EXISTS public.ph_meter_data (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  moxa_id             uuid NOT NULL REFERENCES public."moxaServers"(id) ON DELETE RESTRICT,
  moxa_name           text NOT NULL,
  moxa_host           text NOT NULL,
  report_type         text NOT NULL,          -- 'calibration' | 'analysis' | 'unknown'
  instrument_id       text,                   -- e.g. ML/PH-06/0476
  instrument_sr_no    text,                   -- e.g. PH18560747
  operator            text,
  printed_at          timestamptz,            -- parsed from the report (may be null)
  is_sample           boolean NOT NULL DEFAULT false,
  registration_numbers text[] NOT NULL DEFAULT '{}',
  rows                jsonb NOT NULL DEFAULT '[]'::jsonb,   -- parsed reading rows
  raw_text            text NOT NULL,          -- merged verbatim printout(s)
  content_hash        text NOT NULL,          -- sha256(raw_text)
  set_key             text,                   -- merge key: one row per calibration set / sample
  member_hashes       text[] NOT NULL DEFAULT '{}',  -- per-print hashes in this row (dedupe)
  bytes               integer NOT NULL DEFAULT 0,
  collector_id        text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (moxa_id, content_hash)
);
ALTER TABLE public.ph_meter_data ADD COLUMN IF NOT EXISTS set_key text;
ALTER TABLE public.ph_meter_data ADD COLUMN IF NOT EXISTS member_hashes text[] NOT NULL DEFAULT '{}';
CREATE UNIQUE INDEX IF NOT EXISTS ux_ph_meter_set_key
  ON public.ph_meter_data (set_key);

-- Raw Data worksheet link (set by the LIMS front-end; mirrors printer_documents).
ALTER TABLE public.balance_integration_data
  ADD COLUMN IF NOT EXISTS raw_data_worksheet_id uuid,
  ADD COLUMN IF NOT EXISTS raw_data_worksheet_name text,
  ADD COLUMN IF NOT EXISTS linking_justification text;
ALTER TABLE public.ph_meter_data
  ADD COLUMN IF NOT EXISTS raw_data_worksheet_id uuid,
  ADD COLUMN IF NOT EXISTS raw_data_worksheet_name text,
  ADD COLUMN IF NOT EXISTS linking_justification text;
GRANT UPDATE (raw_data_worksheet_id, raw_data_worksheet_name, linking_justification)
  ON public.balance_integration_data TO authenticated;
GRANT UPDATE (raw_data_worksheet_id, raw_data_worksheet_name, linking_justification)
  ON public.ph_meter_data TO authenticated;
DROP POLICY IF EXISTS "balance_integration_link_auth" ON public.balance_integration_data;
CREATE POLICY "balance_integration_link_auth" ON public.balance_integration_data
  FOR UPDATE TO authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "ph_meter_link_auth" ON public.ph_meter_data;
CREATE POLICY "ph_meter_link_auth" ON public.ph_meter_data
  FOR UPDATE TO authenticated USING (true) WITH CHECK (true);

CREATE TABLE IF NOT EXISTS public.balance_integration_data (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  moxa_id       uuid NOT NULL REFERENCES public."moxaServers"(id) ON DELETE RESTRICT,
  moxa_name     text NOT NULL,
  moxa_host     text NOT NULL,
  kind          text NOT NULL CHECK (kind IN ('weighing','adjustment')),
  label         text NOT NULL,
  inst_id       text,
  reg_no        text,
  balance_sn    text,
  operator      text,
  started_at    timestamptz,
  finished_at   timestamptz,
  raw_text      text NOT NULL,
  blocks        jsonb NOT NULL DEFAULT '[]'::jsonb,
  bytes         integer NOT NULL DEFAULT 0,
  collector_id  text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (moxa_id, started_at, label)
);

GRANT SELECT (id, host, port, name, instrument_type, equipment_id, enabled, status,
              last_seen, collector_id, created_at, updated_at)
       ON public."moxaServers" TO authenticated;
GRANT SELECT ON public.balance_integration_data TO authenticated;
GRANT SELECT ON public.ph_meter_data TO authenticated;
GRANT ALL ON public."moxaServers" TO service_role;
GRANT ALL ON public.balance_integration_data TO service_role;
GRANT ALL ON public.ph_meter_data TO service_role;

ALTER TABLE public."moxaServers" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.balance_integration_data ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ph_meter_data ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "moxaServers_read_auth" ON public."moxaServers";
CREATE POLICY "moxaServers_read_auth" ON public."moxaServers"
  FOR SELECT TO authenticated USING (true);
DROP POLICY IF EXISTS "balance_integration_read_auth" ON public.balance_integration_data;
CREATE POLICY "balance_integration_read_auth" ON public.balance_integration_data
  FOR SELECT TO authenticated USING (true);
DROP POLICY IF EXISTS "ph_meter_read_auth" ON public.ph_meter_data;
CREATE POLICY "ph_meter_read_auth" ON public.ph_meter_data
  FOR SELECT TO authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_balance_integration_finished
  ON public.balance_integration_data (finished_at DESC);
CREATE INDEX IF NOT EXISTS idx_balance_integration_moxa
  ON public.balance_integration_data (moxa_id);
CREATE INDEX IF NOT EXISTS idx_ph_meter_printed
  ON public.ph_meter_data (printed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ph_meter_moxa
  ON public.ph_meter_data (moxa_id);
"""


# ---------------------------------------------------- data layer (cloud) ---
# PostgREST path (cloud). Uses stdlib urllib -- no extra dependency.

class RestError(RuntimeError):
    pass


def _rest(method: str, path: str, params: dict | None = None,
          body=None, prefer: str | None = None, want_count: bool = False):
    base = get("SUPABASE_URL").rstrip("/") + "/rest/v1/"
    url = base + path
    if params:
        qs = "&".join(
            f"{urllib.parse.quote(str(k))}="
            f"{urllib.parse.quote(str(v), safe=',.*:()=')}"
            for k, v in params.items())
        url += "?" + qs
    key = get("SUPABASE_SERVICE_ROLE_KEY_CURRENT")
    headers = {"apikey": key, "Authorization": f"Bearer {key}",
               "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if prefer:
        headers["Prefer"] = prefer
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            cr = resp.headers.get("Content-Range")
            payload = json.loads(raw) if raw else None
            return (payload, cr) if want_count else payload
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        raise RestError(f"{e.code} {e.reason}: {detail}") from None
    except urllib.error.URLError as e:
        raise RestError(f"cannot reach Supabase: {e.reason}") from None


def _rest_count(table: str, extra: dict | None = None) -> int:
    params = {"select": "id", "limit": "1"}
    if extra:
        params.update(extra)
    _, cr = _rest("GET", table, params, prefer="count=exact", want_count=True)
    if cr and "/" in cr:
        tail = cr.rsplit("/", 1)[-1]
        return int(tail) if tail.isdigit() else 0
    return 0


# ------------------------------------------------ data layer (dispatch) ---

def init_db() -> None:
    """Ensure the schema is present. Self-hosted runs the DDL; cloud verifies the
    tables already exist (they must be created via the migration)."""
    if _via_rest():
        try:
            _rest("GET", "moxaServers", {"select": "id", "limit": "1"})
            _rest("GET", "balance_integration_data", {"select": "id", "limit": "1"})
            _rest("GET", "ph_meter_data", {"select": "id", "limit": "1"})
        except RestError as exc:
            raise RuntimeError(
                "Supabase reachable but a table is missing. Apply the migrations "
                "'*_moxa_and_balance_integration.sql' and "
                f"'*_ph_meter_integration.sql' to this project first. ({exc})")
        return
    with pool().connection() as c, c.cursor() as cur:
        cur.execute(DDL)
        try:
            cur.execute("NOTIFY pgrst, 'reload schema'")
        except Exception:
            pass


def db_list_enabled_moxa() -> list[dict]:
    if _via_rest():
        rows = _rest("GET", "moxaServers",
                     {"select": "id,host,port,name,instrument_type,equipment_id",
                      "enabled": "eq.true"}) or []
        return [{"id": r["id"], "host": r["host"], "port": r["port"],
                 "name": r["name"],
                 "instrument_type": r.get("instrument_type") or "balance",
                 "equipment_id": r.get("equipment_id")}
                for r in rows]
    return q('SELECT id::text AS id, host, port, name, '
             'COALESCE(instrument_type, \'balance\') AS instrument_type, '
             'equipment_id '
             'FROM public."moxaServers" WHERE enabled=true')


def db_list_equipment() -> list[dict]:
    """Equipment choices for the Add-equipment dropdown, from the connected DB's
    `equipment` table (latest revision only). Returns [{equipment_id, name, code}]
    sorted by name."""
    try:
        if _via_rest():
            rows = _rest("GET", "equipment",
                         {"select": "equipment_id,name,code",
                          "is_latest": "eq.true",
                          "order": "name.asc"}) or []
        else:
            rows = q('SELECT equipment_id, name, code '
                     'FROM public.equipment WHERE is_latest=true '
                     'ORDER BY name ASC')
    except Exception:
        return []
    out = []
    for r in rows:
        eid = r.get("equipment_id")
        if not eid:
            continue
        out.append({"equipment_id": eid,
                    "name": r.get("name") or "",
                    "code": r.get("code") or ""})
    return out


def db_set_status(mid: str, status: str) -> None:
    if _via_rest():
        _rest("PATCH", "moxaServers", {"id": f"eq.{mid}"},
              body={"status": status, "last_seen": now_iso(), "updated_at": now_iso()},
              prefer="return=minimal")
    else:
        ex('UPDATE public."moxaServers" SET status=%s, last_seen=%s, '
           'updated_at=now() WHERE id=%s', (status, now_iso(), mid))


def db_touch(mid: str) -> None:
    """Heartbeat: refresh last_seen ONLY (leave the status text untouched). Lets the
    Hub/LIMS tell a live collector from a dead one even when a station is connected
    but idle -- a stale last_seen then means 'not connected to the server'."""
    if _via_rest():
        _rest("PATCH", "moxaServers", {"id": f"eq.{mid}"},
              body={"last_seen": now_iso(), "updated_at": now_iso()},
              prefer="return=minimal")
    else:
        ex('UPDATE public."moxaServers" SET last_seen=%s, updated_at=now() '
           'WHERE id=%s', (now_iso(), mid))


def db_insert_session(row: dict) -> None:
    if _via_rest():
        _rest("POST", "balance_integration_data",
              {"on_conflict": "moxa_id,started_at,label"}, body=row,
              prefer="resolution=ignore-duplicates,return=minimal")
    else:
        ex('INSERT INTO public.balance_integration_data '
           '(moxa_id, moxa_name, moxa_host, kind, label, inst_id, reg_no, '
           ' balance_sn, operator, started_at, finished_at, raw_text, blocks, '
           ' bytes, collector_id) '
           'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) '
           'ON CONFLICT (moxa_id, started_at, label) DO NOTHING',
           (row["moxa_id"], row["moxa_name"], row["moxa_host"], row["kind"],
            row["label"], row["inst_id"], row["reg_no"], row["balance_sn"],
            row["operator"], row["started_at"], row["finished_at"],
            row["raw_text"], Json(row["blocks"]), row["bytes"], row["collector_id"]))


def db_upsert_moxa(host: str, port: int, name: str, pw_enc: str | None,
                   instrument_type: str = "balance",
                   equipment_id: str | None = None) -> None:
    if _via_rest():
        body = {"host": host, "port": port, "name": name,
                "instrument_type": instrument_type,
                "equipment_id": equipment_id, "enabled": True,
                "status": "idle", "collector_id": COLLECTOR_ID, "updated_at": now_iso()}
        if pw_enc is not None:
            body["moxa_password_enc"] = pw_enc
        _rest("POST", "moxaServers", {"on_conflict": "host"}, body=body,
              prefer="resolution=merge-duplicates,return=minimal")
    else:
        ex('INSERT INTO public."moxaServers" (host, port, name, instrument_type, '
           'equipment_id, enabled, status, moxa_password_enc, collector_id) '
           'VALUES (%s,%s,%s,%s,%s,true,\'idle\',%s,%s) '
           'ON CONFLICT (host) DO UPDATE SET port=excluded.port, name=excluded.name, '
           'instrument_type=excluded.instrument_type, '
           'equipment_id=excluded.equipment_id, enabled=true, status=\'idle\', '
           'collector_id=excluded.collector_id, '
           'moxa_password_enc=COALESCE(excluded.moxa_password_enc, '
           'public."moxaServers".moxa_password_enc), updated_at=now()',
           (host, port, name, instrument_type, equipment_id, pw_enc, COLLECTOR_ID))


def db_all_ph_rows() -> list[dict]:
    sel = ("id,moxa_id,moxa_name,moxa_host,report_type,instrument_id,instrument_sr_no,"
           "operator,printed_at,is_sample,registration_numbers,rows,raw_text,"
           "content_hash,set_key,member_hashes,bytes,collector_id")
    if _via_rest():
        return _rest("GET", "ph_meter_data",
                     {"select": sel, "order": "created_at.asc", "limit": "10000"}) or []
    return q(f"SELECT id::text AS id, moxa_id::text AS moxa_id, {sel[sel.index('moxa_name'):]} "
             "FROM public.ph_meter_data ORDER BY created_at ASC")


def db_patch_ph(row_id: str, body: dict) -> None:
    if _via_rest():
        _rest("PATCH", "ph_meter_data", {"id": f"eq.{row_id}"}, body=body,
              prefer="return=minimal")
    else:
        cols = [k for k in body]
        sets = ", ".join(f"{k}=%s" for k in cols)
        vals = [Json(body[k]) if k == "rows" else body[k] for k in cols]
        ex(f"UPDATE public.ph_meter_data SET {sets} WHERE id=%s", (*vals, row_id))


def db_delete_ph(row_id: str) -> None:
    if _via_rest():
        _rest("DELETE", "ph_meter_data", {"id": f"eq.{row_id}"}, prefer="return=minimal")
    else:
        ex("DELETE FROM public.ph_meter_data WHERE id=%s", (row_id,))


def db_get_ph_set(set_key: str) -> dict | None:
    if _via_rest():
        rows = _rest("GET", "ph_meter_data",
                     {"select": "raw_text,rows,registration_numbers,member_hashes,"
                                "printed_at,report_type,operator,instrument_id,"
                                "instrument_sr_no,bytes",
                      "set_key": f"eq.{set_key}", "limit": "1"}) or []
        return rows[0] if rows else None
    return q1("SELECT raw_text, rows, registration_numbers, member_hashes, printed_at, "
              "report_type, operator, instrument_id, instrument_sr_no, bytes "
              "FROM public.ph_meter_data WHERE set_key=%s LIMIT 1", (set_key,))


def db_upsert_ph_set(row: dict) -> None:
    """Insert or replace ONE row per set_key (a calibration set or a sample)."""
    if _via_rest():
        _rest("POST", "ph_meter_data", {"on_conflict": "set_key"}, body=row,
              prefer="resolution=merge-duplicates,return=minimal")
    else:
        ex('INSERT INTO public.ph_meter_data '
           '(moxa_id, moxa_name, moxa_host, report_type, instrument_id, '
           ' instrument_sr_no, operator, printed_at, is_sample, registration_numbers, '
           ' rows, raw_text, content_hash, set_key, member_hashes, bytes, collector_id) '
           'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) '
           'ON CONFLICT (set_key) DO UPDATE SET '
           'report_type=excluded.report_type, operator=excluded.operator, '
           'printed_at=excluded.printed_at, registration_numbers=excluded.registration_numbers, '
           'rows=excluded.rows, raw_text=excluded.raw_text, content_hash=excluded.content_hash, '
           'member_hashes=excluded.member_hashes, bytes=excluded.bytes',
           (row["moxa_id"], row["moxa_name"], row["moxa_host"], row["report_type"],
            row["instrument_id"], row["instrument_sr_no"], row["operator"],
            row["printed_at"], row["is_sample"], row["registration_numbers"],
            Json(row["rows"]), row["raw_text"], row["content_hash"], row["set_key"],
            row["member_hashes"], row["bytes"], row["collector_id"]))


def db_disable_moxa(mid: str) -> None:
    if _via_rest():
        _rest("PATCH", "moxaServers", {"id": f"eq.{mid}"},
              body={"enabled": False, "status": "removed", "updated_at": now_iso()},
              prefer="return=minimal")
    else:
        ex('UPDATE public."moxaServers" SET enabled=false, status=\'removed\', '
           'updated_at=now() WHERE id=%s', (mid,))


def db_moxa_display() -> list[dict]:
    if _via_rest():
        return _rest("GET", "moxaServers",
                     {"select": "id,host,port,name,instrument_type,equipment_id,"
                                "status,last_seen",
                      "enabled": "eq.true", "order": "created_at.asc"}) or []
    return q('SELECT id::text AS id, host, port, name, '
             'COALESCE(instrument_type, \'balance\') AS instrument_type, '
             'equipment_id, status, last_seen '
             'FROM public."moxaServers" WHERE enabled=true ORDER BY created_at')


def db_sessions(limit: int = 200) -> list[dict]:
    if _via_rest():
        return _rest("GET", "balance_integration_data",
                     {"select": "id,moxa_name,moxa_host,kind,label,inst_id,reg_no,"
                                "balance_sn,operator,started_at,finished_at,blocks,bytes",
                      "order": "finished_at.desc.nullslast",
                      "limit": str(limit)}) or []
    return q("SELECT id::text AS id, moxa_name, moxa_host, kind, label, inst_id, "
             "reg_no, balance_sn, operator, started_at, finished_at, blocks, bytes "
             "FROM public.balance_integration_data "
             "ORDER BY finished_at DESC NULLS LAST, created_at DESC LIMIT %s", (limit,))


def db_counts() -> tuple[int, int, int]:
    if _via_rest():
        return (_rest_count("balance_integration_data"),
                _rest_count("balance_integration_data", {"kind": "eq.weighing"}),
                _rest_count("balance_integration_data", {"kind": "eq.adjustment"}))
    tot = q1("SELECT COUNT(*) n FROM public.balance_integration_data")["n"]
    tw = q1("SELECT COUNT(*) n FROM public.balance_integration_data "
            "WHERE kind='weighing'")["n"]
    ta = q1("SELECT COUNT(*) n FROM public.balance_integration_data "
            "WHERE kind='adjustment'")["n"]
    return tot, tw, ta


def db_tip() -> dict:
    if _via_rest():
        count = _rest_count("balance_integration_data")
        latest = _rest("GET", "balance_integration_data",
                       {"select": "created_at", "order": "created_at.desc",
                        "limit": "1"}) or []
        mx = latest[0]["created_at"] if latest else ""
        moxa = _rest("GET", "moxaServers",
                     {"select": "status", "enabled": "eq.true"}) or []
        st = ",".join(str(m.get("status") or "") for m in moxa)
        return {"max_id": mx, "count": count, "status": st}
    r = q1("SELECT COUNT(*) c, COALESCE(MAX(created_at)::text,'') m "
           "FROM public.balance_integration_data")
    st = q1("SELECT COALESCE(string_agg(status, ','), '') s "
            'FROM public."moxaServers" WHERE enabled=true')
    return {"max_id": r["m"], "count": r["c"], "status": st["s"]}


def db_ph_reports(limit: int = 200) -> list[dict]:
    if _via_rest():
        return _rest("GET", "ph_meter_data",
                     {"select": "id,moxa_name,report_type,instrument_id,"
                                "instrument_sr_no,operator,printed_at,is_sample,"
                                "registration_numbers,rows,raw_text,member_hashes,bytes",
                      "order": "printed_at.desc.nullslast",
                      "limit": str(limit)}) or []
    return q("SELECT id::text AS id, moxa_name, report_type, instrument_id, "
             "instrument_sr_no, operator, printed_at, is_sample, "
             "registration_numbers, rows, raw_text, member_hashes, bytes "
             "FROM public.ph_meter_data "
             "ORDER BY printed_at DESC NULLS LAST, created_at DESC LIMIT %s", (limit,))


def db_ph_count() -> int:
    if _via_rest():
        return _rest_count("ph_meter_data")
    return q1("SELECT COUNT(*) n FROM public.ph_meter_data")["n"]


# ----------------------------------------------------------- local auth ---

def _load_authstate() -> dict:
    try:
        with open(AUTH_STATE, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_authstate(d: dict) -> None:
    with open(AUTH_STATE, "w", encoding="utf-8") as fh:
        json.dump(d, fh)


def hash_pw(pw: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)


def ensure_password() -> str | None:
    st = _load_authstate()
    env_pw = get("BALANCE_PASSWORD", "").strip()
    if env_pw:
        salt = secrets.token_bytes(16)
        st["pw_salt"] = salt.hex()
        st["pw_hash"] = hash_pw(env_pw, salt).hex()
        _save_authstate(st)
        return None
    if st.get("pw_salt"):
        return None
    # Default login password when none is configured. Override any time by setting
    # BALANCE_PASSWORD in .cred (re-applied on every startup).
    pw = "Megsan@123"
    salt = secrets.token_bytes(16)
    st["pw_salt"] = salt.hex()
    st["pw_hash"] = hash_pw(pw, salt).hex()
    _save_authstate(st)
    return None


def check_pw(pw: str) -> bool:
    st = _load_authstate()
    if not st.get("pw_salt"):
        return False
    salt = bytes.fromhex(st["pw_salt"])
    want = bytes.fromhex(st["pw_hash"])
    return hmac.compare_digest(hash_pw(pw, salt), want)


SESSIONS: dict[str, dict] = {}
SESS_LOCK = threading.Lock()
FAILS: dict[str, list[float]] = {}


# Sliding idle timeout: a session with no requests for this long expires and the
# operator must paste the admin token again (mirrors the Printer hub's 20-min idle).
SESSION_IDLE_SECONDS = 20 * 60


def new_session() -> str:
    tok = secrets.token_urlsafe(32)
    with SESS_LOCK:
        SESSIONS[tok] = {"last": time.time(), "csrf": secrets.token_urlsafe(24)}
    return tok


def get_session(tok: str | None) -> dict | None:
    if not tok:
        return None
    now = time.time()
    with SESS_LOCK:
        s = SESSIONS.get(tok)
        if not s:
            return None
        if now - s["last"] > SESSION_IDLE_SECONDS:
            SESSIONS.pop(tok, None)         # idle too long -> re-enter the admin token
            return None
        s["last"] = now                     # activity resets the idle timer
        return s


def rate_limited(ip: str) -> bool:
    now = time.time()
    hits = [t for t in FAILS.get(ip, []) if now - t < 300]
    FAILS[ip] = hits
    return len(hits) >= 8


# ------------------------------------------------------------- capture ---
# The session-detection state machine is preserved verbatim from the original
# collector; only the storage sink changed (Supabase, not SQLite/.txt).

def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = bytearray()
    while n:
        b.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(b)]) + bytes(b)


def _tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(val)) + val


def snmp_server_name(host: str, community: str = "public", timeout: float = 2.0) -> str | None:
    """Fetch the MOXA's configured Server name via SNMP v1 (sysName,
    OID 1.3.6.1.2.1.1.5.0) using a raw UDP request -- no external `snmpget`
    binary needed, so it works on Windows. Returns None if SNMP is off,
    unreachable, or the community differs from the default."""
    oid = bytes([0x2b, 6, 1, 2, 1, 1, 5, 0])          # 1.3.6.1.2.1.1.5.0
    oid_tlv = _tlv(0x06, oid)
    varbind = _tlv(0x30, oid_tlv + _tlv(0x05, b""))    # OID + NULL
    pdu = _tlv(0xA0,                                    # GET-REQUEST
               _tlv(0x02, os.urandom(4))               # request-id
               + _tlv(0x02, b"\x00")                   # error-status
               + _tlv(0x02, b"\x00")                   # error-index
               + _tlv(0x30, varbind))                  # varbind list
    msg = _tlv(0x30, _tlv(0x02, b"\x00")               # version = 0 (v1)
               + _tlv(0x04, community.encode())        # community
               + pdu)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, (host, 161))
        data, _ = s.recvfrom(2048)
    except Exception:
        return None
    finally:
        s.close()
    # The response echoes the request OID, then carries the value in place of NULL.
    i = data.find(oid_tlv)
    if i < 0:
        return None
    j = i + len(oid_tlv)
    if j + 1 >= len(data):
        return None
    tag = data[j]; j += 1
    ln = data[j]; j += 1
    if ln & 0x80:                                       # long-form length
        nb = ln & 0x7F
        ln = int.from_bytes(data[j:j + nb], "big"); j += nb
    val = data[j:j + ln]
    if tag != 0x04:                                     # expect OCTET STRING
        return None
    name = val.decode("latin-1", "replace").strip().strip('"')
    return name or None


def moxa_name(host: str) -> str:
    try:
        name = snmp_server_name(host)
        if name:
            return name
    except Exception:
        pass
    return f"NPort-{host.replace('.', '-')}"


def kind_of(text: str) -> str:
    if re.search(r"Adjust|Calibrat", text, re.I):
        return "adjustment"
    if re.search(r"INST-ID|Balance S/N|Balance type", text, re.I):
        if not re.search(r"INST-ID", text, re.I) and not re.search(r"Reg No", text, re.I):
            return "adjustment"
        return "header"
    if re.search(r"^\s*Date\b", text, re.M) and re.search(r"^\s*Time\b", text, re.M):
        return "footer"
    return "weight"


SPLIT_AT = re.compile(
    r"(?m)^(?=[-.]*\s*(?:Weighing|Adjustment)\b[^\n]*)|^(?=\s*Current result\b)")


def split_bursts(text: str) -> list[str]:
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
    body = [l.strip() for l in text.splitlines() if l.strip()]
    if not body:
        return True
    for l in body:
        if re.fullmatch(r"[-.\s]*", l):
            continue
        if re.fullmatch(r"(?i)signature", l):
            continue
        return False
    return True


def field(text: str, label: str) -> str:
    m = re.search(rf"^\s*{re.escape(label)}:?\s{{2,}}(\S.*?)\s*$", text, re.M)
    return m.group(1).strip() if m else ""


def operator_of(text: str) -> str:
    """The balance labels the operator differently across templates/brands
    (Radwag prints 'User', others print 'Operator' / 'Operator Name'). Return the
    first one present, ignoring the placeholder 'Signature'."""
    for lbl in ("User", "Operator Name", "Operator"):
        v = field(text, lbl)
        if v and v.lower() != "signature":
            return v
    return ""


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


# ------------------------------------------------- pH meter (LabIndia PICO) ---
# The pH meter prints a whole report per PRINT press (Calibration Report, or an
# Analysis Report of readings/verification). Each report is one record -- no
# header/weight/footer state machine. A sample is identified by a registration
# number in the ID.NO column (e.g. 00803/26/M); calibration/buffer readings have
# a plain serial (1,2,3...) and are not samples.

PH_REG_RE = re.compile(r"\b\d{3,6}/\d{2}/[A-Za-z][A-Za-z0-9]*\b")
PH_DT_RE = re.compile(r"(\d{2}):(\d{2}):(\d{2})\s+(\d{2})/(\d{2})/(\d{4})")
PH_ROW_RE = re.compile(
    r"^\s*(\d+)\s+(\S+)\s+(.+?)\s+([+-]\s*\d+\.\d+)\s+@?\s*(\d+)\s+"
    r"([+-]\s*\d+\.\d+)\s+(\d+\.\d+)\s*$")
PH_CAL_RE = re.compile(r"^\s*(\d+\.\d+)\s+([+-]?\s*\d+\.\d+)\s+(\d+\.\d+)\s*$")


def split_ph_reports(text: str) -> list[str]:
    """Split a burst into individual reports; each begins with an `ID.<id>` line."""
    idx = [m.start() for m in re.finditer(r"(?m)^\s*ID\.[A-Za-z0-9]", text)]
    if len(idx) <= 1:
        return [text] if text.strip() else []
    out = []
    for i, start in enumerate(idx):
        end = idx[i + 1] if i + 1 < len(idx) else len(text)
        seg = text[start:end]
        if seg.strip():
            out.append(seg)
    return out


def _parse_ph_rows(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = PH_ROW_RE.match(line)
        if m:
            no, idno, name, ph, atc, mv, temp = m.groups()
            out.append({"no": no, "id_no": idno, "sample_name": name.strip(),
                        "ph": ph.replace(" ", ""), "atc": atc,
                        "mv": mv.replace(" ", ""), "temp": temp})
    return out


def _parse_ph_cal_rows(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = PH_CAL_RE.match(line)
        if m:
            ph, mv, temp = m.groups()
            out.append({"entered_ph": ph, "mv": mv.replace(" ", ""), "temp": temp})
    summary = {}
    m = re.search(r"Slope of Electrode\s*=\s*([\d.]+)", text)
    if m:
        summary["slope"] = m.group(1)
    m = re.search(r"Offset of Electrode\s*=\s*([+-]?\s*[\d.]+)", text)
    if m:
        summary["offset"] = m.group(1).replace(" ", "")
    if summary:
        out.append({"summary": summary})
    return out


def parse_ph_report(text: str) -> dict:
    if re.search(r"Calibration Report", text, re.I):
        rtype = "calibration"
    elif re.search(r"Analysis Report", text, re.I):
        rtype = "analysis"
    else:
        rtype = "unknown"
    m = re.search(r"ID\.\s*([A-Za-z0-9/._-]+)", text)
    inst_id = m.group(1).strip(".") if m else None
    m = re.search(r"Instrument\s+Sr\.?\s*No\.?\s*[:.]?\s*([A-Za-z0-9]+)", text, re.I)
    sr = m.group(1) if m else None
    printed_at = None
    m = PH_DT_RE.search(text)
    if m:
        hh, mm, ss, dd, mo, yy = m.groups()
        printed_at = f"{yy}-{mo}-{dd}T{hh}:{mm}:{ss}"
    operator = None
    # Anchor to a real "Name:" line (not "Sample Name" in the column header) and
    # stop before "Signature:" so an empty name field is not misread as "Signature".
    m = re.search(r"(?m)^\s*Name\s*[:.]+\s*(.*?)\s*(?:Signature\b.*)?$", text)
    if m:
        cand = re.sub(r"[.:]{2,}", " ", m.group(1)).strip(" .:-")
        if cand and cand.lower() != "signature":
            operator = cand
    regs = sorted(set(PH_REG_RE.findall(text)))
    rows = _parse_ph_rows(text) if rtype != "calibration" else _parse_ph_cal_rows(text)
    ch = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
    return {"report_type": rtype, "instrument_id": inst_id, "instrument_sr_no": sr,
            "operator": operator, "printed_at": printed_at,
            "is_sample": bool(regs), "registration_numbers": regs, "rows": rows,
            "content_hash": ch}


# ------------------------------------------------------------- outbox ---
# Durable local spool so a Supabase/network outage never loses a capture. Every
# capture is written to a JSON file FIRST, then delivered; the file is removed
# only on a confirmed DB write. A background thread retries the backlog until it
# drains. Deliveries are idempotent (balance: ON CONFLICT DO NOTHING; pH: the set
# merge dedups by member hash), so a retry after a partial failure never
# duplicates. The stable grouping day is captured at capture time (`captured_at`)
# so a retry the next day still lands in the right set.

OUTBOX_DIR = get("OUTBOX_DIR", "outbox")
_OUTBOX_LOCK = threading.Lock()


def outbox_count() -> int:
    try:
        return sum(1 for n in os.listdir(OUTBOX_DIR) if n.endswith(".json"))
    except FileNotFoundError:
        return 0


def outbox_write(ev: dict) -> str:
    os.makedirs(OUTBOX_DIR, exist_ok=True)
    path = os.path.join(OUTBOX_DIR, f"{time.time():.6f}_{secrets.token_hex(4)}.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(ev, fh)
    os.replace(tmp, path)              # atomic publish
    return path


def _deliver_balance(ev: dict) -> None:
    db_insert_session(ev["row"])


def _deliver_ph(ev: dict) -> None:
    p, mid = ev["p"], ev["moxa_id"]
    base = {"moxa_id": mid, "moxa_name": ev["moxa_name"], "moxa_host": ev["moxa_host"],
            "instrument_id": p["instrument_id"],
            "instrument_sr_no": p["instrument_sr_no"], "collector_id": COLLECTOR_ID}
    total = int(ev.get("bytes") or 0)
    text = ev["raw_text"]
    if p["is_sample"]:
        key = f"sample|{mid}|{p['content_hash']}"
        db_upsert_ph_set({**base, "report_type": p["report_type"],
            "operator": p["operator"], "printed_at": p["printed_at"], "is_sample": True,
            "registration_numbers": p["registration_numbers"], "rows": p["rows"],
            "raw_text": text, "content_hash": p["content_hash"], "set_key": key,
            "member_hashes": [p["content_hash"]], "bytes": total})
        return
    day = (p["printed_at"] or ev.get("captured_at") or now_iso())[:10]
    key = f"set|{mid}|{p['instrument_id'] or '?'}|{day}"
    cur = db_get_ph_set(key) or {}
    hashes = list(cur.get("member_hashes") or [])
    if p["content_hash"] in hashes:
        return                                          # already merged -> idempotent
    hashes.append(p["content_hash"])
    raw = ((cur.get("raw_text") + "\n\n") if cur.get("raw_text") else "") + text
    rows = list(cur.get("rows") or []) + list(p["rows"])
    regs = sorted(set(cur.get("registration_numbers") or []) | set(p["registration_numbers"]))
    has_cal = (cur.get("report_type") == "calibration") or (p["report_type"] == "calibration")
    db_upsert_ph_set({**base,
        "report_type": "calibration" if has_cal else "analysis",
        "operator": cur.get("operator") or p["operator"],
        "printed_at": cur.get("printed_at") or p["printed_at"],
        "is_sample": False, "registration_numbers": regs, "rows": rows, "raw_text": raw,
        "content_hash": hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest(),
        "set_key": key, "member_hashes": hashes, "bytes": int(cur.get("bytes") or 0) + total})


def deliver(ev: dict) -> None:
    if ev.get("op") == "balance":
        _deliver_balance(ev)
    elif ev.get("op") == "ph":
        _deliver_ph(ev)


def flush_outbox() -> int:
    """Deliver queued captures oldest-first. Returns the remaining count. Stops at
    the first failure (DB likely down) and retries on the next cycle."""
    if not configured():
        return outbox_count()
    if not _OUTBOX_LOCK.acquire(blocking=False):
        return outbox_count()                           # another flush is running
    try:
        try:
            names = sorted(n for n in os.listdir(OUTBOX_DIR) if n.endswith(".json"))
        except FileNotFoundError:
            return 0
        for n in names:
            path = os.path.join(OUTBOX_DIR, n)
            try:
                with open(path, encoding="utf-8") as fh:
                    ev = json.load(fh)
            except (OSError, json.JSONDecodeError):
                continue
            try:
                deliver(ev)
            except Exception:
                break                                   # DB unreachable -> retry later
            try:
                os.remove(path)
            except OSError:
                pass
        return outbox_count()
    finally:
        _OUTBOX_LOCK.release()


def outbox_submit(ev: dict) -> bool:
    """Persist a capture durably, then try to deliver. True if nothing is queued."""
    outbox_write(ev)
    return flush_outbox() == 0


# Liveness-watchdog timings (module-level so tests can tune them).
STATION_RX_IDLE = 20.0        # start pinging after this much silence
STATION_PROBE_EVERY = 10.0    # ping cadence while idle


def _ping_ok(host: str) -> bool:
    """True if the host answers a single ICMP echo. Used as a liveness probe so a
    MOXA that lost power / its Ethernet link is detected even when TCP keepalive
    fails to fire. ICMP does NOT touch the instrument's serial line. If the ping
    tool cannot be run at all, assume reachable (never false-report disconnected)."""
    try:
        if os.name == "nt":
            args = ["ping", "-n", "1", "-w", "1500", host]
        else:
            args = ["ping", "-c", "1", "-W", "2", host]
        r = subprocess.run(args, capture_output=True, timeout=4,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return r.returncode == 0
    except Exception:
        return True


def _connect(host: str, port: int, source_port: int, timeout: float):
    """Open a TCP connection, returning (sock, local_port). On a RECONNECT we bind
    to the SAME local port used before (with SO_REUSEADDR): a MOXA that is still
    holding our previous, now-dead session in its single connection slot then sees
    the same 4-tuple, resets that stale session, and lets us right back in -- instead
    of refusing with 'port 4001 busy with another client' until its own TCP
    alive-check eventually frees the slot. Falls back to an ephemeral port if the
    old one can't be reused, so it never gets stuck."""
    attempts = ([source_port, 0] if source_port else [0])
    last_exc: Exception = OSError("connect failed")
    for sp in attempts:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if sp:
                s.bind(("", sp))
            s.settimeout(timeout)
            s.connect((host, port))
            return s, s.getsockname()[1]
        except OSError as exc:
            last_exc = exc
            try:
                s.close()
            except OSError:
                pass
    raise last_exc


def _enable_keepalive(sock: socket.socket) -> None:
    """Turn on TCP keepalive so a MOXA that loses power or its Ethernet link is
    detected within ~20-30s. A passive reader never notices a half-open TCP
    connection otherwise (recv() just keeps timing out with no error). Keepalive
    probes are EMPTY TCP segments -- they are never forwarded to the instrument's
    serial line, so this cannot disturb the balance."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        return
    if hasattr(socket, "SIO_KEEPALIVE_VALS"):          # Windows
        try:
            # (on/off, idle before first probe = 5s, interval between probes = 2s)
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 5000, 2000))
        except OSError:
            pass
    else:                                              # Linux / macOS (best effort)
        for name, val in (("TCP_KEEPIDLE", 5), ("TCP_KEEPINTVL", 2), ("TCP_KEEPCNT", 4)):
            opt = getattr(socket, name, None)
            if opt is not None:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, opt, val)
                except OSError:
                    pass


class Station(threading.Thread):
    """One MOXA: own socket, own buffer, own session queue -> Supabase."""

    daemon = True

    def __init__(self, mid: str, host: str, port: int, name: str,
                 itype: str = "balance", gap: float = GAP,
                 equipment_id: str | None = None):
        super().__init__(name=f"moxa-{host}")
        self.mid, self.host, self.port, self.name, self.gap = mid, host, port, name, gap
        self.itype = itype or "balance"
        self.equipment_id = equipment_id
        self.codepage = PH_CODEPAGE if self.itype == "ph_meter" else CODEPAGE
        self.stop = threading.Event()

    def _status(self, s: str) -> None:
        try:
            db_set_status(self.mid, s)
        except Exception:
            pass

    def _touch(self) -> None:
        try:
            db_touch(self.mid)
        except Exception:
            pass

    def run(self) -> None:
        sock = None
        buf = bytearray()
        last = 0.0
        next_hb = 0.0                       # next heartbeat (monotonic seconds)
        HB = 10.0                           # heartbeat every 10s while connected
        last_rx = 0.0                       # last time bytes were received (or connect)
        next_probe = 0.0                    # next liveness ping
        ping_fails = 0
        RX_IDLE = STATION_RX_IDLE           # start pinging after this much silence
        PROBE_EVERY = STATION_PROBE_EVERY   # ping cadence while idle
        local_port = 0                      # reuse this src port on reconnect (stale-slot fix)
        blocks: list[tuple[str, str, str]] = []
        meta: dict[str, str] = {}
        while not self.stop.is_set():
            if sock is None:
                try:
                    sock, local_port = _connect(self.host, self.port, local_port, 4)
                    _enable_keepalive(sock)
                    sock.settimeout(0.2)
                    self._status("connected")
                    now_c = time.monotonic()
                    next_hb = now_c + HB
                    last_rx = now_c
                    next_probe = now_c + PROBE_EVERY
                    ping_fails = 0
                except ConnectionRefusedError:
                    # The MOXA answered but refused: either the serial port is not in
                    # TCP Server mode, or (after a cable pull) it is still holding the
                    # OLD/stale session in its single connection slot. Keep retrying
                    # briskly -- it clears once the NPort's TCP alive-check drops the
                    # stale session (or immediately if Max Connection > 1).
                    self._status(f"refused: port {self.port} busy (stale session on the NPort) "
                                 f"or not in TCP Server mode -- retrying")
                    time.sleep(2)
                    continue
                except OSError:
                    # Host unreachable / timeout / no route -> the collector cannot
                    # reach the MOXA (its Ethernet cable is unplugged, or the network
                    # is down). Report a single, unambiguous state the UI maps to
                    # "Not Connected to the Server. Please plug in the Ethernet cable."
                    # Keep retrying so it reconnects on its own the moment the MOXA is
                    # reachable again (no restart needed).
                    self._status("disconnected")
                    time.sleep(2)
                    continue
            # Heartbeat: refresh last_seen while connected (even when idle) so the
            # Hub/LIMS can tell a live collector from a dead one.
            if sock is not None and time.monotonic() >= next_hb:
                self._touch()
                next_hb = time.monotonic() + HB
            # Liveness watchdog: recv() on a half-open socket just times out with no
            # error, so a passive reader can miss a MOXA that lost power / its cable.
            # After some silence, ICMP-ping the device; two consecutive failures mean
            # it is truly gone -> drop the dead socket and reconnect. This guarantees
            # the station never stays stuck "connected" on a dead link (no re-add
            # needed). ICMP never reaches the instrument's serial line.
            now_m = time.monotonic()
            if sock is not None and (now_m - last_rx) > RX_IDLE and now_m >= next_probe:
                next_probe = now_m + PROBE_EVERY
                if _ping_ok(self.host):
                    ping_fails = 0
                else:
                    ping_fails += 1
                    if ping_fails >= 2:
                        self._status("disconnected")
                        try:
                            sock.close()
                        except OSError:
                            pass
                        sock = None
                        ping_fails = 0
                        continue
            try:
                chunk = sock.recv(8192)
                if not chunk:
                    raise ConnectionResetError("closed")
            except socket.timeout:
                chunk = b""
            except OSError:
                self._status("reconnecting")
                try:
                    sock.close()
                except OSError:
                    pass
                sock = None
                time.sleep(2)
                continue

            if chunk:
                buf.extend(chunk)
                last = time.monotonic()
                last_rx = last

            if buf and last and (time.monotonic() - last) > self.gap:
                whole = bytes(buf).decode(self.codepage, errors="replace")
                buf = bytearray()
                if self.itype == "ph_meter":
                    for rep in split_ph_reports(whole):
                        self._ph_capture(rep)
                else:
                    for text in split_bursts(whole):
                        blocks, meta = self._one(text, blocks, meta)
        try:
            if sock:
                sock.close()
        except OSError:
            pass

    def _ph_capture(self, text: str) -> None:
        if is_noise(text):
            return
        p = parse_ph_report(text)
        total = len(text.encode(self.codepage, "replace"))
        # Persist the print to the durable outbox first; the merge into one row
        # per set happens in _deliver_ph (so it survives a DB outage / restart).
        ev = {"op": "ph", "moxa_id": self.mid, "moxa_name": self.name,
              "moxa_host": self.host, "captured_at": now_iso(), "bytes": total,
              "raw_text": text,
              "p": {"report_type": p["report_type"],
                    "instrument_id": p["instrument_id"] or self.equipment_id,
                    "instrument_sr_no": p["instrument_sr_no"], "operator": p["operator"],
                    "printed_at": p["printed_at"], "is_sample": p["is_sample"],
                    "registration_numbers": p["registration_numbers"], "rows": p["rows"],
                    "content_hash": p["content_hash"]}}
        try:
            ok = outbox_submit(ev)
            tag = "SAMPLE" if p["is_sample"] else p["report_type"]
            self._status(f"saved pH {tag}: {p['instrument_id'] or '-'}" if ok
                         else f"queued pH {tag} (DB offline)")
        except Exception as exc:
            self._status(f"pH save failed: {exc}")

    def _one(self, text, blocks, meta):
        if is_noise(text):
            return blocks, meta
        k = kind_of(text)
        stamp = now_iso()
        if k == "adjustment":
            sn = field(text, "Balance S/N") or field(text, "Balance Type")
            self._save("adjustment", f"{self.name}_{sn or 'NA'}_CAL",
                       [("adjustment", stamp, text)],
                       {"balance_sn": sn, "operator": operator_of(text)})
        elif k == "header":
            if blocks:
                self._status(f"discarded incomplete session ({len(blocks)} blocks)")
            blocks = [("header", stamp, text)]
            meta = {"inst_id": field(text, "INST-ID"),
                    "reg_no": field(text, "Reg No"),
                    "balance_sn": field(text, "Balance S/N"),
                    "operator": operator_of(text)}
        elif k == "weight":
            if not blocks:
                self._status("discarded weight (no header yet)")
            else:
                blocks.append(("weight", stamp, text))
        else:
            if not blocks:
                self._status("discarded footer (no header yet)")
            elif not any(x[0] == "weight" for x in blocks):
                self._status("discarded session (no weight between header and footer)")
                blocks, meta = [], {}
            else:
                blocks.append(("footer", stamp, text))
                self._flush(blocks, meta)
                blocks, meta = [], {}
        return blocks, meta

    def _flush(self, blocks: list, meta: dict) -> None:
        if not blocks:
            return
        inst = meta.get("inst_id") or self.equipment_id
        label = f"{self.name}_{inst or 'NA'}_{meta.get('reg_no') or 'NA'}"
        self._save("weighing", label, blocks, meta)

    def _save(self, kind: str, label: str, blocks: list, meta: dict) -> None:
        raw_text = "".join(b[2] for b in blocks)
        total = sum(len(b[2].encode(CODEPAGE, "replace")) for b in blocks)
        payload = [{"seq": i, "kind": b[0], "received": b[1], "body": b[2]}
                   for i, b in enumerate(blocks)]
        row = {"moxa_id": self.mid, "moxa_name": self.name, "moxa_host": self.host,
               "kind": kind, "label": label,
               "inst_id": meta.get("inst_id") or self.equipment_id,
               "reg_no": meta.get("reg_no"), "balance_sn": meta.get("balance_sn"),
               "operator": meta.get("operator"), "started_at": blocks[0][1],
               "finished_at": blocks[-1][1], "raw_text": raw_text,
               "blocks": payload, "bytes": total, "collector_id": COLLECTOR_ID}
        try:
            ok = outbox_submit({"op": "balance", "row": row})
            self._status(f"saved {kind}: {label}" if ok
                         else f"queued (DB offline): {label}")
        except Exception as exc:
            self._status(f"save failed: {exc}")


STATIONS: dict[str, Station] = {}
ST_LOCK = threading.Lock()


def sync_stations() -> None:
    if not configured():
        return
    try:
        rows = db_list_enabled_moxa()
    except Exception:
        return
    with ST_LOCK:
        want = {r["id"]: r for r in rows}
        for mid in list(STATIONS):
            if mid not in want:
                STATIONS.pop(mid).stop.set()
        for mid, r in want.items():
            if mid not in STATIONS or not STATIONS[mid].is_alive():
                st = Station(mid, r["host"], r["port"], r["name"] or r["host"],
                             r.get("instrument_type", "balance"),
                             equipment_id=r.get("equipment_id"))
                STATIONS[mid] = st
                st.start()
            else:
                # live station: refresh the stamping value if it changed (no restart)
                STATIONS[mid].equipment_id = r.get("equipment_id")


# ----------------------------------------------------------------- UI ---

CSS = """
:root{--bg:#f4f7f5;--fg:#111815;--mut:#5a6b63;--line:#d8e2dc;--card:#fff;
--acc:#0f7a52;--acc-soft:rgba(15,122,82,.09);--ok:#0f7a52;--warn:#a4571a;--bad:#b3261e}
:root[data-theme=dark]{--bg:#0e1512;--fg:#e6efea;--mut:#8fa39a;--line:#22302a;
--card:#141d19;--acc:#3ecf8e;--acc-soft:rgba(62,207,142,.13);--ok:#3ecf8e;
--warn:#e0a458;--bad:#f2887f}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 ui-sans-serif,system-ui,-apple-system,sans-serif}
header{display:flex;gap:14px;align-items:center;padding:14px 22px;
background:var(--card);border-bottom:1px solid var(--line)}
h1{font-size:16px;margin:0;font-weight:650;letter-spacing:-.01em}
.wrap{max-width:1180px;margin:0 auto;padding:22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:16px;margin-bottom:18px}
table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.05em;
color:var(--mut);padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
tr.row{cursor:pointer}tr.row:hover td{background:var(--acc-soft)}
.pill{display:inline-block;padding:2px 8px;border-radius:20px;font-size:12px;
font-weight:600;border:1px solid var(--line)}
.k-weighing{color:var(--acc)}.k-adjustment{color:var(--warn)}
.mono{font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}
pre{margin:6px 0 0;padding:11px 13px;background:var(--bg);border:1px solid var(--line);
border-radius:8px;overflow-x:auto;white-space:pre}
.sub{padding:0 10px 14px}
.blk{margin:10px 0}.blk b{font-size:12px;color:var(--mut);text-transform:uppercase;
letter-spacing:.04em}
input,select,button{font:inherit;padding:8px 10px;border:1px solid var(--line);
border-radius:7px;background:var(--card);color:var(--fg)}
button{background:var(--acc);color:#fff;border-color:transparent;cursor:pointer;font-weight:600}
button.ghost{background:transparent;color:var(--fg);border-color:var(--line)}
.mut{color:var(--mut)}.right{margin-left:auto}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:6px}
form.inline{display:flex;gap:9px;flex-wrap:wrap;align-items:center}
.hide{display:none}
tr.row.open td{background:var(--acc-soft);font-weight:550}
tr.row td:first-child::before{content:"\\25B8";display:inline-block;margin-right:8px;
color:var(--mut);transition:transform .12s}
tr.row.open td:first-child::before{transform:rotate(90deg)}
.bar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
.bar input[type=search]{min-width:230px}
kbd{font:11px ui-monospace;border:1px solid var(--line);border-bottom-width:2px;
border-radius:4px;padding:1px 5px;color:var(--mut)}
#toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);
background:var(--fg);color:var(--bg);padding:9px 16px;border-radius:22px;
font-size:13px;font-weight:600;z-index:9;box-shadow:0 6px 24px rgba(0,0,0,.25)}
.copy{float:right;font-size:11px;cursor:pointer;color:var(--acc);font-weight:600}
nav a{color:var(--mut);text-decoration:none;font-weight:600;font-size:14px;padding:6px 2px}
nav a.on{color:var(--fg);border-bottom:2px solid var(--acc)}
.stat{display:flex;gap:26px;flex-wrap:wrap;margin-bottom:4px}
.stat div b{display:block;font-size:22px;letter-spacing:-.02em}
.stat div span{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.05em}
.fp{font:11px ui-monospace;color:var(--mut)}
.badge{font-size:11px;font-weight:700;padding:2px 7px;border-radius:5px;
background:var(--acc-soft);color:var(--ok)}
.req{border-left:3px solid var(--bad);background:rgba(179,38,30,.08);
padding:10px 14px;border-radius:6px;margin-bottom:14px}
label.fld{display:block;font-size:13px;color:var(--mut);margin:12px 0 4px}
.pvwrap{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:80;
display:flex;flex-direction:column}
.pvwrap.hide{display:none}
.pvbar{display:flex;gap:10px;align-items:center;padding:12px 18px;color:#fff}
.pvbar b{font-size:14px;font-weight:650}
.pvscroll{flex:1;overflow:auto;padding:18px;display:flex;justify-content:center}
.pvsheet{background:#fff;color:#000;width:794px;max-width:100%;height:max-content;
padding:30px;box-shadow:0 12px 48px rgba(0,0,0,.5)}
.pvsheet pre{white-space:pre;margin:0;color:#000;
font:12px/1.3 ui-monospace,SFMono-Regular,Consolas,"Courier New",monospace}
"""

LOGIN = """<!doctype html><html data-theme=light><meta charset=utf-8><title>Sign in - LIMS Balance Integration</title>
<meta name=viewport content="width=device-width,initial-scale=1"><style>%s
.mid{min-height:100vh;display:grid;place-items:center}form{width:320px}
</style><div class=mid><form class=card method=post action=/login>
<h1 style=margin-bottom:14px>LIMS Balance Integration</h1>
%s<label class=mut style=font-size:13px>Admin token</label>
<input name=token type=password autofocus required placeholder="paste the admin token" style=width:100%%;margin:6px 0 12px>
<button style=width:100%%>Sign in</button>
<p class=mut style="font-size:11px;margin-top:10px">The admin token is generated on the collector and saved in data/admin_token.txt.</p></form></div>"""


def esc(v) -> str:
    return html.escape("" if v is None else str(v))


def page(body: str, csrf: str, tab: str = "records") -> str:
    nav_r = "on" if tab == "records" else ""
    nav_p = "on" if tab == "ph" else ""
    nav_s = "on" if tab == "settings" else ""
    return f"""<!doctype html><meta charset=utf-8><title>LIMS Instrument Integration</title>
<meta name=viewport content="width=device-width,initial-scale=1"><style>{CSS}</style>
<header><h1>LIMS Instrument Integration</h1>
<nav style=display:flex;gap:16px><a href=/ class="{nav_r}">Balance</a><a href=/ph class="{nav_p}">pH Meter</a><a href=/settings class="{nav_s}">Settings</a></nav><span class=mut id=clock></span><div id=toast class=hide></div>
<button class="ghost right" id=themeBtn title="Toggle theme">&#9681; Theme</button><form method=post action=/logout style=margin-left:10px>
<input type=hidden name=csrf value="{esc(csrf)}">
<button class=ghost>Sign out</button></form></header>
<div class=wrap>{body}</div>
<div id=pvOverlay class="pvwrap hide">
  <div class=pvbar><b>Report preview &mdash; A4</b>
    <span class=mut style=color:#fffc>Click outside or press Esc to close</span></div>
  <div class=pvscroll><div class=pvsheet><pre id=pvBody></pre></div></div>
</div>
<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const setTheme=t=>{{document.documentElement.setAttribute('data-theme',t);
  try{{localStorage.setItem('lims-theme',t)}}catch(e){{}}
  const b=$('#themeBtn'); if(b) b.textContent=(t==='dark'?'◑ Light':'◐ Dark');}};
setTheme(localStorage.getItem('lims-theme')||'light');
$('#themeBtn')?.addEventListener('click',()=>setTheme(
  document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark'));
document.addEventListener('click',e=>{{
  if(e.target.dataset.preview!==undefined){{openPreview(e.target.dataset.preview);return;}}
  const r=e.target.closest('tr.row');
  if(r){{const s=document.getElementById('sub-'+r.dataset.id);
        if(s){{s.classList.toggle('hide'); r.classList.toggle('open');}} return;}}
  if(e.target.id==='expandAll'){{
    const anyHidden=$$('tr.sub-row.hide').length>0;
    $$('tr.sub-row').forEach(s=>s.classList.toggle('hide',!anyHidden));
    $$('tr.row').forEach(r=>r.classList.toggle('open',anyHidden));
    e.target.textContent=anyHidden?'Collapse all':'Expand all';
  }}
  if(e.target.dataset.copy!==undefined){{
    navigator.clipboard.writeText(e.target.closest('.blk').querySelector('pre').textContent);
    toast('Block copied');
  }}
}});
function applyFilter(){{
  const q=($('#q')?.value||'').toLowerCase(), k=$('#kind')?.value||'';
  let n=0;
  $$('tr.row').forEach(r=>{{
    const hit=(!q||r.dataset.search.includes(q))&&(!k||r.dataset.kind===k);
    r.classList.toggle('hide',!hit); if(hit)n++;
    const s=document.getElementById('sub-'+r.dataset.id);
    if(s&&!hit)s.classList.add('hide');
  }});
  $('#count').textContent=n+' shown';
  $('#pauseNote').classList.toggle('hide', !(q||k));
}}
$('#q')?.addEventListener('input',applyFilter);
$('#kind')?.addEventListener('change',applyFilter);
const modeSel=$('#modeSel');
function updMode(){{const m=modeSel.value;
  $$('.grp.pg').forEach(e=>e.style.display=(m==='self_hosted')?'':'none');
  $$('.grp.cloud').forEach(e=>e.style.display=(m==='cloud')?'':'none');}}
if(modeSel){{modeSel.addEventListener('change',updMode); updMode();}}
addEventListener('keydown',e=>{{
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){{e.preventDefault();$('#q')?.focus();}}
  if(e.key==='Escape'&&$('#q')){{$('#q').value='';applyFilter();$('#q').blur();}}
}});
function toast(m){{const t=$('#toast');t.textContent=m;t.classList.remove('hide');
  clearTimeout(t._h);t._h=setTimeout(()=>t.classList.add('hide'),1800);}}
function tick(){{const c=$('#clock');if(c)c.textContent=new Date().toLocaleTimeString();}}
tick();setInterval(tick,1000);
$('#refreshBtn')?.addEventListener('click',()=>location.reload());
// The RECORDS list stays manual-refresh (reloads only on the Refresh button, so
// it never flickers). Only the gateway CONNECTION STATUS is auto-polled below.

// ---- Auto-refresh gateway status every 1s (in place, no page reload) ----
function gwEsc(s){{s=String(s==null?'':s);return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}}
async function pollGateways(){{
  try{{
    const r=await fetch('/api/gateways',{{cache:'no-store'}});
    if(!r.ok) return;
    const j=await r.json();
    (j.gateways||[]).forEach(function(g){{
      const st=document.getElementById('gwstat-'+g.id);
      if(st) st.innerHTML='<span class=dot style=background:'+g.color+'></span><b>'+gwEsc(g.label)+'</b>'+
        (g.detail?'<div class=mut style=font-size:11px>'+gwEsc(g.detail)+'</div>':'');
      const se=document.getElementById('gwseen-'+g.id);
      if(se) se.textContent=g.last_seen;
    }});
  }}catch(e){{}}
}}
setInterval(pollGateways,1000);

// ---- A4 report preview + print (pH tab) ----
function _fit(raw,w){{var L=raw.split('\\n'),m=20;for(var i=0;i<L.length;i++)m=Math.max(m,L[i].length);
  return Math.max(9,Math.min(18,w/(m*0.62)));}}
function openPreview(key){{
  var src=document.getElementById('sub-'+key), pre=src?src.querySelector('pre'):null;
  var raw=pre?pre.textContent:'';
  var b=$('#pvBody'); b.textContent=raw; b.style.fontSize=_fit(raw,734).toFixed(1)+'px';
  $('#pvOverlay').classList.remove('hide');
}}
function closePreview(){{$('#pvOverlay').classList.add('hide');}}
$('#pvClose')?.addEventListener('click',closePreview);
$('#pvOverlay')?.addEventListener('click',e=>{{if(e.target.id==='pvOverlay'||e.target.classList.contains('pvscroll'))closePreview();}});
addEventListener('keydown',e=>{{if(e.key==='Escape')closePreview();}});
$('#pvPrint')?.addEventListener('click',()=>{{
  var raw=$('#pvBody').textContent, f=_fit(raw,(210-16)*3.7795);
  var esc=s=>s.replace(/[&<>]/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;'}}[c]));
  var doc='<!doctype html><meta charset=utf-8><style>@page{{size:A4 portrait;margin:8mm}}html,body{{margin:0}}pre{{white-space:pre;margin:0;font:'+f.toFixed(1)+'px/1.3 ui-monospace,Consolas,monospace}}</style><pre>'+esc(raw)+'</pre>';
  var ifr=document.createElement('iframe'); ifr.style.cssText='position:fixed;right:0;bottom:0;width:0;height:0;border:0';
  document.body.appendChild(ifr); var d=ifr.contentWindow.document; d.open(); d.write(doc); d.close();
  var w=ifr.contentWindow; w.onafterprint=()=>setTimeout(()=>ifr.remove(),500); setTimeout(()=>{{w.focus();w.print();}},250);
}});
</script>"""


# Grace period (seconds) after which a gateway with no fresh heartbeat is treated
# as not connected to the collector. The collector heartbeats every 10s.
STATUS_STALE_SECONDS = 40
GATEWAY_DISCONNECTED_MSG = "Not Connected to the Server. Please plug in the Ethernet cable."


def gateway_view(status: str | None, last_seen) -> tuple[str, str, str]:
    """Map a stored (status, last_seen) to an accurate (label, detail, css_color).

    A collector heartbeats last_seen every ~10s while its link to the MOXA is up,
    so a stale last_seen means the collector is down or its MOXA Ethernet link is
    gone -> always reported as Disconnected, never a stale 'Connected'.
    """
    low = (status or "").strip().lower()
    stale = True
    if last_seen:
        try:
            dt = datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            stale = (datetime.now(timezone.utc) - dt).total_seconds() > STATUS_STALE_SECONDS
        except Exception:
            stale = True
    if stale or low.startswith(("disconnected", "offline", "reconnect", "removed", "error")):
        return "Disconnected", GATEWAY_DISCONNECTED_MSG, "var(--bad)"
    if low.startswith(("refused", "busy")):
        return "Not ready", (status or "").strip(), "var(--warn)"
    if low.startswith(("connected", "saved", "queued", "idle")):
        return "Connected", (status or "").strip(), "var(--ok)"
    return (status or "unknown").strip(), (status or "").strip(), "var(--warn)"


def moxa_card(csrf: str, moxas: list, only_type: str, heading: str,
              default_type: str, equipment: list | None = None) -> str:
    """Gateway table + add-form for one instrument type. Used by both tabs."""
    equipment = equipment or []
    eq_name = {e["equipment_id"]: (e.get("name") or e["equipment_id"])
               for e in equipment}
    shown = [m for m in moxas if (m.get("instrument_type") or "balance") == only_type]
    h = [f"<div class=card><h1>{esc(heading)}</h1><table><tr><th>IP<th>Name of the Device"
         "<th>Equipment<th>Status<th>Last seen<th></tr>"]
    for m in shown:
        label, detail, col = gateway_view(m.get("status"), m.get("last_seen"))
        last = esc(str(m["last_seen"])[:19].replace("T", " ") if m["last_seen"] else "-")
        eid = m.get("equipment_id")
        eq_disp = eq_name.get(eid, eid) if eid else "-"
        h.append(
            f"<tr><td class=mono>{esc(m['host'])}:{m['port']}"
            f"<td>{esc(m['name'])}"
            f"<td>{esc(str(eq_disp))}"
            f"<td id=gwstat-{esc(m['id'])}><span class=dot style=background:{col}></span><b>{esc(label)}</b>"
            f"<div class=mut style=font-size:11px>{esc(detail)}</div>"
            f"<td id=gwseen-{esc(m['id'])} class=mut>{last}"
            f"<td><form class=inline method=post action=/moxa/del>"
            f"<input type=hidden name=csrf value='{esc(csrf)}'>"
            f"<input type=hidden name=id value='{esc(m['id'])}'>"
            f"<input name=password type=password placeholder='admin token' "
            f"size=16 required autocomplete=off>"
            f"<button class=ghost>Remove</button></form></tr>")
    bal_sel = "selected" if default_type == "balance" else ""
    ph_sel = "selected" if default_type == "ph_meter" else ""
    eq_opts = ["<option value=''>Equipment (from LIMS)</option>"]
    for e in equipment:
        lbl = e.get("name") or e["equipment_id"]
        code = e.get("code")
        if code and code not in lbl:
            lbl = f"{lbl} ({code})"
        eq_opts.append(
            f"<option value='{esc(e['equipment_id'])}'>{esc(str(lbl))}</option>")
    h.append("</table><form class='inline' method=post action=/moxa/add "
             "style=margin-top:14px>"
             f"<input type=hidden name=csrf value='{esc(csrf)}'>"
             "<input name=host placeholder='IP (e.g. 192.168.127.150)' required>"
             "<input name=port value=4001 size=6>"
             "<select name=instrument_type title='Instrument type'>"
             f"<option value=balance {bal_sel}>Balance</option>"
             f"<option value=ph_meter {ph_sel}>pH Meter</option></select>"
             "<select name=equipment_id title='Equipment (Instrument ID from the LIMS)'>"
             f"{''.join(eq_opts)}</select>"
             "<input name=name placeholder='Name of the Device (server name from the MOXA panel)'>"
             "<input name=moxa_password type=password placeholder='device password (stored encrypted)' autocomplete=off>"
             "<button>Add equipment</button></form></div>")
    return "".join(h)


def render(csrf: str) -> str:
    try:
        moxas = db_moxa_display()
        rows = db_sessions(200)
        tot, tw, ta = db_counts()
    except Exception as exc:
        return (f"<div class=card><h1>Database error</h1>"
                f"<p class=mut>Could not reach Supabase: {esc(exc)}</p>"
                f"<p><a href=/settings>Check settings</a></p></div>")

    equipment = db_list_equipment()
    n_bal = sum(1 for m in moxas if (m.get("instrument_type") or "balance") == "balance")
    m_html = [moxa_card(csrf, moxas, "balance",
                        "Balance Equipment / MOXA gateways", "balance",
                        equipment=equipment)]

    queued = outbox_count()
    q_col = "var(--bad)" if queued else "var(--mut)"
    r_html = [f"""<div class=card>
      <div class=stat><div><b>{tot}</b><span>records</span></div>
      <div><b>{tw}</b><span>weighing</span></div>
      <div><b>{ta}</b><span>adjustment</span></div>
      <div><b>{n_bal}</b><span>servers</span></div>
      <div><b style=color:{q_col}>{queued}</b><span>queued (offline)</span></div></div></div>
      <div class=card><div class=bar>
      <input id=q type=search placeholder="Filter label, operator, INST-ID, Reg No...">
      <select id=kind><option value="">All types</option>
      <option value=weighing>Weighing</option>
      <option value=adjustment>Adjustment</option></select>
      <button class=ghost id=expandAll>Expand all</button><button class=ghost id=refreshBtn title="Reload now">&#8635; Refresh</button>
      <span class=mut id=count>{len(rows)} shown</span>
      <span class="mut right"><kbd>/</kbd> search &nbsp;<kbd>Esc</kbd> clear</span>
      </div>
      <div id=pauseNote class="mut hide" style=margin-bottom:8px>
      Auto-refresh paused while filtering.</div>
      <div id=newNote class=hide style="margin-bottom:8px">
      <span class=badge>New records captured</span>
      <a href=# onclick="location.reload();return false" style=color:var(--acc)>
      &nbsp;Reload to view</a></div>
      <table>
      <tr><th>When<th>Type<th>Label<th>MOXA<th>Operator<th>Blocks<th>Bytes</tr>"""]
    if not rows:
        r_html.append("<tr><td colspan=7 class=mut>No records yet. "
                      "Print a header, weights and a footer on the balance.</tr>")
    for r in rows:
        blocks = r["blocks"] or []
        when = esc(str(r["finished_at"] or "")[:19].replace("T", " "))
        search = " ".join(str(x or "").lower() for x in
                          (r["label"], r["operator"], r["inst_id"],
                           r["reg_no"], r["balance_sn"], r["moxa_name"]))
        r_html.append(
            f"<tr class=row data-id={esc(r['id'])} data-kind={esc(r['kind'])} "
            f"data-search=\"{esc(search)}\"><td class=mono>{when}"
            f"<td><span class='pill k-{esc(r['kind'])}'>{esc(r['kind'])}</span>"
            f"<td class=mono>{esc(r['label'])}<td>{esc(r['moxa_name'])}"
            f"<td>{esc(r['operator'] or '-')}<td>{len(blocks)}"
            f"<td class=mono>{r['bytes']}</tr>")
        sub = [f"<tr id=sub-{esc(r['id'])} class='sub-row hide'><td colspan=7><div class=sub>"]
        if r["inst_id"] or r["reg_no"] or r["balance_sn"]:
            sub.append(f"<div class=mut style=margin:4px 0 10px>INST-ID "
                       f"<b>{esc(r['inst_id'] or '-')}</b> &middot; Reg No "
                       f"<b>{esc(r['reg_no'] or '-')}</b> &middot; Balance S/N "
                       f"<b>{esc(r['balance_sn'] or '-')}</b></div>")
        for b in blocks:
            sub.append(f"<div class=blk><span class=copy data-copy>copy</span>"
                       f"<b>{b.get('seq', 0) + 1}. {esc(b.get('kind'))}</b> "
                       f"<span class=mut>{esc(str(b.get('received', ''))[:19].replace('T', ' '))}"
                       f"</span><pre class=mono>{esc(b.get('body'))}</pre></div>")
        sub.append("</div></tr>")
        r_html.append("".join(sub))
    r_html.append("</table></div>")
    return "".join(m_html) + "".join(r_html)


def _safe_name(s) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", str(s or "")).strip("-")
    return s or "NA"


def ph_file_name(g: dict) -> str:
    """<moxaServerName>_<instrumentID>_<YYYYMMDD-HHMMSS> -- unique per report/set
    even when several devices print at once (mirrors the balance label scheme)."""
    dt = ""
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})",
                  str(g.get("printed_at") or ""))
    if m:
        dt = f"{m.group(1)}{m.group(2)}{m.group(3)}-{m.group(4)}{m.group(5)}{m.group(6)}"
    parts = [_safe_name(g.get("moxa_name")), _safe_name(g.get("instrument_id"))]
    if dt:
        parts.append(dt)
    return "_".join(parts)


def render_ph(csrf: str) -> str:
    """The pH Meter tab -- pH gateways + pH reports."""
    try:
        moxas = db_moxa_display()
    except Exception:
        moxas = []
    g_html = moxa_card(csrf, moxas, "ph_meter", "Equipment / MOXA gateways",
                       "ph_meter", equipment=db_list_equipment())
    try:
        ph_rows = db_ph_reports(200)
        ph_tot = db_ph_count()
    except Exception as exc:
        return (g_html + f"<div class=card><h1>pH Meter reports</h1><p class=mut>"
                f"Could not load pH reports: {esc(exc)}</p>"
                f"<p><a href=/settings>Check settings</a></p></div>")
    # Group non-sample reports (Calibration + Readings + Verification) from the
    # same instrument on the same day into ONE record; samples stay individual.
    sets: dict[str, list] = {}
    samples: list = []
    for r in ph_rows:
        if r.get("is_sample"):
            samples.append(r)
        else:
            day = str(r.get("printed_at") or "")[:10]
            sets.setdefault(f"{r.get('moxa_name')}|{r.get('instrument_id') or '?'}|{day}", []).append(r)

    def _mk(reps, key, is_sample):
        s = sorted(reps, key=lambda x: str(x.get("printed_at") or ""))
        regs = sorted({rn for x in s for rn in (x.get("registration_numbers") or [])})
        op = next((x.get("operator") for x in s
                   if x.get("operator") and str(x.get("operator")).lower() != "signature"), None)
        first = s[0]
        count = sum(len(x.get("member_hashes") or []) for x in s) or len(s)
        return {"key": key, "reports": s, "is_sample": is_sample, "count": count,
                "instrument_id": first.get("instrument_id"),
                "instrument_sr_no": first.get("instrument_sr_no"),
                "moxa_name": first.get("moxa_name"),
                "printed_at": first.get("printed_at"),
                "operator": op, "reg_numbers": regs,
                "has_calibration": any(x.get("report_type") == "calibration" for x in s),
                "raw": "\n\n".join(x.get("raw_text") or "" for x in s),
                "bytes": sum(int(x.get("bytes") or 0) for x in s)}

    groups = [_mk(v, "set|" + k, False) for k, v in sets.items()]
    groups += [_mk([smp], "sample|" + str(smp.get("id")), True) for smp in samples]
    groups.sort(key=lambda g: str(g["printed_at"] or ""), reverse=True)
    ph_samples = sum(1 for g in groups if g["is_sample"])

    queued = outbox_count()
    q_col = "var(--bad)" if queued else "var(--mut)"
    ph_html = [g_html, f"""<div class=card>
      <div class=stat><div><b>{ph_tot}</b><span>pH reports</span></div>
      <div><b>{ph_samples}</b><span>samples (shown)</span></div>
      <div><b>{len(groups)}</b><span>records (shown)</span></div>
      <div><b style=color:{q_col}>{queued}</b><span>queued (offline)</span></div></div></div>
      <div class=card><div class=bar>
      <input id=q type=search placeholder="Filter instrument, operator, registration no...">
      <select id=kind><option value="">All reports</option>
      <option value=calibration>Calibration set</option>
      <option value=sample>Sample</option></select>
      <button class=ghost id=expandAll>Expand all</button>
      <button class=ghost id=refreshBtn title="Reload now">&#8635; Refresh</button>
      <span class=mut id=count>{len(groups)} shown</span>
      <span class="mut right"><kbd>/</kbd> search &nbsp;<kbd>Esc</kbd> clear</span></div>
      <div id=pauseNote class="mut hide" style=margin-bottom:8px>Filtering.</div>
      <table><tr><th>Printed<th>File name<th>Report<th>Instrument<th>Sample<th>Operator<th>Reports<th>Bytes</tr>"""]
    if not groups:
        ph_html.append("<tr><td colspan=8 class=mut>No pH reports yet. Add a pH Meter "
                       "gateway (Instrument type = pH Meter) on the Balance tab and "
                       "press PRINT on the instrument.</tr>")
    for g in groups:
        when = esc(str(g["printed_at"] or "")[:19].replace("T", " "))
        regs = g["reg_numbers"]
        label = "sample" if g["is_sample"] else ("calibration set" if g["has_calibration"] else "analysis")
        dkind = "sample" if g["is_sample"] else ("calibration" if g["has_calibration"] else "analysis")
        fname = ph_file_name(g)
        search = " ".join(str(x or "").lower() for x in
                          (g["instrument_id"], g["operator"], g["instrument_sr_no"],
                           g["moxa_name"], fname, " ".join(regs)))
        sample_cell = (f"<span class=badge style='color:var(--acc)'>"
                       f"{esc(', '.join(regs) or 'sample')}</span>"
                       if g["is_sample"] else "-")
        ph_html.append(
            f"<tr class=row data-id={esc(g['key'])} data-kind={dkind} "
            f"data-search=\"{esc(search)}\"><td class=mono>{when}"
            f"<td class=mono>{esc(fname)}"
            f"<td><span class=pill>{esc(label)}</span>"
            f"<td class=mono>{esc(g['instrument_id'] or '-')}"
            f"<td>{sample_cell}<td>{esc(g['operator'] or '-')}"
            f"<td>{g['count']}<td class=mono>{g['bytes']}</tr>")
        sub = [f"<tr id=sub-{esc(g['key'])} class='sub-row hide'><td colspan=8><div class=sub>"]
        sub.append(f"<div class=mut style=margin:4px 0 10px>Sr. No "
                   f"<b>{esc(g['instrument_sr_no'] or '-')}</b> &middot; MOXA "
                   f"<b>{esc(g['moxa_name'] or '-')}</b> &middot; "
                   f"{g['count']} report(s) merged</div>")
        sub.append(f"<div class=blk><span class=copy data-copy>copy</span>"
                   f"<b>{'Report' if g['is_sample'] else 'Merged report (Calibration + Readings + Verification)'}</b>"
                   f"<pre class=mono>{esc(g['raw'])}</pre></div>")
        sub.append("</div></tr>")
        ph_html.append("".join(sub))
    ph_html.append("</table></div>")
    return "".join(ph_html)


# (key, label, placeholder, is_secret, group)  group in {"pg","cloud","common"}
SUPA_FIELDS = [
    ("SUPABASE_DB_HOST", "Postgres host", "10.1.11.98", False, "pg"),
    ("SUPABASE_DB_PORT", "Postgres port", "5433", False, "pg"),
    ("SUPABASE_DB_NAME", "Database name", "lims_restore", False, "pg"),
    ("SUPABASE_DB_USER", "Username", "supabase_admin", False, "pg"),
    ("SUPABASE_DB_PASSWORD", "Password", "", True, "pg"),
    ("SUPABASE_URL", "SUPABASE_URL", "https://xxxx.supabase.co", False, "common"),
    ("SUPABASE_SERVICE_ROLE_KEY_CURRENT", "Service role key", "", True, "common"),
    ("SUPABASE_PUBLISHABLE_KEY", "Publishable / anon key", "", True, "common"),
    ("SESSION_SECRET_CURRENT", "Session secret (min 32 chars)", "", True, "common"),
]


def render_settings(csrf: str, msg: str = "", bad: bool = False) -> str:
    cur_mode = mode()
    out = ["<div class=card><h1>Supabase connection</h1>"]
    if not configured():
        out.append("<div class=req><b>Supabase configuration is required.</b> "
                   "The collector will not capture or store any weighing sessions "
                   "until this is completed.</div>")
    if msg:
        color = "var(--bad)" if bad else "var(--ok)"
        out.append(f"<div class=badge style='margin-bottom:10px;color:{color}'>{esc(msg)}</div>")

    out.append(f"<form method=post action=/settings autocomplete=off>"
               f"<input type=hidden name=csrf value='{esc(csrf)}'>")
    # Mode selector.
    sh = "selected" if cur_mode == "self_hosted" else ""
    cl = "selected" if cur_mode == "cloud" else ""
    out.append(
        "<label class=fld>Deployment</label>"
        "<select name=SUPABASE_MODE id=modeSel style=max-width:520px;width:100%>"
        f"<option value=self_hosted {sh}>Self-hosted Supabase (via API URL)</option>"
        f"<option value=cloud {cl}>Cloud Supabase (*.supabase.co, REST)</option>"
        "</select>"
        "<div class=mut style='font-size:12px;margin-top:6px'>Both modes connect "
        "through the Supabase REST API at <b>SUPABASE_URL</b> with the service-role "
        "key (the self-hosted stack is reached via its API gateway). Create the tables first by applying the "
        "migrations. Direct Postgres (host/port/db/user/password) is used only as "
        "a fallback when no Supabase URL is set.</div>")

    for k, label, ph, is_secret, group in SUPA_FIELDS:
        note = ""
        shown = ""
        input_ph = ph
        if is_secret:
            # A configured secret is shown ONLY as a "set" badge -- never the
            # value, a masked value, or a fingerprint. The field itself is left
            # empty with NO placeholder text (blank on save keeps the stored one).
            if get(k):
                note = "<span class=badge>set</span>"
            input_ph = ""
            # type=text (not password) + a CSS mask keeps the value hidden on
            # screen while ensuring the browser's password manager (Google
            # Passwords etc.) never offers to save or autofill it.
            attrs = ("type=text autocomplete=off autocorrect=off "
                     "autocapitalize=off spellcheck=false data-lpignore=true "
                     "data-1p-ignore data-form-type=other "
                     "style=\"-webkit-text-security:disc;width:100%;max-width:520px\"")
        else:
            shown = get(k)
            attrs = "autocomplete=off style=width:100%;max-width:520px"
        wrap_cls = "grp common" if group == "common" else f"grp {group}"
        out.append(
            f"<div class='{wrap_cls}'><label class=fld>{esc(label)}</label>"
            f"<input name={k} value=\"{esc(shown)}\" placeholder=\"{esc(input_ph)}\" "
            f"{attrs}>"
            f"<div style=margin-top:4px>{note}</div></div>")
    out.append("<div style=margin-top:14px><button>Save &amp; connect</button> "
               "<span class=mut style=margin-left:10px>Secret fields are encrypted "
               "at rest (Windows DPAPI, else keyed from the session secret). Leave a "
               "secret blank to keep the stored value.</span></div></form></div>")

    out.append("<div class=card><h1>Status</h1><table>"
               f"<tr><td>Mode<td class=mono>{esc(cur_mode)}</tr>"
               f"<tr><td>Platform<td class=mono>{esc(platform.system())}</tr>"
               f"<tr><td>Secret at rest<td class=mono>"
               f"{'Windows DPAPI' if _is_windows() else 'HMAC keystream (SESSION_SECRET)'}</tr>"
               f"<tr><td>Collector ID<td class=mono>{esc(COLLECTOR_ID)}</tr>"
               f"<tr><td>Supabase configured<td class=mono>{'yes' if configured() else 'no'}</tr>"
               "</table></div>")
    return "".join(out)


# ------------------------------------------------------------ FastAPI ---

app = FastAPI(title="LIMS Balance Integration")


@app.on_event("startup")
def _startup() -> None:
    if configured():
        try:
            init_db()
        except Exception as exc:
            print(f"  init_db failed: {exc}")
    sync_stations()
    try:
        flush_outbox()                    # drain any backlog from a previous run
    except Exception:
        pass

    def _loop():
        while True:
            time.sleep(20)
            try:
                sync_stations()
            except Exception:
                pass
    threading.Thread(target=_loop, daemon=True).start()

    def _flush_loop():                    # retry queued captures when DB returns
        while True:
            time.sleep(5)
            try:
                flush_outbox()
            except Exception:
                pass
    threading.Thread(target=_flush_loop, daemon=True).start()


SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": ("default-src 'none'; style-src 'unsafe-inline'; "
                               "script-src 'unsafe-inline'; connect-src 'self'; "
                               "form-action 'self'"),
}


@app.middleware("http")
async def _sec(request: Request, call_next):
    resp = await call_next(request)
    for k, v in SEC_HEADERS.items():
        resp.headers.setdefault(k, v)
    return resp


def _sess(request: Request):
    tok = request.cookies.get("sid")
    return tok, get_session(tok)


def _html(body: str, code: int = 200) -> HTMLResponse:
    return HTMLResponse(body, status_code=code)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    msg = ("<p style='color:var(--warn)'>Session expired after 20 min of inactivity — "
           "re-enter the admin token.</p>") if request.query_params.get("expired") else ""
    return _html(LOGIN % (CSS, msg))


@app.post("/login")
async def login(request: Request):
    ip = request.client.host if request.client else "?"
    if rate_limited(ip):
        return _html(LOGIN % (CSS, "<p style=color:var(--bad)>Too many attempts. "
                              "Wait 5 minutes.</p>"), 429)
    form = await request.form()
    if check_admin_token(form.get("token", "")):
        FAILS.pop(ip, None)
        tok = new_session()
        resp = Response(status_code=303, headers={"Location": "/"})
        resp.set_cookie("sid", tok, max_age=28800, httponly=True,
                        samesite="strict", path="/")
        return resp
    FAILS.setdefault(ip, []).append(time.time())
    return _html(LOGIN % (CSS, "<p style=color:var(--bad)>Invalid admin token.</p>"), 401)


@app.get("/", response_class=HTMLResponse)
def records(request: Request):
    tok, s = _sess(request)
    if not s:
        # A present-but-invalid cookie means the 20-min idle session lapsed.
        loc = "/login?expired=1" if tok else "/login"
        return Response(status_code=303, headers={"Location": loc})
    # Supabase configuration is mandatory -- send the user straight to Settings
    # until it is done. Nothing is captured or stored before then.
    if not configured():
        return Response(status_code=303, headers={"Location": "/settings"})
    return _html(page(render(s["csrf"]), s["csrf"]))


@app.get("/ph", response_class=HTMLResponse)
def ph_page(request: Request):
    _, s = _sess(request)
    if not s:
        return Response(status_code=303, headers={"Location": "/login"})
    if not configured():
        return Response(status_code=303, headers={"Location": "/settings"})
    return _html(page(render_ph(s["csrf"]), s["csrf"], "ph"))


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    _, s = _sess(request)
    if not s:
        return Response(status_code=303, headers={"Location": "/login"})
    return _html(page(render_settings(s["csrf"]), s["csrf"], "settings"))


@app.get("/api/gateways")
def api_gateways(request: Request):
    """Lightweight status of every gateway, polled by the dashboard once a second
    so Connected/Disconnected updates in place without reloading the whole page."""
    _, s = _sess(request)
    if not s:
        return JSONResponse({"error": "auth"}, status_code=401)
    try:
        moxas = db_moxa_display()
    except Exception as exc:
        return JSONResponse({"error": str(exc), "gateways": []})
    out = []
    for m in moxas:
        label, detail, col = gateway_view(m.get("status"), m.get("last_seen"))
        last = (str(m["last_seen"])[:19].replace("T", " ") if m.get("last_seen") else "-")
        out.append({"id": m["id"], "label": label, "detail": detail,
                    "color": col, "last_seen": last})
    return JSONResponse({"gateways": out})


@app.get("/api/tip")
def api_tip(request: Request):
    _, s = _sess(request)
    if not s:
        return JSONResponse({"error": "auth"}, status_code=401)
    if not configured():
        return JSONResponse({"max_id": 0, "count": 0, "status": "unconfigured"})
    try:
        return JSONResponse(db_tip())
    except Exception as exc:
        return JSONResponse({"max_id": 0, "count": 0, "status": f"error: {exc}"})


def _csrf_ok(form, s) -> bool:
    return bool(s) and hmac.compare_digest(form.get("csrf", ""), s["csrf"])


@app.post("/logout")
async def logout(request: Request):
    tok, s = _sess(request)
    form = await request.form()
    if not _csrf_ok(form, s):
        return PlainTextResponse("bad csrf", status_code=403)
    with SESS_LOCK:
        SESSIONS.pop(tok, None)
    resp = Response(status_code=303, headers={"Location": "/login"})
    resp.set_cookie("sid", "", max_age=0, httponly=True, path="/")
    return resp


@app.post("/settings")
async def save_settings(request: Request):
    _, s = _sess(request)
    if not s:
        return Response(status_code=303, headers={"Location": "/login"})
    form = await request.form()
    if not _csrf_ok(form, s):
        return PlainTextResponse("bad csrf", status_code=403)
    updates = {k: (form.get(k) or "").strip() for k, *_ in SUPA_FIELDS}
    updates["SUPABASE_MODE"] = "cloud" if (form.get("SUPABASE_MODE") or "") == "cloud" else "self_hosted"
    try:
        save_cred(updates)
    except Exception as exc:
        return _html(page(render_settings(s["csrf"], f"Not saved: {exc}", True),
                          s["csrf"], "settings"))
    global COLLECTOR_ID
    COLLECTOR_ID = get("COLLECTOR_ID", "collector-01")
    reset_pool()
    msg, bad = "Saved.", False
    if configured():
        try:
            init_db()
            sync_stations()
            msg = "Saved. Connected to Supabase and tables are ready."
        except Exception as exc:
            msg, bad = f"Saved, but connection failed: {exc}", True
    else:
        msg, bad = "Saved, but some required fields are still empty.", True
    return _html(page(render_settings(s["csrf"], msg, bad), s["csrf"], "settings"))


@app.post("/moxa/add")
async def moxa_add(request: Request):
    _, s = _sess(request)
    if not s:
        return Response(status_code=303, headers={"Location": "/login"})
    form = await request.form()
    if not _csrf_ok(form, s):
        return PlainTextResponse("bad csrf", status_code=403)
    if not configured():
        return Response(status_code=303, headers={"Location": "/settings"})
    host = (form.get("host") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", host):
        return PlainTextResponse("bad host", status_code=400)
    port = max(1, min(65535, int(form.get("port") or DEFAULT_PORT)))
    name = (form.get("name") or "").strip() or moxa_name(host)
    itype = (form.get("instrument_type") or "balance").strip()
    if itype not in ("balance", "ph_meter"):
        itype = "balance"
    equipment_id = (form.get("equipment_id") or "").strip() or None
    pw = (form.get("moxa_password") or "").strip()
    pw_enc = encrypt_secret(pw) if pw else None
    try:
        db_upsert_moxa(host, port, name, pw_enc, itype, equipment_id)
    except Exception as exc:
        return _html(page(f"<div class=card><h1>Could not add gateway</h1>"
                          f"<p class=mut>{esc(exc)}</p><p><a href=/>Back</a></p></div>",
                          s["csrf"]))
    sync_stations()
    dest = "/ph" if itype == "ph_meter" else "/"
    return Response(status_code=303, headers={"Location": dest})


@app.post("/moxa/del")
async def moxa_del(request: Request):
    _, s = _sess(request)
    if not s:
        return Response(status_code=303, headers={"Location": "/login"})
    form = await request.form()
    if not _csrf_ok(form, s):
        return PlainTextResponse("bad csrf", status_code=403)
    if not check_admin_token(form.get("password", "")):
        return _html(page("<div class=card><h1>Removal refused</h1><p class=mut>"
                          "Wrong admin token. The gateway was not removed.</p>"
                          "<p><a href=/>Back to records</a></p></div>", s["csrf"]))
    mid = (form.get("id") or "").strip()
    with ST_LOCK:
        st = STATIONS.pop(mid, None)
    if st:
        st.stop.set()
    try:
        db_disable_moxa(mid)
    except Exception:
        pass
    sync_stations()
    return Response(status_code=303, headers={"Location": "/"})


def repair_ph() -> int:
    """One-time repair: re-decode pH reports that were stored while the collector
    was on the wrong codepage (cp1250) so their box-drawing borders became junk.
    The bytes are recoverable -- re-encode as cp1250 and decode as CP437 -- then
    re-parse so report_type / operator / sample fields are corrected too."""
    if _via_rest():
        rows = _rest("GET", "ph_meter_data",
                     {"select": "id,raw_text", "limit": "5000"}) or []
    else:
        rows = q("SELECT id::text AS id, raw_text FROM public.ph_meter_data")
    fixed = 0
    for r in rows:
        old = r.get("raw_text") or ""
        # Already CP437-correct (has box-drawing chars)? Leave it -- re-encoding a
        # clean record would corrupt it. This makes the repair safe to re-run.
        if any("─" <= c <= "╿" for c in old):
            continue
        try:
            repaired = old.encode("cp1250", "replace").decode("cp437", "replace")
        except Exception:
            continue
        # Only rewrite when the fix actually produces box-drawing lines -- i.e. this
        # really was cp1250-mangled pH output, not innocent plain ASCII.
        if repaired == old or not any("─" <= c <= "╿" for c in repaired):
            continue
        p = parse_ph_report(repaired)
        body = {"raw_text": repaired, "report_type": p["report_type"],
                "instrument_id": p["instrument_id"],
                "instrument_sr_no": p["instrument_sr_no"], "operator": p["operator"],
                "printed_at": p["printed_at"], "is_sample": p["is_sample"],
                "registration_numbers": p["registration_numbers"],
                "rows": p["rows"], "content_hash": p["content_hash"]}
        try:
            if _via_rest():
                _rest("PATCH", "ph_meter_data", {"id": f"eq.{r['id']}"},
                      body=body, prefer="return=minimal")
            else:
                ex("UPDATE public.ph_meter_data SET raw_text=%s, report_type=%s, "
                   "instrument_id=%s, instrument_sr_no=%s, operator=%s, printed_at=%s, "
                   "is_sample=%s, registration_numbers=%s, rows=%s, content_hash=%s "
                   "WHERE id=%s",
                   (repaired, p["report_type"], p["instrument_id"], p["instrument_sr_no"],
                    p["operator"], p["printed_at"], p["is_sample"],
                    p["registration_numbers"], Json(p["rows"]), p["content_hash"], r["id"]))
            fixed += 1
        except Exception as exc:
            print(f"  skip {r['id']}: {exc}")
    print(f"repaired {fixed} pH row(s)")
    return 0


def consolidate_ph() -> int:
    """One-time: merge existing per-print pH rows into ONE row per calibration set
    (moxa+instrument+day); samples get their own set_key. Idempotent."""
    rows = db_all_ph_rows()
    sets: dict[tuple, list] = {}
    samples: list = []
    for r in rows:
        if r.get("is_sample"):
            samples.append(r)
        else:
            day = str(r.get("printed_at") or "")[:10]
            sets.setdefault((r.get("moxa_id"), r.get("instrument_id") or "?", day), []).append(r)

    changed = 0
    for smp in samples:
        key = f"sample|{smp.get('moxa_id')}|{smp.get('content_hash')}"
        if smp.get("set_key") != key or not smp.get("member_hashes"):
            db_patch_ph(smp["id"], {"set_key": key,
                                    "member_hashes": [smp.get("content_hash")]})
            changed += 1

    for (moxa_id, inst, day), reps in sets.items():
        s = sorted(reps, key=lambda x: str(x.get("printed_at") or ""))
        seen: set = set()
        uniq: list = []
        for r in s:
            h = r.get("content_hash")
            if h in seen:
                db_delete_ph(r["id"]); changed += 1; continue
            seen.add(h); uniq.append(r)
        keeper = uniq[0]
        key = f"set|{moxa_id}|{inst}|{day}"
        if len(uniq) == 1 and keeper.get("set_key") == key and keeper.get("member_hashes"):
            continue                                    # already consolidated
        raw = "\n\n".join(r.get("raw_text") or "" for r in uniq)
        merged_rows = [x for r in uniq for x in (r.get("rows") or [])]
        regs = sorted({rn for r in uniq for rn in (r.get("registration_numbers") or [])})
        has_cal = any(r.get("report_type") == "calibration" for r in uniq)
        op = next((r.get("operator") for r in uniq
                   if r.get("operator") and str(r.get("operator")).lower() != "signature"), None)
        db_patch_ph(keeper["id"], {
            "report_type": "calibration" if has_cal else "analysis",
            "operator": op, "printed_at": keeper.get("printed_at"), "is_sample": False,
            "registration_numbers": regs, "rows": merged_rows, "raw_text": raw,
            "content_hash": hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest(),
            "set_key": key, "member_hashes": [r.get("content_hash") for r in uniq],
            "bytes": sum(int(r.get("bytes") or 0) for r in uniq)})
        for r in uniq[1:]:
            db_delete_ph(r["id"])
        changed += 1
    print(f"consolidated pH rows; {changed} change(s)")
    return 0


def main() -> int:
    import uvicorn
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=get("BALANCE_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(get("BALANCE_PORT", "8000") or "8000"))
    ap.add_argument("--repair-ph", action="store_true",
                    help="Re-decode & re-parse existing pH records (cp1250->CP437), then exit.")
    ap.add_argument("--consolidate-ph", action="store_true",
                    help="Merge existing per-print pH rows into one row per set, then exit.")
    args = ap.parse_args()

    if args.repair_ph:
        if not configured():
            print("Supabase not configured; cannot repair.")
            return 1
        return repair_ph()
    if args.consolidate_ph:
        if not configured():
            print("Supabase not configured; cannot consolidate.")
            return 1
        return consolidate_ph()

    print(f"LIMS Balance Integration  ->  http://{args.host}:{args.port}")
    # Show the admin token only on an interactive console; when run as a hidden
    # background service the value must not land in the log -- read it from the file.
    if os.isatty(1):
        print(f"\n  ADMIN TOKEN:  {ADMIN_TOKEN}\n"
              f"  (paste this to sign in; also saved in {ADMIN_TOKEN_FILE})\n")
    else:
        print(f"  ADMIN TOKEN: hidden -- read it from {ADMIN_TOKEN_FILE}\n")
    if not configured():
        print("  Supabase is NOT configured yet -- configuration is MANDATORY.\n"
              "  Open Settings to connect before any session can be captured.\n")
    if args.host not in ("127.0.0.1", "localhost"):
        print("  WARNING: bound to a non-loopback address. Put it behind TLS.\n")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
