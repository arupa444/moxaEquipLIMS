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
DEFAULT_PORT = int(get("MOXA_DEFAULT_PORT", "4001") or "4001")
GAP = float(get("BURST_GAP_SECONDS", "1.5") or "1.5")
COLLECTOR_ID = get("COLLECTOR_ID", "collector-01")


def mode() -> str:
    m = (get("SUPABASE_MODE", "self_hosted") or "self_hosted").lower()
    return "cloud" if m == "cloud" else "self_hosted"


def configured() -> bool:
    if not get("SESSION_SECRET_CURRENT"):
        return False
    if mode() == "cloud":
        return all(get(k) for k in ("SUPABASE_URL",
                                    "SUPABASE_SERVICE_ROLE_KEY_CURRENT",
                                    "SUPABASE_PUBLISHABLE_KEY"))
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
  enabled       boolean NOT NULL DEFAULT true,
  status        text DEFAULT 'idle',
  last_seen     timestamptz,
  snmp_community text,
  moxa_password_enc text,
  collector_id  text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

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

GRANT SELECT (id, host, port, name, enabled, status, last_seen, collector_id,
              created_at, updated_at) ON public."moxaServers" TO authenticated;
GRANT SELECT ON public.balance_integration_data TO authenticated;
GRANT ALL ON public."moxaServers" TO service_role;
GRANT ALL ON public.balance_integration_data TO service_role;

ALTER TABLE public."moxaServers" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.balance_integration_data ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "moxaServers_read_auth" ON public."moxaServers";
CREATE POLICY "moxaServers_read_auth" ON public."moxaServers"
  FOR SELECT TO authenticated USING (true);
DROP POLICY IF EXISTS "balance_integration_read_auth" ON public.balance_integration_data;
CREATE POLICY "balance_integration_read_auth" ON public.balance_integration_data
  FOR SELECT TO authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_balance_integration_finished
  ON public.balance_integration_data (finished_at DESC);
CREATE INDEX IF NOT EXISTS idx_balance_integration_moxa
  ON public.balance_integration_data (moxa_id);
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
    if mode() == "cloud":
        try:
            _rest("GET", "moxaServers", {"select": "id", "limit": "1"})
            _rest("GET", "balance_integration_data", {"select": "id", "limit": "1"})
        except RestError as exc:
            raise RuntimeError(
                "Supabase reachable but the tables are missing. Apply the "
                "migration '*_moxa_and_balance_integration.sql' to this project "
                f"first. ({exc})")
        return
    with pool().connection() as c, c.cursor() as cur:
        cur.execute(DDL)
        try:
            cur.execute("NOTIFY pgrst, 'reload schema'")
        except Exception:
            pass


def db_list_enabled_moxa() -> list[dict]:
    if mode() == "cloud":
        rows = _rest("GET", "moxaServers",
                     {"select": "id,host,port,name", "enabled": "eq.true"}) or []
        return [{"id": r["id"], "host": r["host"], "port": r["port"],
                 "name": r["name"]} for r in rows]
    return q('SELECT id::text AS id, host, port, name '
             'FROM public."moxaServers" WHERE enabled=true')


def db_set_status(mid: str, status: str) -> None:
    if mode() == "cloud":
        _rest("PATCH", "moxaServers", {"id": f"eq.{mid}"},
              body={"status": status, "last_seen": now_iso(), "updated_at": now_iso()},
              prefer="return=minimal")
    else:
        ex('UPDATE public."moxaServers" SET status=%s, last_seen=%s, '
           'updated_at=now() WHERE id=%s', (status, now_iso(), mid))


def db_insert_session(row: dict) -> None:
    if mode() == "cloud":
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


def db_upsert_moxa(host: str, port: int, name: str, pw_enc: str | None) -> None:
    if mode() == "cloud":
        body = {"host": host, "port": port, "name": name, "enabled": True,
                "status": "idle", "collector_id": COLLECTOR_ID, "updated_at": now_iso()}
        if pw_enc is not None:
            body["moxa_password_enc"] = pw_enc
        _rest("POST", "moxaServers", {"on_conflict": "host"}, body=body,
              prefer="resolution=merge-duplicates,return=minimal")
    else:
        ex('INSERT INTO public."moxaServers" (host, port, name, enabled, status, '
           'moxa_password_enc, collector_id) VALUES (%s,%s,%s,true,\'idle\',%s,%s) '
           'ON CONFLICT (host) DO UPDATE SET port=excluded.port, name=excluded.name, '
           'enabled=true, status=\'idle\', collector_id=excluded.collector_id, '
           'moxa_password_enc=COALESCE(excluded.moxa_password_enc, '
           'public."moxaServers".moxa_password_enc), updated_at=now()',
           (host, port, name, pw_enc, COLLECTOR_ID))


def db_disable_moxa(mid: str) -> None:
    if mode() == "cloud":
        _rest("PATCH", "moxaServers", {"id": f"eq.{mid}"},
              body={"enabled": False, "status": "removed", "updated_at": now_iso()},
              prefer="return=minimal")
    else:
        ex('UPDATE public."moxaServers" SET enabled=false, status=\'removed\', '
           'updated_at=now() WHERE id=%s', (mid,))


def db_moxa_display() -> list[dict]:
    if mode() == "cloud":
        return _rest("GET", "moxaServers",
                     {"select": "id,host,port,name,status,last_seen",
                      "enabled": "eq.true", "order": "created_at.asc"}) or []
    return q('SELECT id::text AS id, host, port, name, status, last_seen '
             'FROM public."moxaServers" WHERE enabled=true ORDER BY created_at')


def db_sessions(limit: int = 200) -> list[dict]:
    if mode() == "cloud":
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
    if mode() == "cloud":
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
    if mode() == "cloud":
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
    pw = secrets.token_urlsafe(12)
    salt = secrets.token_bytes(16)
    st["pw_salt"] = salt.hex()
    st["pw_hash"] = hash_pw(pw, salt).hex()
    _save_authstate(st)
    return pw


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


def new_session() -> str:
    tok = secrets.token_urlsafe(32)
    with SESS_LOCK:
        SESSIONS[tok] = {"exp": time.time() + 8 * 3600, "csrf": secrets.token_urlsafe(24)}
    return tok


def get_session(tok: str | None) -> dict | None:
    if not tok:
        return None
    with SESS_LOCK:
        s = SESSIONS.get(tok)
        if not s:
            return None
        if s["exp"] < time.time():
            SESSIONS.pop(tok, None)
            return None
        return s


def rate_limited(ip: str) -> bool:
    now = time.time()
    hits = [t for t in FAILS.get(ip, []) if now - t < 300]
    FAILS[ip] = hits
    return len(hits) >= 8


# ------------------------------------------------------------- capture ---
# The session-detection state machine is preserved verbatim from the original
# collector; only the storage sink changed (Supabase, not SQLite/.txt).

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


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class Station(threading.Thread):
    """One MOXA: own socket, own buffer, own session queue -> Supabase."""

    daemon = True

    def __init__(self, mid: str, host: str, port: int, name: str, gap: float = GAP):
        super().__init__(name=f"moxa-{host}")
        self.mid, self.host, self.port, self.name, self.gap = mid, host, port, name, gap
        self.stop = threading.Event()

    def _status(self, s: str) -> None:
        try:
            db_set_status(self.mid, s)
        except Exception:
            pass

    def run(self) -> None:
        sock = None
        buf = bytearray()
        last = 0.0
        blocks: list[tuple[str, str, str]] = []
        meta: dict[str, str] = {}
        while not self.stop.is_set():
            if sock is None:
                try:
                    sock = socket.create_connection((self.host, self.port), timeout=5)
                    sock.settimeout(0.2)
                    self._status("connected")
                except ConnectionRefusedError:
                    self._status("busy: port 4001 in use by another client")
                    time.sleep(5)
                    continue
                except OSError as exc:
                    self._status(f"offline: {exc.strerror or exc}")
                    time.sleep(5)
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

            if buf and last and (time.monotonic() - last) > self.gap:
                whole = bytes(buf).decode(CODEPAGE, errors="replace")
                buf = bytearray()
                for text in split_bursts(whole):
                    blocks, meta = self._one(text, blocks, meta)
        try:
            if sock:
                sock.close()
        except OSError:
            pass

    def _one(self, text, blocks, meta):
        if is_noise(text):
            return blocks, meta
        k = kind_of(text)
        stamp = now_iso()
        if k == "adjustment":
            sn = field(text, "Balance S/N") or field(text, "Balance Type")
            self._save("adjustment", f"{self.name}_{sn or 'NA'}_CAL",
                       [("adjustment", stamp, text)],
                       {"balance_sn": sn, "operator": field(text, "Operator")})
        elif k == "header":
            if blocks:
                self._status(f"discarded incomplete session ({len(blocks)} blocks)")
            blocks = [("header", stamp, text)]
            meta = {"inst_id": field(text, "INST-ID"),
                    "reg_no": field(text, "Reg No"),
                    "balance_sn": field(text, "Balance S/N"),
                    "operator": field(text, "Operator")}
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
        label = f"{self.name}_{meta.get('inst_id') or 'NA'}_{meta.get('reg_no') or 'NA'}"
        self._save("weighing", label, blocks, meta)

    def _save(self, kind: str, label: str, blocks: list, meta: dict) -> None:
        raw_text = "".join(b[2] for b in blocks)
        total = sum(len(b[2].encode(CODEPAGE, "replace")) for b in blocks)
        payload = [{"seq": i, "kind": b[0], "received": b[1], "body": b[2]}
                   for i, b in enumerate(blocks)]
        row = {"moxa_id": self.mid, "moxa_name": self.name, "moxa_host": self.host,
               "kind": kind, "label": label, "inst_id": meta.get("inst_id"),
               "reg_no": meta.get("reg_no"), "balance_sn": meta.get("balance_sn"),
               "operator": meta.get("operator"), "started_at": blocks[0][1],
               "finished_at": blocks[-1][1], "raw_text": raw_text,
               "blocks": payload, "bytes": total, "collector_id": COLLECTOR_ID}
        try:
            db_insert_session(row)
            self._status(f"saved {kind}: {label}")
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
                st = Station(mid, r["host"], r["port"], r["name"] or r["host"])
                STATIONS[mid] = st
                st.start()


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
"""

LOGIN = """<!doctype html><html data-theme=light><meta charset=utf-8><title>Sign in - LIMS Balance Integration</title>
<meta name=viewport content="width=device-width,initial-scale=1"><style>%s
.mid{min-height:100vh;display:grid;place-items:center}form{width:320px}
</style><div class=mid><form class=card method=post action=/login>
<h1 style=margin-bottom:14px>LIMS Balance Integration</h1>
%s<label class=mut style=font-size:13px>Password</label>
<input name=password type=password autofocus required style=width:100%%;margin:6px 0 12px>
<button style=width:100%%>Sign in</button></form></div>"""


def esc(v) -> str:
    return html.escape("" if v is None else str(v))


def page(body: str, csrf: str, tab: str = "records") -> str:
    nav_r = "on" if tab == "records" else ""
    nav_s = "on" if tab == "settings" else ""
    return f"""<!doctype html><meta charset=utf-8><title>LIMS Balance Integration</title>
<meta name=viewport content="width=device-width,initial-scale=1"><style>{CSS}</style>
<header><h1>LIMS Balance Integration</h1>
<nav style=display:flex;gap:16px><a href=/ class="{nav_r}">Records</a><a href=/settings class="{nav_s}">Settings</a></nav><span class=mut id=clock></span><div id=toast class=hide></div>
<button class="ghost right" id=themeBtn title="Toggle theme">&#9681; Theme</button><form method=post action=/logout style=margin-left:10px>
<input type=hidden name=csrf value="{esc(csrf)}">
<button class=ghost>Sign out</button></form></header>
<div class=wrap>{body}</div>
<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const setTheme=t=>{{document.documentElement.setAttribute('data-theme',t);
  try{{localStorage.setItem('lims-theme',t)}}catch(e){{}}
  const b=$('#themeBtn'); if(b) b.textContent=(t==='dark'?'◑ Light':'◐ Dark');}};
setTheme(localStorage.getItem('lims-theme')||'light');
$('#themeBtn')?.addEventListener('click',()=>setTheme(
  document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark'));
document.addEventListener('click',e=>{{
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
// Manual refresh only: the page reloads solely when the Refresh button is
// clicked. No background polling or auto-reload.
</script>"""


def render(csrf: str) -> str:
    try:
        moxas = db_moxa_display()
        rows = db_sessions(200)
        tot, tw, ta = db_counts()
    except Exception as exc:
        return (f"<div class=card><h1>Database error</h1>"
                f"<p class=mut>Could not reach Supabase: {esc(exc)}</p>"
                f"<p><a href=/settings>Check settings</a></p></div>")

    m_html = ["<div class=card><h1>Equipment / MOXA gateways</h1><table><tr><th>Name<th>Host"
              "<th>Status<th>Last seen<th></tr>"]
    for m in moxas:
        st = esc(m["status"])
        col = ("var(--ok)" if st.startswith(("connected", "saved"))
               else "var(--warn)" if st.startswith(("busy", "idle", "reconnect"))
               else "var(--bad)" if st.startswith(("offline", "removed", "error")) else "var(--warn)")
        last = esc(str(m["last_seen"])[:19].replace("T", " ") if m["last_seen"] else "-")
        m_html.append(
            f"<tr><td>{esc(m['name'])}<td class=mono>{esc(m['host'])}:{m['port']}"
            f"<td><span class=dot style=background:{col}></span>{st}"
            f"<td class=mut>{last}"
            f"<td><form class=inline method=post action=/moxa/del>"
            f"<input type=hidden name=csrf value='{esc(csrf)}'>"
            f"<input type=hidden name=id value='{esc(m['id'])}'>"
            f"<input name=password type=password placeholder='password' "
            f"size=12 required autocomplete=off>"
            f"<button class=ghost>Remove</button></form></tr>")
    m_html.append("</table><form class='inline' method=post action=/moxa/add "
                  "style=margin-top:14px>"
                  f"<input type=hidden name=csrf value='{esc(csrf)}'>"
                  "<input name=host placeholder='10.20.30.11' required>"
                  "<input name=port value=4001 size=6>"
                  "<input name=name placeholder='equipment name (blank = ask via SNMP)'>"
                  "<input name=moxa_password type=password placeholder='device password (stored encrypted)' autocomplete=off>"
                  "<button>Add equipment</button></form></div>")

    r_html = [f"""<div class=card>
      <div class=stat><div><b>{tot}</b><span>records</span></div>
      <div><b>{tw}</b><span>weighing</span></div>
      <div><b>{ta}</b><span>adjustment</span></div>
      <div><b>{len(moxas)}</b><span>servers</span></div></div></div>
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


# (key, label, placeholder, is_secret, group)  group in {"pg","cloud","common"}
SUPA_FIELDS = [
    ("SUPABASE_DB_HOST", "Postgres host", "10.1.11.98", False, "pg"),
    ("SUPABASE_DB_PORT", "Postgres port", "5433", False, "pg"),
    ("SUPABASE_DB_NAME", "Database name", "lims_restore", False, "pg"),
    ("SUPABASE_DB_USER", "Username", "supabase_admin", False, "pg"),
    ("SUPABASE_DB_PASSWORD", "Password", "", True, "pg"),
    ("SUPABASE_URL", "SUPABASE_URL", "https://xxxx.supabase.co", False, "cloud"),
    ("SUPABASE_SERVICE_ROLE_KEY_CURRENT", "Service role key", "eyJhbGciOi...", True, "cloud"),
    ("SUPABASE_PUBLISHABLE_KEY", "Publishable / anon key", "sb_publishable_...", True, "cloud"),
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

    out.append(f"<form method=post action=/settings>"
               f"<input type=hidden name=csrf value='{esc(csrf)}'>")
    # Mode selector.
    sh = "selected" if cur_mode == "self_hosted" else ""
    cl = "selected" if cur_mode == "cloud" else ""
    out.append(
        "<label class=fld>Deployment</label>"
        "<select name=SUPABASE_MODE id=modeSel style=max-width:520px;width:100%>"
        f"<option value=self_hosted {sh}>Self-hosted Supabase (direct Postgres)</option>"
        f"<option value=cloud {cl}>Cloud Supabase (*.supabase.co, REST)</option>"
        "</select>"
        "<div class=mut style='font-size:12px;margin-top:6px'>Self-hosted uses a "
        "direct Postgres connection and creates the tables automatically. Cloud "
        "uses the REST API with the service-role key; create the tables first by "
        "applying the migration to the project.</div>")

    for k, label, ph, is_secret, group in SUPA_FIELDS:
        note = ""
        shown = ""
        if is_secret:
            resolved = get(k)
            if resolved:
                raw = _CFG_RAW.get(k, "")
                enc = ("DPAPI-encrypted" if raw.startswith("dpapi:")
                       else "encrypted" if raw.startswith("enc:") else "stored")
                note = (f"<span class=badge>{enc}</span> "
                        f"<span class=fp>{esc(mask(resolved))} &middot; "
                        f"sha256:{esc(fingerprint(resolved))}</span>")
            ph = "(set - blank keeps it)" if resolved else ph
        else:
            shown = get(k)
        wrap_cls = "grp common" if group == "common" else f"grp {group}"
        out.append(
            f"<div class='{wrap_cls}'><label class=fld>{esc(label)}</label>"
            f"<input name={k} value=\"{esc(shown)}\" placeholder=\"{esc(ph)}\" "
            f"style=width:100%;max-width:520px "
            f"{'type=password autocomplete=new-password' if is_secret else ''}>"
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
    ensure_password()
    if configured():
        try:
            init_db()
        except Exception as exc:
            print(f"  init_db failed: {exc}")
    sync_stations()

    def _loop():
        while True:
            time.sleep(20)
            try:
                sync_stations()
            except Exception:
                pass
    threading.Thread(target=_loop, daemon=True).start()


SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": ("default-src 'none'; style-src 'unsafe-inline'; "
                               "script-src 'unsafe-inline'; form-action 'self'"),
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
def login_page():
    return _html(LOGIN % (CSS, ""))


@app.post("/login")
async def login(request: Request):
    ip = request.client.host if request.client else "?"
    if rate_limited(ip):
        return _html(LOGIN % (CSS, "<p style=color:var(--bad)>Too many attempts. "
                              "Wait 5 minutes.</p>"), 429)
    form = await request.form()
    if check_pw(form.get("password", "")):
        FAILS.pop(ip, None)
        tok = new_session()
        resp = Response(status_code=303, headers={"Location": "/"})
        resp.set_cookie("sid", tok, max_age=28800, httponly=True,
                        samesite="strict", path="/")
        return resp
    FAILS.setdefault(ip, []).append(time.time())
    return _html(LOGIN % (CSS, "<p style=color:var(--bad)>Wrong password.</p>"), 401)


@app.get("/", response_class=HTMLResponse)
def records(request: Request):
    _, s = _sess(request)
    if not s:
        return Response(status_code=303, headers={"Location": "/login"})
    # Supabase configuration is mandatory -- send the user straight to Settings
    # until it is done. Nothing is captured or stored before then.
    if not configured():
        return Response(status_code=303, headers={"Location": "/settings"})
    return _html(page(render(s["csrf"]), s["csrf"]))


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    _, s = _sess(request)
    if not s:
        return Response(status_code=303, headers={"Location": "/login"})
    return _html(page(render_settings(s["csrf"]), s["csrf"], "settings"))


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
    pw = (form.get("moxa_password") or "").strip()
    pw_enc = encrypt_secret(pw) if pw else None
    try:
        db_upsert_moxa(host, port, name, pw_enc)
    except Exception as exc:
        return _html(page(f"<div class=card><h1>Could not add gateway</h1>"
                          f"<p class=mut>{esc(exc)}</p><p><a href=/>Back</a></p></div>",
                          s["csrf"]))
    sync_stations()
    return Response(status_code=303, headers={"Location": "/"})


@app.post("/moxa/del")
async def moxa_del(request: Request):
    _, s = _sess(request)
    if not s:
        return Response(status_code=303, headers={"Location": "/login"})
    form = await request.form()
    if not _csrf_ok(form, s):
        return PlainTextResponse("bad csrf", status_code=403)
    if not check_pw(form.get("password", "")):
        return _html(page("<div class=card><h1>Removal refused</h1><p class=mut>"
                          "Wrong password. The gateway was not removed.</p>"
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


def main() -> int:
    import uvicorn
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=get("BALANCE_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(get("BALANCE_PORT", "8000") or "8000"))
    args = ap.parse_args()

    gen = ensure_password()
    print(f"LIMS Balance Integration  ->  http://{args.host}:{args.port}")
    if gen:
        print(f"\n  GENERATED PASSWORD:  {gen}\n"
              f"  (stored hashed in {AUTH_STATE}; set BALANCE_PASSWORD in .cred to choose your own)\n")
    if not configured():
        print("  Supabase is NOT configured yet -- configuration is MANDATORY.\n"
              "  Open Settings to connect before any session can be captured.\n")
    if args.host not in ("127.0.0.1", "localhost"):
        print("  WARNING: bound to a non-loopback address. Put it behind TLS.\n")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
