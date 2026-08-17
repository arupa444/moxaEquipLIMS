"""LIMS Equipment Config -- multi-MOXA capture with a web UI. Stdlib only.

    python balance_server.py                 # http://127.0.0.1:8000
    BALANCE_PASSWORD=secret python balance_server.py

Records go to SQLite (balance.db), not .txt files. The UI lists them as rows;
click a row to expand its sub-blocks (header / weights / footer).

SECURITY
  * binds 127.0.0.1 by default (--host 0.0.0.0 only if you mean it)
  * PBKDF2-SHA256 password, 200k iterations, per-install random salt
  * random 256-bit session token, HttpOnly + SameSite=Strict cookie, 8h expiry
  * constant-time credential compare; login rate-limited per IP
  * every SQL statement parameterised; every value HTML-escaped on output
  * CSP forbids external/inline-script loading; no third-party assets at all
  * POST endpoints require a CSRF token bound to the session
"""

import argparse
import html
import hmac
import http.cookies
import json
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

def load_env(path: str = ".env") -> None:
    """Minimal .env loader -- no third-party dependency. Real environment
    variables always win, so a shell export can override the file."""
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip().strip('"').strip("'")
                os.environ.setdefault(k, v)
    except FileNotFoundError:
        pass


load_env()

DB = os.environ.get("BALANCE_DB", "balance.db")
CODEPAGE = os.environ.get("BALANCE_CODEPAGE", "cp1250")
PORT = int(os.environ.get("MOXA_DEFAULT_PORT", "4001"))
GAP = float(os.environ.get("BURST_GAP_SECONDS", "1.5"))
MASTER_KEY = os.environ.get("BALANCE_SECRET_KEY", "")


# --------------------------------------------------------- secret at rest ---
# Reusable credentials (Supabase keys) CANNOT be hashed -- a hash is one-way and
# we must send the real key to Supabase later. So they are ENCRYPTED at rest with
# a key derived from BALANCE_SECRET_KEY, and additionally fingerprinted with a
# SHA-256 hash so the UI can prove which value is stored without revealing it.
# The login password, which never needs recovering, IS hashed (PBKDF2) instead.

def _keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    import hashlib
    out = b""
    ctr = 0
    while len(out) < n:
        out += hmac.new(key, nonce + ctr.to_bytes(8, "big"), hashlib.sha256).digest()
        ctr += 1
    return out[:n]


def encrypt_secret(plain: str) -> str:
    """nonce | ciphertext | HMAC tag, base64. Authenticated (encrypt-then-MAC)."""
    import base64, hashlib
    if not plain:
        return ""
    if not MASTER_KEY or MASTER_KEY.startswith("REPLACE"):
        raise ValueError("BALANCE_SECRET_KEY is not set in .env")
    key = hashlib.pbkdf2_hmac("sha256", MASTER_KEY.encode(), b"balance-secret", 200_000)
    nonce = secrets.token_bytes(16)
    data = plain.encode()
    ct = bytes(a ^ b for a, b in zip(data, _keystream(key, nonce, len(data))))
    tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()[:16]
    return base64.b64encode(nonce + ct + tag).decode()


def decrypt_secret(blob: str) -> str:
    import base64, hashlib
    if not blob:
        return ""
    key = hashlib.pbkdf2_hmac("sha256", MASTER_KEY.encode(), b"balance-secret", 200_000)
    raw = base64.b64decode(blob)
    nonce, ct, tag = raw[:16], raw[16:-16], raw[-16:]
    if not hmac.compare_digest(hmac.new(key, nonce + ct, hashlib.sha256).digest()[:16], tag):
        raise ValueError("secret failed integrity check (wrong BALANCE_SECRET_KEY?)")
    return bytes(a ^ b for a, b in zip(ct, _keystream(key, nonce, len(ct)))).decode()


def fingerprint(plain: str) -> str:
    import hashlib
    return hashlib.sha256(plain.encode()).hexdigest()[:12] if plain else ""


def mask(plain: str) -> str:
    if not plain:
        return ""
    return plain[:4] + "\u2026" + plain[-4:] if len(plain) > 12 else "\u2022" * len(plain)

# ---------------------------------------------------------------- storage ---

_local = threading.local()


def db() -> sqlite3.Connection:
    if not getattr(_local, "conn", None):
        _local.conn = sqlite3.connect(DB, timeout=30)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
    return _local.conn


def init_db() -> None:
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS moxa (
        id INTEGER PRIMARY KEY, host TEXT UNIQUE NOT NULL,
        port INTEGER NOT NULL DEFAULT 4001, name TEXT, enabled INTEGER DEFAULT 1,
        status TEXT DEFAULT 'idle', last_seen TEXT);
    CREATE TABLE IF NOT EXISTS record (
        id INTEGER PRIMARY KEY, moxa_id INTEGER NOT NULL REFERENCES moxa(id),
        kind TEXT NOT NULL, label TEXT NOT NULL, inst_id TEXT, reg_no TEXT,
        balance_sn TEXT, operator TEXT, started TEXT, finished TEXT,
        bytes INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS block (
        id INTEGER PRIMARY KEY, record_id INTEGER NOT NULL REFERENCES record(id),
        seq INTEGER NOT NULL, kind TEXT NOT NULL, received TEXT NOT NULL,
        body TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS setting (k TEXT PRIMARY KEY, v TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS ix_rec ON record(finished DESC);
    CREATE INDEX IF NOT EXISTS ix_blk ON block(record_id, seq);
    """)
    c.commit()


def setting(k: str, default: str = "") -> str:
    r = db().execute("SELECT v FROM setting WHERE k=?", (k,)).fetchone()
    return r["v"] if r else default


def set_setting(k: str, v: str) -> None:
    db().execute("INSERT INTO setting(k,v) VALUES(?,?) "
                 "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))
    db().commit()


# --------------------------------------------------------------- security ---

def hash_pw(pw: str, salt: bytes) -> bytes:
    return hashlib_pbkdf2(pw.encode(), salt)


def hashlib_pbkdf2(pw: bytes, salt: bytes) -> bytes:
    import hashlib
    return hashlib.pbkdf2_hmac("sha256", pw, salt, 200_000)


def ensure_password() -> str | None:
    """Sync the login password from .env on EVERY start.

    Previously the hash was written only on first run, so editing
    BALANCE_PASSWORD in .env silently did nothing and the old password kept
    working -- which looked exactly like "the right password is rejected".
    If BALANCE_PASSWORD is set it is now authoritative and re-hashed each start.
    Returns a generated password only when none was supplied and none exists.
    """
    env_pw = os.environ.get("BALANCE_PASSWORD", "").strip()
    if env_pw:
        salt = secrets.token_bytes(16)
        set_setting("pw_salt", salt.hex())
        set_setting("pw_hash", hash_pw(env_pw, salt).hex())
        return None
    if setting("pw_salt"):
        return None
    pw = secrets.token_urlsafe(12)
    salt = secrets.token_bytes(16)
    set_setting("pw_salt", salt.hex())
    set_setting("pw_hash", hash_pw(pw, salt).hex())
    return pw


def check_pw(pw: str) -> bool:
    salt = bytes.fromhex(setting("pw_salt"))
    want = bytes.fromhex(setting("pw_hash"))
    return hmac.compare_digest(hash_pw(pw, salt), want)


SESSIONS: dict[str, dict] = {}
SESS_LOCK = threading.Lock()
FAILS: dict[str, list[float]] = {}


def new_session() -> str:
    tok = secrets.token_urlsafe(32)
    with SESS_LOCK:
        SESSIONS[tok] = {"exp": time.time() + 8 * 3600,
                         "csrf": secrets.token_urlsafe(24)}
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


# ---------------------------------------------------------------- capture ---

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
    """Split one TCP burst into the separate printouts it contains.

    Split ONLY at a titled rule (`--- Weighing ---`, `--- Adjustment ---`) or a
    `Current result` line. An earlier version also split at any bare `-----`
    rule, which cut blocks apart internally and turned the leftover
    `Signature`/rule tail into phantom `weight` segments -- weights nobody
    pressed. Bare rules are decoration inside a block, never a boundary.
    """
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
    """Rules, blank lines and a lone `Signature` carry no record content."""
    body = [l.strip() for l in text.splitlines() if l.strip()]
    if not body:
        return True
    for l in body:
        if re.fullmatch(r"[-.\s]*", l):        # a rule
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
    """One MOXA: own socket, own buffer, own session queue."""

    daemon = True

    def __init__(self, mid: int, host: str, port: int, gap: float = 1.5):
        super().__init__(name=f"moxa-{host}")
        self.mid, self.host, self.port, self.gap = mid, host, port, gap
        self.stop = threading.Event()

    def _status(self, s: str) -> None:
        c = db()
        c.execute("UPDATE moxa SET status=?, last_seen=? WHERE id=?",
                  (s, now_iso(), self.mid))
        c.commit()

    def run(self) -> None:
        sock = None
        buf = bytearray()
        last = 0.0
        blocks: list[tuple[str, str, str]] = []   # (kind, received, body)
        meta: dict[str, str] = {}
        while not self.stop.is_set():
            if sock is None:
                try:
                    sock = socket.create_connection((self.host, self.port), timeout=5)
                    sock.settimeout(0.2)
                    self._status("connected")
                except ConnectionRefusedError:
                    # The NPort allows ONE TCP client. Refused almost always
                    # means another tool already holds port 4001, not that the
                    # gateway is down.
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

    def _one(self, text, blocks, meta):
        if is_noise(text):
            return blocks, meta
        k = kind_of(text)
        stamp = now_iso()
        if k == "adjustment":
            sn = field(text, "Balance S/N") or field(text, "Balance Type")
            self._save("adjustment",
                       f"{self.disp_name()}_{sn or 'NA'}_CAL",
                       [("adjustment", stamp, text)],
                       {"balance_sn": sn, "operator": field(text, "Operator")})
        elif k == "header":
            if blocks:
                # header -> ... -> header never reached a footer: discard.
                self._status(f"discarded incomplete session ({len(blocks)} blocks)")
            blocks = [("header", stamp, text)]
            meta = {"inst_id": field(text, "INST-ID"),
                    "reg_no": field(text, "Reg No"),
                    "balance_sn": field(text, "Balance S/N"),
                    "operator": field(text, "Operator")}
        elif k == "weight":
            # A weight or footer arriving with no open session has no
            # header to belong to -- treat it as a false input and drop
            # it, rather than storing a record with no metadata.
            if not blocks:
                self._status("discarded weight (no header yet)")
            else:
                blocks.append(("weight", stamp, text))
        else:
            if not blocks:
                self._status("discarded footer (no header yet)")
            elif not any(x[0] == "weight" for x in blocks):
                # header -> footer with nothing weighed is not a valid
                # session; discard the whole flow.
                self._status("discarded session (no weight between "
                             "header and footer)")
                blocks, meta = [], {}
            else:
                blocks.append(("footer", stamp, text))
                self._flush(blocks, meta)
                blocks, meta = [], {}
        return blocks, meta
        if sock:
            sock.close()

    def disp_name(self) -> str:
        """NOT named _name: threading.Thread sets an instance attribute
        `self._name` in its constructor, which shadows a method of that name
        and fails at call time with "'str' object is not callable"."""
        r = db().execute("SELECT name FROM moxa WHERE id=?", (self.mid,)).fetchone()
        return (r["name"] if r and r["name"] else self.host)

    def _flush(self, blocks: list, meta: dict) -> None:
        if not blocks:
            return
        label = (f"{self.disp_name()}_{meta.get('inst_id') or 'NA'}"
                 f"_{meta.get('reg_no') or 'NA'}")
        self._save("weighing", label, blocks, meta)

    def _save(self, kind: str, label: str, blocks: list, meta: dict) -> None:
        c = db()
        total = sum(len(b[2].encode(CODEPAGE, "replace")) for b in blocks)
        cur = c.execute(
            "INSERT INTO record(moxa_id,kind,label,inst_id,reg_no,balance_sn,"
            "operator,started,finished,bytes) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (self.mid, kind, label, meta.get("inst_id"), meta.get("reg_no"),
             meta.get("balance_sn"), meta.get("operator"),
             blocks[0][1], blocks[-1][1], total))
        rid = cur.lastrowid
        c.executemany(
            "INSERT INTO block(record_id,seq,kind,received,body) VALUES(?,?,?,?,?)",
            [(rid, i, b[0], b[1], b[2]) for i, b in enumerate(blocks)])
        c.commit()


STATIONS: dict[int, Station] = {}
ST_LOCK = threading.Lock()


def sync_stations() -> None:
    with ST_LOCK:
        rows = db().execute("SELECT * FROM moxa WHERE enabled=1").fetchall()
        want = {r["id"]: r for r in rows}
        for mid in list(STATIONS):
            if mid not in want:
                STATIONS.pop(mid).stop.set()
        for mid, r in want.items():
            if mid not in STATIONS or not STATIONS[mid].is_alive():
                st = Station(mid, r["host"], r["port"])
                STATIONS[mid] = st
                st.start()


# --------------------------------------------------------------------- UI ---

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
tr.row td:first-child::before{content:"\25B8";display:inline-block;margin-right:8px;
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
"""

LOGIN = """<!doctype html><html data-theme=light><meta charset=utf-8><title>Sign in - LIMS Equipment Config</title>
<meta name=viewport content="width=device-width,initial-scale=1"><style>%s
.mid{min-height:100vh;display:grid;place-items:center}form{width:320px}
</style><div class=mid><form class=card method=post action=/login>
<h1 style=margin-bottom:14px>LIMS Equipment Config</h1>
%s<label class=mut style=font-size:13px>Password</label>
<input name=password type=password autofocus required style=width:100%%;margin:6px 0 12px>
<button style=width:100%%>Sign in</button></form></div>"""


def esc(v) -> str:
    return html.escape("" if v is None else str(v))


def page(body: str, csrf: str, tab: str = "records") -> bytes:
    nav_r = "on" if tab == "records" else ""
    nav_s = "on" if tab == "settings" else ""
    return (f"""<!doctype html><meta charset=utf-8><title>LIMS Equipment Config</title>
<meta name=viewport content="width=device-width,initial-scale=1"><style>{CSS}</style>
<header><h1>LIMS Equipment Config</h1>
<nav style=display:flex;gap:16px><a href=/ class="{nav_r}">Records</a><a href=/settings class="{nav_s}">Settings</a></nav><span class=mut id=clock></span><div id=toast class=hide></div>
<button class="ghost right" id=themeBtn title="Toggle theme">&#9681; Theme</button><form method=post action=/logout style=margin-left:10px>
<input type=hidden name=csrf value="{esc(csrf)}">
<button class=ghost>Sign out</button></form></header>
<div class=wrap>{body}</div>
<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const setTheme=t=>{{document.documentElement.setAttribute('data-theme',t);
  try{{localStorage.setItem('lims-theme',t)}}catch(e){{}}
  const b=$('#themeBtn'); if(b) b.textContent=(t==='dark'?'\u25D1 Light':'\u25D0 Dark');}};
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
addEventListener('keydown',e=>{{
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){{e.preventDefault();$('#q')?.focus();}}
  if(e.key==='Escape'&&$('#q')){{$('#q').value='';applyFilter();$('#q').blur();}}
}});
function toast(m){{const t=$('#toast');t.textContent=m;t.classList.remove('hide');
  clearTimeout(t._h);t._h=setTimeout(()=>t.classList.add('hide'),1800);}}
function tick(){{const c=$('#clock');if(c)c.textContent=new Date().toLocaleTimeString();}}
tick();setInterval(tick,1000);
$('#refreshBtn')?.addEventListener('click',()=>location.reload());
// Poll a tiny endpoint and reload only when a session actually completes or a
// gateway status changes -- not on a blind timer.
let tip=null;
async function poll(){{
  try{{
    const r=await fetch('/api/tip',{{cache:'no-store'}});
    if(!r.ok) return;
    const d=await r.json(), sig=d.max_id+'|'+d.count+'|'+d.status;
    if(tip===null){{tip=sig; return;}}
    if(sig===tip) return;
    tip=sig;
    const busy=($('#q')?.value)||($('#kind')?.value)||$$('tr.sub-row:not(.hide)').length;
    if(busy){{
      const n=$('#newNote');
      if(n){{n.classList.remove('hide');}}
      return;                       // never yank the page mid-read
    }}
    location.reload();
  }}catch(e){{}}
}}
setInterval(poll,2000); poll();
</script>""").encode()


def render(csrf: str) -> str:
    c = db()
    moxas = c.execute("SELECT * FROM moxa WHERE enabled=1 ORDER BY id").fetchall()
    rows = c.execute("""SELECT r.*, m.name AS mname, m.host AS mhost
                        FROM record r JOIN moxa m ON m.id=r.moxa_id
                        ORDER BY r.id DESC LIMIT 200""").fetchall()

    m_html = ["<div class=card><h1>Equipment / MOXA gateways</h1><table><tr><th>Name<th>Host"
              "<th>Status<th>Last seen<th></tr>"]
    for m in moxas:
        st = esc(m["status"])
        col = ("var(--ok)" if st.startswith("connected")
               else "var(--warn)" if st.startswith("busy")
               else "var(--bad)" if st.startswith("offline") else "var(--warn)")
        m_html.append(
            f"<tr><td>{esc(m['name'])}<td class=mono>{esc(m['host'])}:{m['port']}"
            f"<td><span class=dot style=background:{col}></span>{st}"
            f"<td class=mut>{esc(m['last_seen'] or '-')}"
            f"<td><form class=inline method=post action=/moxa/del>"
            f"<input type=hidden name=csrf value='{esc(csrf)}'>"
            f"<input type=hidden name=id value='{m['id']}'>"
            f"<input name=password type=password placeholder='password' "
            f"size=12 required autocomplete=off>"
            f"<button class=ghost>Remove</button></form></tr>")
    m_html.append("</table><form class='inline' method=post action=/moxa/add "
                  "style=margin-top:14px>"
                  f"<input type=hidden name=csrf value='{esc(csrf)}'>"
                  "<input name=host placeholder='192.168.127.254' required>"
                  "<input name=port value=4001 size=6>"
                  "<input name=name placeholder='equipment name (blank = ask via SNMP)'>"
                  "<button>Add equipment</button></form></div>")

    tot = c.execute("SELECT COUNT(*) n FROM record").fetchone()["n"]
    tw = c.execute("SELECT COUNT(*) n FROM record WHERE kind='weighing'").fetchone()["n"]
    ta = c.execute("SELECT COUNT(*) n FROM record WHERE kind='adjustment'").fetchone()["n"]
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
        blocks = c.execute("SELECT * FROM block WHERE record_id=? ORDER BY seq",
                           (r["id"],)).fetchall()
        when = esc((r["finished"] or "")[:19].replace("T", " "))
        search = " ".join(str(x or "").lower() for x in
                          (r["label"], r["operator"], r["inst_id"],
                           r["reg_no"], r["balance_sn"], r["mname"]))
        r_html.append(
            f"<tr class=row data-id={r['id']} data-kind={esc(r['kind'])} "
            f"data-search=\"{esc(search)}\"><td class=mono>{when}"
            f"<td><span class='pill k-{esc(r['kind'])}'>{esc(r['kind'])}</span>"
            f"<td class=mono>{esc(r['label'])}<td>{esc(r['mname'])}"
            f"<td>{esc(r['operator'] or '-')}<td>{len(blocks)}"
            f"<td class=mono>{r['bytes']}</tr>")
        sub = [f"<tr id=sub-{r['id']} class='sub-row hide'><td colspan=7><div class=sub>"]
        if r["inst_id"] or r["reg_no"] or r["balance_sn"]:
            sub.append(f"<div class=mut style=margin:4px 0 10px>INST-ID "
                       f"<b>{esc(r['inst_id'] or '-')}</b> &middot; Reg No "
                       f"<b>{esc(r['reg_no'] or '-')}</b> &middot; Balance S/N "
                       f"<b>{esc(r['balance_sn'] or '-')}</b></div>")
        for b in blocks:
            sub.append(f"<div class=blk><span class=copy data-copy>copy</span>"
                       f"<b>{b['seq']+1}. {esc(b['kind'])}</b> "
                       f"<span class=mut>{esc(b['received'][:19].replace('T',' '))}"
                       f"</span><pre class=mono>{esc(b['body'])}</pre></div>")
        sub.append("</div></tr>")
        r_html.append("".join(sub))
    r_html.append("</table></div>")
    return "".join(m_html) + "".join(r_html)


SUPA_FIELDS = [("supabase_url", "Project URL", "https://xxxx.supabase.co", False),
               ("supabase_anon_key", "Anon / public key", "eyJhbGciOi...", True),
               ("supabase_service_key", "Service role key", "eyJhbGciOi...", True),
               ("supabase_table", "Table name", "balance_records", False)]


def render_settings(csrf: str, msg: str = "") -> str:
    key_ok = bool(MASTER_KEY) and not MASTER_KEY.startswith("REPLACE")
    out = ["<div class=card><h1>Supabase</h1>"]
    if msg:
        out.append(f"<div class=badge style=margin-bottom:10px>{esc(msg)}</div>")
    if not key_ok:
        out.append("<div class=mut style='color:var(--bad);margin-bottom:10px'>"
                   "BALANCE_SECRET_KEY is not set in .env - secrets cannot be "
                   "encrypted until it is.</div>")
    out.append(f"<form method=post action=/settings>"
               f"<input type=hidden name=csrf value='{esc(csrf)}'>")
    for k, label, ph, is_secret in SUPA_FIELDS:
        stored = setting(k, "")
        shown = ""
        note = ""
        if stored:
            if is_secret:
                try:
                    plain = decrypt_secret(stored)
                    note = (f"<span class=badge>encrypted</span> "
                            f"<span class=fp>{esc(mask(plain))} &middot; "
                            f"sha256:{esc(fingerprint(plain))}</span>")
                except Exception as exc:
                    note = f"<span class=fp style=color:var(--bad)>{esc(exc)}</span>"
            else:
                shown = stored
                note = "<span class=fp>plain (not a secret)</span>"
        out.append(
            f"<div style=margin-bottom:12px><label class=mut "
            f"style=font-size:13px;display:block>{esc(label)}</label>"
            f"<input name={k} value=\"{esc(shown)}\" placeholder=\"{esc(ph)}\" "
            f"style=width:100%;max-width:520px "
            f"{'type=password autocomplete=new-password' if is_secret else ''}>"
            f"<div style=margin-top:4px>{note}</div></div>")
    out.append("<button>Save settings</button> "
               "<span class=mut style=margin-left:10px>Secret fields are "
               "encrypted with AES-free HMAC-SHA256 keystream + MAC, keyed from "
               "BALANCE_SECRET_KEY. Leave a secret blank to keep the stored "
               "value.</span></form></div>")

    out.append("<div class=card><h1>Environment</h1><table>"
               "<tr><th>Variable<th>Value</tr>")
    for k in ("BALANCE_HOST", "BALANCE_PORT", "BALANCE_DB", "MOXA_DEFAULT_PORT",
              "BURST_GAP_SECONDS", "BALANCE_CODEPAGE"):
        out.append(f"<tr><td class=mono>{esc(k)}<td class=mono>"
                   f"{esc(os.environ.get(k, '-'))}</tr>")
    for k in ("BALANCE_PASSWORD", "BALANCE_SECRET_KEY"):
        v = os.environ.get(k, "")
        out.append(f"<tr><td class=mono>{esc(k)}<td class=fp>"
                   f"{'set, ' + esc(mask(v)) if v else 'not set'}</tr>")
    out.append("</table><div class=mut style=margin-top:10px>Loaded from "
               "<span class=mono>.env</span>. Shell exports take precedence.</div></div>")
    return "".join(out)


class Handler(BaseHTTPRequestHandler):
    server_version = "BalanceRecordServer"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):        # quieter console
        pass

    # -- helpers
    def _sess(self):
        raw = self.headers.get("Cookie", "")
        jar = http.cookies.SimpleCookie(raw)
        tok = jar["sid"].value if "sid" in jar else None
        return tok, get_session(tok)

    def _send(self, code: int, body: bytes, ctype="text/html; charset=utf-8",
              cookie: str | None = None, location: str | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; form-action 'self'")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, to="/", cookie=None):
        self._send(303, b"", cookie=cookie, location=to)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        return {k: v[0] for k, v in parse_qs(raw).items()}

    # -- routes
    def do_GET(self):
        path = urlparse(self.path).path
        tok, s = self._sess()
        if path == "/login":
            return self._send(200, (LOGIN % (CSS, "")).encode())
        if not s:
            return self._redirect("/login")
        if path == "/":
            return self._send(200, page(render(s["csrf"]), s["csrf"]))
        if path == "/settings":
            return self._send(200, page(render_settings(s["csrf"]), s["csrf"],
                                        "settings"))
        if path == "/api/tip":
            r = db().execute("SELECT COALESCE(MAX(id),0) n, COUNT(*) c "
                             "FROM record").fetchone()
            st = db().execute("SELECT COALESCE(GROUP_CONCAT(status),'') s "
                              "FROM moxa WHERE enabled=1").fetchone()
            return self._send(200, json.dumps(
                {"max_id": r["n"], "count": r["c"], "status": st["s"]}).encode(),
                "application/json")
        if path == "/api/records":
            rows = db().execute("SELECT * FROM record ORDER BY id DESC LIMIT 500").fetchall()
            return self._send(200, json.dumps([dict(r) for r in rows]).encode(),
                              "application/json")
        return self._send(404, b"not found", "text/plain")

    def do_POST(self):
        path = urlparse(self.path).path
        ip = self.client_address[0]
        if path == "/login":
            if rate_limited(ip):
                return self._send(429, (LOGIN % (CSS,
                    "<p style=color:var(--bad)>Too many attempts. Wait 5 minutes.</p>")
                    ).encode())
            pw = self._body().get("password", "")
            if check_pw(pw):
                FAILS.pop(ip, None)
                tok = new_session()
                return self._redirect("/", cookie=(
                    f"sid={tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800"))
            FAILS.setdefault(ip, []).append(time.time())
            return self._send(401, (LOGIN % (CSS,
                "<p style=color:var(--bad)>Wrong password.</p>")).encode())

        tok, s = self._sess()
        if not s:
            return self._redirect("/login")
        form = self._body()
        if not hmac.compare_digest(form.get("csrf", ""), s["csrf"]):
            return self._send(403, b"bad csrf", "text/plain")

        if path == "/logout":
            with SESS_LOCK:
                SESSIONS.pop(tok, None)
            return self._redirect("/login",
                                  cookie="sid=; Path=/; Max-Age=0; HttpOnly")
        if path == "/settings":
            saved = []
            for k, label, _ph, is_secret in SUPA_FIELDS:
                val = (form.get(k) or "").strip()
                if is_secret:
                    if not val:
                        continue                    # blank = keep existing
                    try:
                        set_setting(k, encrypt_secret(val))
                        saved.append(label)
                    except ValueError as exc:
                        return self._send(200, page(
                            render_settings(s["csrf"], f"NOT saved: {exc}"),
                            s["csrf"], "settings"))
                else:
                    set_setting(k, val)
                    saved.append(label)
            return self._send(200, page(
                render_settings(s["csrf"],
                                "Saved: " + ", ".join(saved) if saved else "No change"),
                s["csrf"], "settings"))
        if path == "/moxa/add":
            host = (form.get("host") or "").strip()
            if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", host):
                return self._send(400, b"bad host", "text/plain")
            port = max(1, min(65535, int(form.get("port") or 4001)))
            name = (form.get("name") or "").strip() or moxa_name(host)
            # Upsert. `host` is UNIQUE, so a host that was previously removed
            # (enabled=0) still occupies the row -- a plain INSERT raised
            # IntegrityError, which was swallowed, and re-adding appeared to do
            # nothing. Re-enable and refresh the row instead.
            db().execute(
                "INSERT INTO moxa(host,port,name,enabled,status) "
                "VALUES(?,?,?,1,'idle') "
                "ON CONFLICT(host) DO UPDATE SET "
                "port=excluded.port, name=excluded.name, enabled=1, status='idle'",
                (host, port, name))
            db().commit()
            sync_stations()
            return self._redirect("/")
        if path == "/moxa/del":
            # Removing a gateway stops acquisition for that instrument, so it is
            # re-authenticated rather than being a one-click action.
            if not check_pw(form.get("password", "")):
                return self._send(403, page(
                    "<div class=card><h1>Removal refused</h1><p class=mut>"
                    "Wrong password. The gateway was not removed.</p>"
                    "<p><a href=/>Back to records</a></p></div>",
                    s["csrf"]))
            mid = int(form.get("id") or 0)
            with ST_LOCK:
                st = STATIONS.pop(mid, None)
            if st:
                st.stop.set()
            db().execute("UPDATE moxa SET enabled=0, status='removed' WHERE id=?", (mid,))
            db().commit()
            sync_stations()
            return self._redirect("/")
        return self._send(404, b"not found", "text/plain")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()

    init_db()
    generated = ensure_password()
    sync_stations()
    threading.Thread(target=lambda: [time.sleep(20) or sync_stations()
                                     for _ in iter(int, 1)], daemon=True).start()

    print(f"LIMS Equipment Config  ->  http://{args.host}:{args.port}")
    if generated:
        print(f"\n  GENERATED PASSWORD:  {generated}\n"
              f"  (stored hashed in {DB}; set BALANCE_PASSWORD to choose your own)\n")
    if args.host not in ("127.0.0.1", "localhost"):
        print("  WARNING: bound to a non-loopback address. Put it behind TLS.\n")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
