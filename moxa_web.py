"""Minimal client for the NPort 5150 web console.

The login page hands out a per-load `FakeChallenge` and hashes the password
in JavaScript. Reimplemented here so we can read the pages that actually
matter for debugging -- above all Monitor -> Async, which shows the TX and RX
byte counters for the serial port. Those counters are the ground truth for
"did any byte ever arrive from the balance".

Read-only by default. `set-baud` writes, and asks first.
"""

import argparse
import hashlib
import re
import sys
import time
import urllib.parse
import urllib.request

HOST = "192.168.127.254"
PASSWORD = "moxa"
HEXD = "0123456789abcdef"


def md5_hex(text: str) -> str:
    return hashlib.md5(text.encode("latin-1")).hexdigest()


def encode_password(password: str, challenge: str) -> str:
    """Port of SetPass() from the NPort login page."""
    m = md5_hex(challenge)                                  # MD5 of the challenge
    w = "".join(format(ord(c), "x") for c in password)      # password bytes as hex
    p = "".join(HEXD[HEXD.index(a) ^ HEXD.index(b)] for a, b in zip(w, m))
    return md5_hex(p)


class NPort:
    def __init__(self, host: str = HOST, password: str = PASSWORD):
        self.host = host
        self.password = password
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor()
        )

    def _get(self, path: str, timeout: float = 10.0) -> str:
        url = f"http://{self.host}/{path.lstrip('/')}"
        with self.opener.open(url, timeout=timeout) as resp:
            return resp.read().decode("latin-1")

    def _login_once(self) -> bool:
        root = self._get("/")
        match = re.search(r'set\("FakeChallenge","([0-9A-Fa-f]+)"\)', root)
        if not match:
            # Some firmware builds skip the password page entirely.
            return "Input password" not in root
        challenge = match.group(1)
        enc = encode_password(self.password, challenge)
        query = urllib.parse.urlencode(
            {
                "token_text": "",
                "FakeChallenge": challenge,
                "EncPasswd": enc,
                "Submit": "Submit",
            }
        )
        page = self._get(f"/home.htm?{query}")
        if "Input password" in page:
            return False
        # home.htm is only a frameset; it renders even when the session was
        # not really granted. Confirm against a page with real content.
        return "Input password" not in self._get("Mn_asyn.htm")

    def login(self, attempts: int = 3) -> bool:
        """The NPort 5150 allows only ONE web console session at a time.

        If the console is open in a browser, that session and this one keep
        evicting each other. Retry a few times, then say so plainly.
        """
        for n in range(attempts):
            try:
                if self._login_once():
                    return True
            except Exception:
                pass
            time.sleep(0.6 * (n + 1))
        return False

    def page(self, path: str) -> str:
        return self._get(path)


def strip_html(html: str) -> str:
    html = re.sub(r"(?is)<script.*?</script>", " ", html)
    html = re.sub(r"(?is)<style.*?</style>", " ", html)
    html = re.sub(r"(?s)<[^>]+>", " ", html)
    html = html.replace("&nbsp;", " ").replace("&amp;", "&")
    return re.sub(r"[ \t]{2,}", "  ", re.sub(r"\n\s*\n+", "\n", html)).strip()


# Candidate URLs for the async monitor page across firmware revisions.
MONITOR_PAGES = [
    "MonitorAsync.htm",
    "MonitorAsyncSetting.htm",
    "Async.htm",
    "MonitorLine.htm",
    "MonitorAsync.asp",
    "Monitor.htm",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["login", "monitor", "serial", "dump"])
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--password", default=PASSWORD)
    ap.add_argument("--path", help="page to fetch for `dump`")
    args = ap.parse_args()

    np = NPort(args.host, args.password)
    if not np.login():
        print("LOGIN FAILED - wrong password, or firmware uses a scheme we don't handle.")
        return 1
    print("Logged in to NPort web console.")

    if args.command == "login":
        return 0

    if args.command == "dump":
        print(strip_html(np.page(args.path)))
        return 0

    if args.command == "serial":
        for path in ("SerialSettings.htm", "OpModeSettings.htm", "Serial.htm"):
            try:
                body = strip_html(np.page(path))
            except Exception:
                continue
            if body and "Input password" not in body:
                print(f"\n===== {path} =====")
                print(body[:1500])
        return 0

    # monitor
    for path in MONITOR_PAGES:
        try:
            body = np.page(path)
        except Exception as exc:
            print(f"{path}: {exc}")
            continue
        text = strip_html(body)
        if not text or "Input password" in text:
            continue
        print(f"\n===== {path} =====")
        print(text[:2000])
    return 0


if __name__ == "__main__":
    sys.exit(main())
