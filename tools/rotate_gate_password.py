#!/usr/bin/env python3
"""Rotate the client-side password gate on a published HTML artifact.

The artifact's real content is stored in the page as an AES-256-GCM ciphertext
whose key is derived from the gate password with PBKDF2-HMAC-SHA256. Rotating
the password therefore means decrypting the payload and re-encrypting it under a
new password, with a fresh salt and IV.

Passwords are never stored anywhere. Each one is derived on demand from a single
long-lived secret (GATE_MASTER_KEY, a GitHub Actions secret) plus the rotation
index, which is public state:

    password(n) = base32(HMAC-SHA256(master_key, "<artifact>:<n>"))[:16]

That means the workflow can always recover the current password to decrypt, and
anyone holding the master key (this workflow, and Claude via the project's
environment doc) can independently derive the password for any rotation without
it ever being written to a file, a log, or a commit.

Usage:
    rotate_gate_password.py check     # exit 0 if a rotation is due, 3 if not
    rotate_gate_password.py rotate    # rotate if due (--force to rotate anyway)
    rotate_gate_password.py password  # print the current password (local use)
    rotate_gate_password.py bootstrap --plaintext FILE
"""

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
IV_BYTES = 12
PASSWORD_CHARS = 16          # base32 chars -> 80 bits of entropy
PASSWORD_GROUP = 4           # rendered as xxxx-xxxx-xxxx-xxxx

DATA_RE = re.compile(
    r'var DATA=\{salt:"(?P<salt>[^"]+)",iv:"(?P<iv>[^"]+)",'
    r'ct:"(?P<ct>[^"]+)",iter:(?P<iter>\d+)\};'
)


# --------------------------------------------------------------------------- #
# business days
# --------------------------------------------------------------------------- #

def _nth_weekday(year, month, weekday, n):
    d = dt.date(year, month, 1)
    d += dt.timedelta(days=(weekday - d.weekday()) % 7)
    return d + dt.timedelta(weeks=n - 1)


def _last_weekday(year, month, weekday):
    d = dt.date(year, month, 28)
    while (d + dt.timedelta(days=7)).month == month:
        d += dt.timedelta(days=7)
    return d - dt.timedelta(days=(d.weekday() - weekday) % 7)


def us_federal_holidays(year):
    """Observed US federal holidays (weekend holidays shift to Fri/Mon)."""
    fixed = [
        dt.date(year, 1, 1),    # New Year's Day
        dt.date(year, 6, 19),   # Juneteenth
        dt.date(year, 7, 4),    # Independence Day
        dt.date(year, 11, 11),  # Veterans Day
        dt.date(year, 12, 25),  # Christmas Day
    ]
    observed = set()
    for d in fixed:
        if d.weekday() == 5:
            d -= dt.timedelta(days=1)
        elif d.weekday() == 6:
            d += dt.timedelta(days=1)
        observed.add(d)
    observed.update({
        _nth_weekday(year, 1, 0, 3),    # MLK Day
        _nth_weekday(year, 2, 0, 3),    # Presidents' Day
        _last_weekday(year, 5, 0),      # Memorial Day
        _nth_weekday(year, 9, 0, 1),    # Labor Day
        _nth_weekday(year, 10, 0, 2),   # Columbus Day
        _nth_weekday(year, 11, 3, 4),   # Thanksgiving
    })
    return observed


def is_business_day(d):
    return d.weekday() < 5 and d not in us_federal_holidays(d.year)


def business_days_between(start, end):
    """Business days strictly after `start`, up to and including `end`."""
    if end <= start:
        return 0
    count, cur = 0, start + dt.timedelta(days=1)
    while cur <= end:
        if is_business_day(cur):
            count += 1
        cur += dt.timedelta(days=1)
    return count


def add_business_days(start, n):
    cur, added = start, 0
    while added < n:
        cur += dt.timedelta(days=1)
        if is_business_day(cur):
            added += 1
    return cur


# --------------------------------------------------------------------------- #
# password derivation + crypto
# --------------------------------------------------------------------------- #

def master_key():
    raw = os.environ.get("GATE_MASTER_KEY", "").strip()
    if not raw:
        sys.exit("GATE_MASTER_KEY is not set.")
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception:
        sys.exit("GATE_MASTER_KEY is not valid base64.")
    if len(key) < 32:
        sys.exit("GATE_MASTER_KEY must be at least 32 bytes.")
    return key


def derive_password(key, artifact, index):
    mac = hmac.new(key, f"{artifact}:{index}".encode(), hashlib.sha256).digest()
    chars = base64.b32encode(mac).decode().lower().rstrip("=")[:PASSWORD_CHARS]
    return "-".join(
        chars[i:i + PASSWORD_GROUP] for i in range(0, PASSWORD_CHARS, PASSWORD_GROUP)
    )


def derive_aes_key(password, salt, iterations):
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
    ).derive(password.encode())


def decrypt_payload(html, password):
    m = DATA_RE.search(html)
    if not m:
        sys.exit("Could not find the DATA blob in the gate page.")
    salt = base64.b64decode(m.group("salt"))
    iv = base64.b64decode(m.group("iv"))
    ct = base64.b64decode(m.group("ct"))
    key = derive_aes_key(password, salt, int(m.group("iter")))
    return AESGCM(key).decrypt(iv, ct, None).decode("utf-8")


def encrypt_payload(html, plaintext, password):
    salt = secrets.token_bytes(SALT_BYTES)
    iv = secrets.token_bytes(IV_BYTES)
    key = derive_aes_key(password, salt, PBKDF2_ITERATIONS)
    ct = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)
    blob = (
        'var DATA={{salt:"{}",iv:"{}",ct:"{}",iter:{}}};'.format(
            base64.b64encode(salt).decode(),
            base64.b64encode(iv).decode(),
            base64.b64encode(ct).decode(),
            PBKDF2_ITERATIONS,
        )
    )
    updated = DATA_RE.sub(lambda _: blob, html, count=1)
    if updated == html:
        sys.exit("Failed to substitute the DATA blob.")
    return updated


# --------------------------------------------------------------------------- #
# state
# --------------------------------------------------------------------------- #

def load_state(path):
    with open(path) as fh:
        return json.load(fh)


def save_state(path, state):
    with open(path, "w") as fh:
        json.dump(state, fh, indent=2)
        fh.write("\n")


def today():
    override = os.environ.get("ROTATION_TODAY")
    if override:
        return dt.date.fromisoformat(override)
    # The schedule is anchored to the artifact owner's working week.
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=8)).date()


def mask(value):
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::add-mask::{value}")


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #

def cmd_password(args):
    state = load_state(args.state)
    pw = derive_password(master_key(), state["artifact"], state["index"])
    mask(pw)
    print(pw)


def cmd_check(args):
    state = load_state(args.state)
    last = dt.date.fromisoformat(state["last_rotated"])
    elapsed = business_days_between(last, today())
    due = elapsed >= state["interval_business_days"]
    print(
        f"{state['artifact']}: rotation #{state['index']} on {last.isoformat()}, "
        f"{elapsed}/{state['interval_business_days']} business days elapsed, "
        f"next due {state['next_due']} -> {'DUE' if due else 'not due'}"
    )
    sys.exit(0 if due else 3)


def cmd_rotate(args):
    state = load_state(args.state)
    key = master_key()
    now = today()
    last = dt.date.fromisoformat(state["last_rotated"])
    elapsed = business_days_between(last, now)

    if elapsed < state["interval_business_days"] and not args.force:
        print(f"Not due: {elapsed}/{state['interval_business_days']} business days.")
        sys.exit(3)

    with open(args.file) as fh:
        html = fh.read()

    current_pw = derive_password(key, state["artifact"], state["index"])
    mask(current_pw)
    plaintext = decrypt_payload(html, current_pw)

    digest = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
    if state.get("payload_sha256") and state["payload_sha256"] != digest:
        sys.exit("Decrypted payload does not match the recorded checksum.")

    next_index = state["index"] + 1
    next_pw = derive_password(key, state["artifact"], next_index)
    mask(next_pw)

    updated = encrypt_payload(html, plaintext, next_pw)
    if decrypt_payload(updated, next_pw) != plaintext:
        sys.exit("Round-trip verification failed; refusing to write.")

    with open(args.file, "w") as fh:
        fh.write(updated)

    state.update(
        index=next_index,
        last_rotated=now.isoformat(),
        next_due=add_business_days(now, state["interval_business_days"]).isoformat(),
        payload_sha256=digest,
    )
    save_state(args.state, state)

    print(f"Rotated to #{next_index}. Next rotation due {state['next_due']}.")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as fh:
            fh.write("rotated=true\n")
            fh.write(f"index={next_index}\n")
            fh.write(f"next_due={state['next_due']}\n")


def cmd_bootstrap(args):
    key = master_key()
    now = today()
    with open(args.file) as fh:
        html = fh.read()
    with open(args.plaintext) as fh:
        plaintext = fh.read()

    artifact = args.artifact
    index = 1
    pw = derive_password(key, artifact, index)
    mask(pw)

    updated = encrypt_payload(html, plaintext, pw)
    if decrypt_payload(updated, pw) != plaintext:
        sys.exit("Round-trip verification failed; refusing to write.")

    with open(args.file, "w") as fh:
        fh.write(updated)

    save_state(args.state, {
        "artifact": artifact,
        "index": index,
        "last_rotated": now.isoformat(),
        "next_due": add_business_days(now, args.interval).isoformat(),
        "interval_business_days": args.interval,
        "payload_sha256": hashlib.sha256(plaintext.encode("utf-8")).hexdigest(),
        "note": "Public rotation state. Contains no secrets; the password is derived from GATE_MASTER_KEY plus the index above.",
    })
    print(f"Bootstrapped {artifact} at rotation #{index}.")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--file", default="rfp-assessment-calculator/index.html")
    p.add_argument("--state", default=".gate-rotation/rfp-assessment-calculator.json")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("check").set_defaults(func=cmd_check)
    sub.add_parser("password").set_defaults(func=cmd_password)

    r = sub.add_parser("rotate")
    r.add_argument("--force", action="store_true")
    r.set_defaults(func=cmd_rotate)

    b = sub.add_parser("bootstrap")
    b.add_argument("--plaintext", required=True)
    b.add_argument("--artifact", default="rfp-assessment-calculator")
    b.add_argument("--interval", type=int, default=10)
    b.set_defaults(func=cmd_bootstrap)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
