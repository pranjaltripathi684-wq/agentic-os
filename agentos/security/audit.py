"""
Tamper-evident audit log.

Every event is one JSON line. Each line stores the hash of the line before it
("prev") and its own hash, computed over its contents plus prev:

    seq 1: {..., "prev": "000...0", "hash": H1}      H1 = sha256("000...0" + entry1)
    seq 2: {..., "prev": H1,        "hash": H2}      H2 = sha256(H1 + entry2)
    seq 3: {..., "prev": H2,        "hash": H3}

Change one character in entry 2 and its hash no longer matches; fix that
hash and entry 3's "prev" no longer matches. `agentos audit verify` walks the
chain and names the first broken entry. Same idea as Git commits and blockchains.

A hash chain alone can't stop someone who rewrites the WHOLE file from the
edit onwards. Checkpoints fix that: `agentos audit checkpoint` signs the
latest hash with an Ed25519 private key kept in ~/.agentos/keys. A rewritten
chain won't match the signed hash, and forging a new signature needs the key.
(Someone with your user account can read that key, so for real-world use
you'd copy checkpoints off the machine, e.g. email them to yourself.)
"""

import fcntl
import hashlib
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone

from .. import config
from .redact import redact_obj

GENESIS = "0" * 64
_lock = threading.Lock()


def canonical(entry: dict) -> str:
    """One exact text form per entry (sorted keys, no spaces), so hashes are reproducible."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256((body["prev"] + canonical(body)).encode()).hexdigest()


def _last_line(f) -> str:
    """Read the last non-empty line without loading the whole file."""
    f.seek(0, os.SEEK_END)
    pos, buf = f.tell(), b""
    while pos > 0:
        step = min(4096, pos)
        pos -= step
        f.seek(pos)
        buf = f.read(step) + buf
        lines = buf.rstrip(b"\n").split(b"\n")
        if len(lines) > 1 or pos == 0:
            return lines[-1].decode()
    return ""


def log_event(event: str, **fields) -> dict:
    """Append one event to the chain. Secrets in any field are redacted first."""
    path = config.LOG_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = redact_obj(fields) if config.REDACTION else fields
    with _lock, open(path, "a+b") as f:
        fcntl.flock(f, fcntl.LOCK_EX)          # also safe if two agentos processes log at once
        try:
            last = _last_line(f)
            if last:
                prev_entry = json.loads(last)
                seq, prev = prev_entry["seq"] + 1, prev_entry["hash"]
            else:
                seq, prev = 1, GENESIS
            entry = {"seq": seq, "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                     "event": event, **fields, "prev": prev}
            entry["hash"] = entry_hash(entry)
            f.seek(0, os.SEEK_END)
            f.write((json.dumps(entry, ensure_ascii=False) + "\n").encode())
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
    return entry


def read_entries(path=None, last=None):
    path = path or config.LOG_FILE
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        lines = [line for line in f if line.strip()]
    lines = lines[-last:] if last else lines
    return [json.loads(line) for line in lines]


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    bad_seq: int = None
    reason: str = ""
    checkpoints: int = 0


def verify(path=None, checkpoints=None) -> VerifyResult:
    """Walk the whole chain. Returns where and why it breaks, if it does."""
    path = path or config.LOG_FILE
    if not path.exists():
        return VerifyResult(True, 0, reason="no audit log yet")
    prev, hashes, n = GENESIS, {}, 0
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return VerifyResult(False, n, lineno, f"line {lineno} is not valid JSON")
            seq = entry.get("seq")
            if seq != n + 1:
                return VerifyResult(False, n, seq, f"expected entry {n + 1}, found {seq} (deleted or reordered)")
            if entry.get("prev") != prev:
                return VerifyResult(False, n, seq, f"entry {seq} doesn't link to entry {seq - 1} (prev hash differs)")
            if entry_hash(entry) != entry.get("hash"):
                return VerifyResult(False, n, seq, f"entry {seq} was modified (its hash doesn't match its contents)")
            prev, n = entry["hash"], n + 1
            hashes[seq] = prev
    cp_result = _verify_checkpoints(hashes, checkpoints or config.CHECKPOINT_FILE)
    if cp_result:
        return VerifyResult(False, n, cp_result[0], cp_result[1])
    cps = len(read_entries(checkpoints or config.CHECKPOINT_FILE))
    return VerifyResult(True, n, checkpoints=cps)


# ------------------------------------------------------------------ signed checkpoints
def _load_or_create_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key_path = config.AUDIT_KEY
    if key_path.exists():
        return serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # readable only by you
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return key


def _public_hex(key) -> str:
    from cryptography.hazmat.primitives import serialization
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def checkpoint() -> dict:
    """Sign the current head of the chain. Needs the `cryptography` package."""
    entries = read_entries(last=1)
    if not entries:
        raise RuntimeError("the audit log is empty; nothing to checkpoint")
    head = entries[-1]
    key = _load_or_create_key()
    message = f"{head['seq']}:{head['hash']}".encode()
    record = {"seq": head["seq"], "hash": head["hash"],
              "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "public_key": _public_hex(key), "signature": key.sign(message).hex()}
    config.CHECKPOINT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(config.CHECKPOINT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    return record


def _verify_checkpoints(hashes: dict, cp_path):
    """Return (seq, reason) for the first bad checkpoint, or None if all are fine."""
    records = read_entries(cp_path)
    if not records:
        return None
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    trusted_pub = _public_hex(_load_or_create_key()) if config.AUDIT_KEY.exists() else None
    for cp in records:
        if trusted_pub and cp["public_key"] != trusted_pub:
            return cp["seq"], f"checkpoint at entry {cp['seq']} was signed by a different key"
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(cp["public_key"])).verify(
                bytes.fromhex(cp["signature"]), f"{cp['seq']}:{cp['hash']}".encode())
        except (InvalidSignature, ValueError):
            return cp["seq"], f"checkpoint at entry {cp['seq']} has an invalid signature"
        if cp["seq"] not in hashes:
            return cp["seq"], f"log is shorter than signed checkpoint {cp['seq']} (entries were deleted)"
        if hashes[cp["seq"]] != cp["hash"]:
            return cp["seq"], f"entry {cp['seq']} differs from the signed checkpoint (log was rewritten)"
    return None
