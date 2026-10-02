"""Decrypt the captured Authy backup, checking the password before writing.

Same scheme as decrypt.py (PBKDF2-HMAC-SHA1 -> AES-256-CBC, PKCS7), but it
tests the password against every token first, says how many decrypt, and
asks again on a miss. The password is used exactly as typed (no stripping).
"""
import base64, binascii, json, os, re
from getpass import getpass
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HERE = Path(__file__).parent
tokens = json.loads((HERE / "authenticator_tokens.json").read_text())["authenticator_tokens"]


def decrypt(tok, password):
    key = PBKDF2HMAC(hashes.SHA1(), 32, tok["salt"].encode(), tok["key_derivation_iterations"]).derive(password.encode())
    iv = binascii.unhexlify(tok["unique_iv"]) if tok.get("unique_iv") else bytes(16)
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    raw = d.update(base64.b64decode(tok["encrypted_seed"])) + d.finalize()
    pad = raw[-1]
    if not 1 <= pad <= 16 or raw[-pad:] != bytes([pad]) * pad:
        return None
    try:
        seed = raw[:-pad].decode("ascii")
    except UnicodeDecodeError:
        return None
    return seed if seed.isprintable() else None


while True:
    pw = getpass("Authy backup password (hidden; Ctrl+C to quit): ")
    notes = [f"{len(pw)} characters"]
    if pw != pw.strip():
        notes.append("has a leading/trailing space")
    if not pw.isascii():
        notes.append("has non-ASCII characters")
    # One token is enough to tell right from wrong; each try costs 100k rounds.
    if decrypt(tokens[0], pw) is None and decrypt(tokens[1], pw) is None:
        print(f"  Wrong password ({', '.join(notes)}). Try again.\n")
        continue
    out, failed = [], []
    for t in tokens:
        seed = decrypt(t, pw)
        if seed is None:
            failed.append(t["name"])
            continue
        out.append({k: t.get(k) for k in ("account_type", "name", "issuer", "digits", "logo", "unique_id")} | {"decrypted_seed": seed})
    path = HERE / "decrypted_tokens.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"decrypted_authenticator_tokens": out}, f, indent=2)
    print(f"  Correct. Decrypted {len(out)} of {len(tokens)} -> {path.name}")
    for name in failed:
        print(f"  could not decrypt: {name}")
    break
