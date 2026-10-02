"""Attach the migrated Authy codes to existing Bitwarden logins.

Run it yourself, in a terminal where the vault is unlocked (BW_SESSION set):

  python3 bw_match.py index   # writes vault_index.json: names, usernames, hosts. No passwords.
  python3 bw_match.py apply   # applies mapping.json: sets the authenticator key on each matched
                              # login, creates a new login in "Authy import" for the rest.

mapping.json is {authy unique_id: bitwarden item id | "new" | "skip"}.
Nothing here prints or writes a password or a seed.
"""
import json, os, subprocess, sys
from pathlib import Path
from urllib.parse import quote, urlparse

HERE = Path(__file__).parent
FOLDER = "Authy import"


def bw(*args, stdin=None):
    r = subprocess.run(["bw", *args, "--nointeraction"], input=stdin, capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"bw {args[0]} {args[1] if len(args) > 1 else ''} failed: {r.stderr.strip()}")
    return r.stdout


def write_private(name, obj):
    fd = os.open(HERE / name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, indent=1)


def otpauth(t):
    seed = "".join(c for c in t["decrypted_seed"] if c not in " =-").upper()
    uri = f"otpauth://totp/{quote(t['name'])}?secret={seed}"
    if t.get("issuer"):
        uri += f"&issuer={quote(t['issuer'])}"
    return uri + f"&digits={t.get('digits') or 6}&period=30"


def index():
    bw("sync")
    folders = {f["id"]: f["name"] for f in json.loads(bw("list", "folders"))}
    out = []
    for it in json.loads(bw("list", "items")):
        if it.get("type") != 1:
            continue
        login = it.get("login") or {}
        hosts = sorted({urlparse(u["uri"]).hostname or u["uri"] for u in login.get("uris") or [] if u.get("uri")})
        out.append({"id": it["id"], "name": it["name"], "username": login.get("username"), "hosts": hosts,
                    "has_totp": bool(login.get("totp")), "folder": folders.get(it.get("folderId"))})
    write_private("vault_index.json", out)
    print(f"Indexed {len(out)} logins -> vault_index.json (no passwords)")


def apply():
    tokens = {str(t["unique_id"]): t for t in
              json.loads((HERE / "decrypted_tokens.json").read_text())["decrypted_authenticator_tokens"]}
    mapping = json.loads((HERE / "mapping.json").read_text())
    bw("sync")  # see anything a failed earlier run did create
    folder_id = next((f["id"] for f in json.loads(bw("list", "folders")) if f["name"] == FOLDER), None)
    # Re-runs must not duplicate: remember what the import folder already holds.
    existing = {i["name"] for i in json.loads(bw("list", "items", "--folderid", folder_id))} if folder_id else set()
    done = made = skipped = 0
    for uid, target in mapping.items():
        t = tokens[uid]
        if target == "skip":
            skipped += 1
            continue
        if target == "new":
            if folder_id is None:
                folder_id = json.loads(bw("create", "folder", stdin=bw("encode", stdin=json.dumps({"name": FOLDER}))))["id"]
            title = t["name"] if not t.get("issuer") or t["issuer"].lower() in t["name"].lower() else f"{t['issuer']} ({t['name']})"
            if title in existing:
                print(f"  exists   {title}")
                skipped += 1
                continue
            item = {"type": 1, "name": title, "folderId": folder_id, "notes": "Migrated from Authy 2026-10-02",
                    "login": {"totp": otpauth(t)}}
            bw("create", "item", stdin=bw("encode", stdin=json.dumps(item)))
            made += 1
            print(f"  new      {title}")
            continue
        item = json.loads(bw("get", "item", target))
        if item["login"].get("totp"):
            print(f"  KEPT     {item['name']}: already has an authenticator key, left alone ({t['name']})")
            skipped += 1
            continue
        item["login"]["totp"] = otpauth(t)
        bw("edit", "item", target, stdin=bw("encode", stdin=json.dumps(item)))
        done += 1
        print(f"  attached {t['name']}  ->  {item['name']}")
    bw("sync")
    print(f"attached {done}, created {made}, skipped {skipped}")


if not os.environ.get("BW_SESSION"):
    sys.exit('Vault is locked for this shell. Run:  export BW_SESSION="$(bw unlock --raw)"')
{"index": index, "apply": apply}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: sys.exit(__doc__))()
