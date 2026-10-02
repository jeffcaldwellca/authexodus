"""Convert decrypted_tokens.json into a Bitwarden CSV import. Prints names only."""
import base64, collections, csv, json, os, re
from pathlib import Path
from urllib.parse import quote

HERE = Path(__file__).parent
tokens = json.loads((HERE / "decrypted_tokens.json").read_text())["decrypted_authenticator_tokens"]
rows, bad = [], []
for x in tokens:
    seed = re.sub(r"[\s=-]", "", x["decrypted_seed"]).upper()
    try:
        assert len(base64.b32decode(seed + "=" * (-len(seed) % 8))) >= 10
    except Exception:
        bad.append(x["name"])
        continue
    name, issuer, digits = x["name"], x.get("issuer") or "", x.get("digits") or 6
    user = ""
    if ": " in name:
        user = name.split(": ", 1)[1]
    elif re.fullmatch(r"\S+@\S+", name):
        user = name
    # Authy drops the issuer on many tokens but keeps a logo slug naming the service.
    logo = x.get("logo") or ""
    if not issuer and logo and not logo.startswith("authenticator") and logo.split()[0].lower() not in name.lower():
        issuer = logo.title()
    title = name if (not issuer or issuer.lower() in name.lower()) else f"{issuer} ({name})"
    uri = f"otpauth://totp/{quote(name)}?secret={seed}"
    if issuer:
        uri += f"&issuer={quote(issuer)}"
    uri += f"&digits={digits}&period=30"
    rows.append(["Authy import", "", "login", title, "Migrated from Authy 2026-10-02", "", "", "", user, "", uri])
    print("  " + title + ("" if issuer else f"   [logo: {x.get('logo')}]"))

fd = os.open(HERE / "bitwarden_import.csv", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp".split(","))
    w.writerows(rows)
print("decrypted:", len(tokens), "| written:", len(rows), "| bad:", bad)
print("duplicate titles:", [k for k, v in collections.Counter(r[3] for r in rows).items() if v > 1])
