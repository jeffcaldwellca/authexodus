"""mitmproxy addon: save Authy's encrypted token backup the moment it passes.

Writes the response holding "authenticator_tokens" to authenticator_tokens.json
and, if seen, the Authy-native app list to authy_apps.json. The log records
only method, path and status: query strings and bodies carry credentials.
"""
import os
from pathlib import Path

from mitmproxy import http

OUT = Path(__file__).parent


def _write(name: str, data: bytes) -> None:
    path = OUT / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def response(flow: http.HTTPFlow) -> None:
    if "authy.com" not in flow.request.pretty_host:
        return
    body = flow.response.content or b""
    path = flow.request.path.split("?")[0]
    saved = ""
    if b'"authenticator_tokens"' in body:
        _write("authenticator_tokens.json", body)
        saved = " -> saved authenticator_tokens.json"
    elif path.endswith("/apps") or b'"secret_seed"' in body:
        _write("authy_apps.json", body)
        saved = " -> saved authy_apps.json"
    with open(OUT / "capture.log", "a") as log:
        log.write(f"{flow.request.method} {path} {flow.response.status_code} {len(body)}B{saved}\n")
