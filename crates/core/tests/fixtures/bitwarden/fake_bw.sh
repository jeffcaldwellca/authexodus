#!/bin/sh
# Stand-in for the `bw` binary in tests. Records its arguments, answers from fixtures.
DIR="$(dirname "$0")"
echo "$@" >> "$DIR/args.log"
echo "appdata=$BITWARDENCLI_APPDATA_DIR session=${BW_SESSION:-none} pw=${BW_PASSWORD:-none} cid=${BW_CLIENTID:-none} sec=${BW_CLIENTSECRET:-none} resp=${BW_RESPONSE:-none}" >> "$DIR/env.log"
case "$1" in
  logout) exit 0 ;;
  config) exit 0 ;;
  login)
    if [ "$AUTHEXODUS_BW_PASSWORD" != "correct horse" ]; then
      echo "Invalid master password. Confirm your email is correct and your account was created on vault.bitwarden.com." >&2; exit 1
    fi
    case "$*" in
      *--code*) : ;;
      *) if [ -f "$DIR/needs2fa" ]; then echo "Code is required." >&2; exit 1; fi ;;
    esac
    echo "SESSIONKEYFROMLOGIN"; exit 0 ;;
  unlock) echo "fake-session-key"; exit 0 ;;
  list)
    case "$2" in
      items) if [ "$3" = "--folderid" ]; then cat "$DIR/import_folder_items.json"; else cat "$DIR/list_items.json"; fi ;;
      folders) cat "$DIR/list_folders.json" ;;
    esac
    exit 0 ;;
  get)
    if [ -f "$DIR/item_has_code" ]; then T='"otpauth://totp/old?secret=AAAA"'; else T=null; fi
    echo '{"object":"item","id":"'"$3"'","type":1,"name":"Some Login","login":{"username":"u","password":"p","totp":'"$T"'}}'; exit 0 ;;
  encode) cat > "$DIR/encode.in"; echo "ENCODEDJSON"; exit 0 ;;
  edit) cat > "$DIR/edit.stdin"; exit 0 ;;
  create) cat > "$DIR/create.stdin"; echo '{"id":"new-id"}'; exit 0 ;;
  sync) if [ -f "$DIR/locked" ]; then echo "Vault is locked." >&2; exit 1; fi; echo "Syncing complete."; exit 0 ;;
esac
echo "unexpected: $*" >&2; exit 1
