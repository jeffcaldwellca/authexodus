#!/bin/sh
# Stand-in for the `bw` binary in tests. Records its arguments, answers from fixtures.
DIR="$(dirname "$0")"
echo "$@" >> "$DIR/args.log"
env >> "$DIR/env.full"
echo "appdata=$BITWARDENCLI_APPDATA_DIR session=${BW_SESSION:-none} pw=${BW_PASSWORD:-none} cid=${BW_CLIENTID:-none} sec=${BW_CLIENTSECRET:-none} resp=${BW_RESPONSE:-none}" >> "$DIR/env.log"
case "$1" in
  logout) exit 0 ;;
  config) exit 0 ;;
  login)
    if [ "$AUTHEXODUS_BW_PASSWORD" != "correct horse" ]; then
      echo "Invalid master password. Confirm your email is correct and your account was created on vault.bitwarden.com." >&2; exit 1
    fi
    # The messages below are the ones CLI 2026.9.1 prints (read from its source), except the
    # wrong-code one, which is the server's wording as assumed in cli.rs.
    if [ -f "$DIR/noproviders" ]; then echo "No providers available for this client." >&2; exit 1; fi
    case "$*" in
      *--code*)
        if [ -f "$DIR/wrong2fa" ]; then echo "Two-step token is invalid. Try again." >&2; exit 1; fi
        if [ -f "$DIR/askedagain" ]; then echo "Login failed." >&2; exit 1; fi
        if [ -f "$DIR/devicecheck" ]; then echo "Code is required." >&2; exit 1; fi
        if [ -f "$DIR/noauthapp" ]; then echo "Login failed. No provider selected." >&2; exit 1; fi
        ;;
      *)
        if [ -f "$DIR/needs2fa" ] || [ -f "$DIR/devicecheck" ]; then echo "Code is required." >&2; exit 1; fi
        if [ -f "$DIR/manymethods" ] || [ -f "$DIR/noauthapp" ]; then echo "Login failed. No provider selected." >&2; exit 1; fi
        ;;
    esac
    echo "SESSIONKEYFROMLOGIN"; exit 0 ;;
  unlock) echo "fake-session-key"; exit 0 ;;
  list)
    case "$2" in
      items) if [ "$3" = "--folderid" ]; then cat "$DIR/import_folder_items.json"; else cat "$DIR/list_items.json"; fi ;;
      folders) if [ -f "$DIR/odd_folder_id" ]; then echo '[{"object":"folder","id":"--pretty","name":"Authy import"}]'; elif [ -f "$DIR/no_import_folder" ]; then echo '[]'; else cat "$DIR/list_folders.json"; fi ;;
    esac
    exit 0 ;;
  get)
    if [ -f "$DIR/item_has_same_code" ]; then T='"otpauth://totp/renamed%20since?issuer=Someone&secret=jbsw%20y3dp-ehpk3pxp"'
    elif [ -f "$DIR/item_has_code" ]; then T='"otpauth://totp/old?secret=AAAA"'; else T=null; fi
    echo '{"object":"item","id":"'"$3"'","type":1,"name":"Some Login","login":{"username":"u","password":"p","totp":'"$T"'}}'; exit 0 ;;
  encode) cat > "$DIR/encode.in"; echo "ENCODEDJSON"; exit 0 ;;
  edit) cat > "$DIR/edit.stdin"; exit 0 ;;
  create)
    cat > "$DIR/create.stdin"
    if [ -f "$DIR/odd_new_id" ]; then echo '{"id":"--organizationid"}'; else echo '{"id":"22222222-0000-4000-8000-00000000000a"}'; fi
    exit 0 ;;
  sync) if [ -f "$DIR/locked" ]; then echo "Vault is locked." >&2; exit 1; fi; echo "Syncing complete."; exit 0 ;;
esac
echo "unexpected: $*" >&2; exit 1
