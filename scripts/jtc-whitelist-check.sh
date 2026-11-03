#!/bin/sh
# jtc-whitelist-check.sh — early warning for the no-OTP provisioning path.
#
# The bridge's rotating-password fetch (register.sh -> jfc_configure.py with nwk_intf=eth,
# i.e. --no-otp) only works while your router reports JTCAutoWhitelist=true. That flag is set
# by the router's IMS stack (libims.so), reflects a Jio-side policy, and can change without
# warning. If it flips to false, new credential fetches stop auto-whitelisting and the bridge
# can no longer (re-)register without running the OTP add-device flow again.
#
# This checks the flag via the router's local discovery endpoint and exits non-zero (and
# optionally ntfy-alerts) if it is anything other than "true". Run it from any host that can
# reach the router on the LAN; cron/systemd-timer it for a standing early warning.
#
#   ROUTER=192.168.29.1 ./jtc-whitelist-check.sh
#   NTFY=https://ntfy.sh/your-topic ROUTER=192.168.29.1 ./jtc-whitelist-check.sh
#
# Only the flag is read/printed — the /request_account response also contains your IMSI/MSISDN,
# which this script never emits.
set -u
ROUTER="${ROUTER:-192.168.29.1}"   # default JioFiber gateway
PORT="${PORT:-8080}"               # JUICE local HTTP (binds the LAN IP, not loopback)
NTFY="${NTFY:-}"                   # optional ntfy topic URL for alerts

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -s -m 8 "http://${ROUTER}:${PORT}/request_account"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- -T 8 "http://${ROUTER}:${PORT}/request_account"
  else
    # busybox fallback (some routers' wget segfaults; nc is reliable)
    printf 'GET /request_account HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$ROUTER" \
      | { command -v nc >/dev/null 2>&1 && nc "$ROUTER" "$PORT" || busybox nc "$ROUTER" "$PORT"; }
  fi
}

body="$(fetch 2>/dev/null)"
if [ -z "$body" ]; then
  echo "jtc-whitelist-check: cannot reach router at ${ROUTER}:${PORT}" >&2
  exit 2   # unreachable — treat as "unknown", not a flip
fi

val="$(printf '%s' "$body" | sed -n 's/.*"JTCAutoWhitelist": *"\([A-Za-z]*\)".*/\1/p' | head -1)"
[ -z "$val" ] && val="absent"

if [ "$val" = "true" ]; then
  echo "JTCAutoWhitelist=true (no-OTP cred path OK)"
  exit 0
fi

msg="JTCAutoWhitelist=${val} on ${ROUTER} — the no-OTP rotating-password fetch will stop working; new device adds will need the OTP flow."
echo "jtc-whitelist-check: $msg" >&2
[ -n "$NTFY" ] && curl -s -m 8 -H "Title: JioFiber whitelist flipped" -H "Priority: urgent" -d "$msg" "$NTFY" >/dev/null 2>&1
exit 1
