#!/bin/bash
# Bridge start wrapper. Run inside a UTS namespace so pj_gethostname()==DEVICE_HOST:
#   ExecStart=/usr/bin/unshare --uts /opt/jiofiber-bridge/scripts/register.sh   (see systemd unit)
# It: sets the device hostname, fetches the ROTATING userpwd from the router, then execs the B2BUA.
set -u
source /opt/jiofiber-bridge/bridge.env

hostname "$DEVICE_HOST"

# Fetch the current rotating userpwd from the router (no OTP once the device is whitelisted).
# jfc_configure.py derives the MAC from the (namespaced) hostname, so this must run after `hostname`.
PW=$(cd "$(dirname "$JFC")" && python3 -u "$JFC" -l 5 </dev/null 2>&1 \
     | grep -iE 'DEBUG - userpwd:' | tail -1 | sed -E 's/.*userpwd: *//' | tr -d '\r ')
[ -z "$PW" ] && { echo "ERROR: no userpwd — device de-whitelisted? Re-run the OTP add (README §5)."; exit 1; }

# Auto-detect the LAN IP on the router subnet (survives DHCP changes).
LAN_IP=$(ip -4 route get "$ROUTER_IP" 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}' | head -1)

echo "$(date -Is) starting B2BUA as $DEVICE_HOST (lan=$LAN_IP trunk=$BRIDGE_OVERLAY_IP -> asterisk=$ASTERISK_OVERLAY_IP)"
exec "$BIN" "$SIP_AUTH_USER" "$PW" "$BRIDGE_OVERLAY_IP" "$ASTERISK_OVERLAY_IP" "$LAN_IP"
