#!/bin/bash
# Health check + self-heal. Run every ~2 min via systemd timer.
# Detects a lost registration (the persistent SIP/TLS flow) and auto-restarts the bridge, which
# re-registers; optionally ntfy-alerts.
#
# Mode-aware: in the default JUICE path the flow is the TLS to the router on :5068; in DIRECT_IMS
# mode (see DIRECT-IMS.md) it is the TLS to the P-CSCF on :5061. Set the same vars as the bridge.
set -u
source /opt/jiofiber-bridge/bridge.env
TAG=jiofiber-health
alert(){ [ -n "${NTFY_TOPIC:-}" ] && curl -s -m 8 -H "Title: $1" -H "Priority: ${3:-4}" -d "$2" "$NTFY_TOPIC" >/dev/null 2>&1; }

# What a healthy registration flow looks like, per mode:
if [ "${DIRECT_IMS:-0}" = 1 ]; then
  # DIRECT_IMS: an established TLS6 to the P-CSCF on :5061. PCSCF_V6 is bare (no brackets).
  FLOW="\\[${PCSCF_V6}\\]:${PCSCF_PORT:-5061}"
  WHAT="direct P-CSCF registration"
else
  # JUICE path: an established TLS to the router on :5068.
  FLOW="${ROUTER_IP}:5068"
  WHAT="JUICE registration"
fi
flow_up(){ ss -tnH state established 2>/dev/null | grep -q "$FLOW"; }

systemctl is-active --quiet jiofiber-bridge || { logger -t "$TAG" "service inactive (systemd Restart=always handles it)"; exit 0; }

# Registration alive? = the persistent established TLS flow for this mode.
if ! flow_up; then
  logger -t "$TAG" "CRIT: no SIP/TLS flow ($FLOW) -> restarting bridge"
  alert "JioFiber bridge DOWN" "Lost $WHAT - auto-restarting." urgent
  systemctl restart jiofiber-bridge
  sleep 20
  if flow_up; then
    alert "JioFiber bridge RECOVERED" "Re-registered after auto-restart." 3
  else
    alert "JioFiber bridge STILL DOWN" "Auto-restart did not restore registration - needs attention." urgent
  fi
  exit 0
fi

# Overlay path to Asterisk direct? (Tailscale DERP relay => call quality may degrade)
if command -v tailscale >/dev/null 2>&1 && tailscale ping --c 2 "$ASTERISK_OVERLAY_IP" 2>/dev/null | tail -1 | grep -qi DERP; then
  logger -t "$TAG" "WARN: overlay to Asterisk via DERP relay"
  FLAG=/tmp/jiofiber-derp-alerted   # throttle to hourly
  if [ ! -f "$FLAG" ] || [ $(( $(date +%s) - $(stat -c %Y "$FLAG" 2>/dev/null||echo 0) )) -gt 3600 ]; then
    alert "JioFiber bridge degraded" "Overlay to Asterisk on DERP relay - call quality may degrade." 3
    touch "$FLAG"
  fi
fi
logger -t "$TAG" "OK: registered; overlay path checked"
