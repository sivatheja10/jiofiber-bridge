#!/bin/bash
# Health check + self-heal. Run every ~2 min via systemd timer.
# Detects a lost JUICE registration (the persistent TLS to the router), auto-restarts the
# bridge (which re-fetches the rotating password and re-registers), and optionally ntfy-alerts.
set -u
source /opt/jiofiber-bridge/bridge.env
TAG=jiofiber-health
alert(){ [ -n "${NTFY_TOPIC:-}" ] && curl -s -m 8 -H "Title: $1" -H "Priority: ${3:-4}" -d "$2" "$NTFY_TOPIC" >/dev/null 2>&1; }

systemctl is-active --quiet jiofiber-bridge || { logger -t "$TAG" "service inactive (systemd Restart=always handles it)"; exit 0; }

# Registration alive? = a persistent established TLS connection to the router on :5068
if ! ss -tnH state established 2>/dev/null | grep -q "${ROUTER_IP}:5068"; then
  logger -t "$TAG" "CRIT: no TLS to router:5068 -> restarting bridge"
  alert "JioFiber bridge DOWN" "Lost JUICE registration - auto-restarting." urgent
  systemctl restart jiofiber-bridge
  sleep 20
  if ss -tnH state established 2>/dev/null | grep -q "${ROUTER_IP}:5068"; then
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
