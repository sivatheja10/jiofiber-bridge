#!/bin/sh
# jfv-credfind.sh — recover & VERIFY your own JioFiber-Voice IMS digest password.
# Runs directly ON YOUR OWN JioFiber ONT (busybox shell + md5sum — no python needed).
#
# It reads your identity+realm from the provisioning XML, pulls a real authenticated
# REGISTER from the JUICE SIP log (nonce+response), dumps the JUICE (hgw-voice-app)
# heap, and reports the ONE memory token that REPRODUCES the log's known-good digest
# — a verified match, no guessing.
#
# Scope: a line YOU own only (reads your own ONT's memory+logs). The password is your
# secret — never commit/share it.  Usage:  sh jfv-credfind.sh
#
# Portability: works on stripped-down busybox firmwares that lack `printf` and `head`
# (e.g. some JCOW404-family builds). Uses awk (universal in busybox) as the
# byte-exact "print string without trailing newline" primitive — needed because
# `echo -n` behaviour varies by shell and any stray newline breaks the MD5 digest.
set -u

# putf: print $1 to stdout with NO trailing newline, byte-exact.
# The string is passed via the environment (not `awk -v`) so awk doesn't process
# backslash escapes in the value — safe for arbitrary nonces/passwords.
putf(){ _s="$1" awk 'BEGIN{ printf "%s", ENVIRON["_s"] }'; }
md5(){ putf "$1" | md5sum | cut -d' ' -f1; }
first(){ sed -n '1p'; }   # portable replacement for `head -1`

# --- 1. identity + realm from provisioning XML -------------------------------
XML=$(cat /flash/juice/*.dat /pfrm2.0/etc/juice/*.dat 2>/dev/null)
USER=$(putf "$XML" | grep -o 'name="UserName" value="[^"]*"' | first | sed 's/.*value="//;s/"//')
[ -z "$USER" ] && USER=$(putf "$XML" | grep -o 'Private_User_Identity" value="[^"]*"' | first | sed 's/.*value="//;s/"//;s/^sip://')
REALM=$(putf "$XML" | grep -o 'name="Realm" value="[^"]*"' | first | sed 's/.*value="//;s/"//')
[ -z "$USER" ] || [ -z "$REALM" ] && { echo "!! could not read UserName/Realm from /flash/juice/*.dat"; exit 1; }
echo "[+] identity : $USER"
echo "[+] realm    : $REALM"

# --- 2. a real authenticated REGISTER from the JUICE log ---------------------
# find an Authorization: Digest line whose uri targets the realm, and pull its fields
AUTH=$(grep -h 'Authorization: Digest' /tmp/juicelogs/*.txt 2>/dev/null | grep 'response=' | grep "uri=\"sip:$REALM\"" | tail -1)
[ -z "$AUTH" ] && { echo "!! no authenticated REGISTER (Authorization: Digest, uri=sip:$REALM) in the log."; \
                    echo "   Trigger a fresh REGISTER (restart JUICE), wait ~5s, re-run."; exit 1; }
# NOTE: require a non-letter just before the field name, else the greedy `.*` lets `nonce`
# also match inside `cnonce` (suffix collision) and captures the wrong value.
field(){ putf "$AUTH" | sed -n "s/.*[^a-zA-Z]$1=\"\([^\"]*\)\".*/\1/p" | first; }
ufield(){ putf "$AUTH" | sed -n "s/.*[^a-zA-Z]$1=\([^,\" ]*\).*/\1/p" | first; }   # unquoted (nc, qop)
NONCE=$(field nonce); RESP=$(field response); URI=$(field uri); CNONCE=$(field cnonce)
NC=$(ufield nc); [ -z "$NC" ] && NC=00000001
QOP=$(ufield qop); [ -z "$QOP" ] && QOP=auth
UN=$(field username); [ -z "$UN" ] && UN="$USER"
echo "[+] captured digest: nonce=$(putf "$NONCE" | cut -c1-12)… response=$RESP"

# --- 3. dump JUICE heap -> unique candidate tokens ---------------------------
PID=$(pidof hgw-voice-app 2>/dev/null | awk '{print $1}')
[ -z "$PID" ] && { echo "!! hgw-voice-app (JUICE) not running"; exit 1; }
echo "[+] JUICE pid: $PID"
DUMP=/tmp/jfv-heap.$$; : > "$DUMP"
# dd the named anonymous regions that hold the credential ([heap], [stack]), page-aligned.
# (Iterating ALL rw-p regions can BLOCK on a device-backed map and hang the dump — so we
#  target only the named regions, which are readable and where the password actually lives.)
for TAG in '[heap]' '[stack]'; do
  line=$(grep -F "$TAG" /proc/$PID/maps | first); [ -z "$line" ] && continue
  a=$(echo "$line" | cut -d- -f1); b=$(echo "$line" | cut -d' ' -f1 | cut -d- -f2)
  sp=$(( 0x$a / 4096 )); cnt=$(( (0x$b - 0x$a) / 4096 ))
  [ "$cnt" -gt 0 ] && [ "$cnt" -lt 24576 ] && \
    dd if=/proc/$PID/mem bs=4096 skip="$sp" count="$cnt" 2>/dev/null >> "$DUMP"
done
# printable tokens, plausible password shape (len 8-24), unique.
# NOTE: use `strings` + `grep -oE`, NOT `tr -c ... '\n'` / bare `awk length` — on this ONT's
# busybox those misbehave (tr doesn't emit newlines; bare `length` evaluates to 0).
CANDS=$(strings "$DUMP" | grep -oE '[A-Za-z0-9._$@/+=-]{8,24}' | sort -u)
rm -f "$DUMP"
N=$(echo "$CANDS" | grep -c .)
echo "[+] $N unique candidate tokens from JUICE memory"

# --- 4. verify: which token reproduces the log digest? -----------------------
HA2=$(md5 "REGISTER:$URI")
echo "$CANDS" | while IFS= read -r C; do
  [ -z "$C" ] && continue
  HA1=$(md5 "$UN:$REALM:$C")
  if [ -n "$QOP" ]; then R=$(md5 "$HA1:$NONCE:$NC:$CNONCE:$QOP:$HA2"); else R=$(md5 "$HA1:$NONCE:$HA2"); fi
  if [ "$R" = "$RESP" ]; then
    echo ""; echo "===================================================="
    echo "  VERIFIED PASSWORD:  $C"
    echo "  (reproduces the ONT's own REGISTER digest)"
    echo "===================================================="
    echo ""; echo "Bridge env:  IMS_IMPI=$UN   IMS_PASSWORD=$C   SIP_REALM=$REALM"
    echo "$C" > /tmp/jfv-password.txt   # <- your secret; delete when done
    exit 0
  fi
done
[ -f /tmp/jfv-password.txt ] && exit 0
echo "!! no memory token reproduced the digest — the password may be held obfuscated between"
echo "   REGISTERs. Re-run IMMEDIATELY after a fresh REGISTER, or widen len/charset in step 3."
exit 1
