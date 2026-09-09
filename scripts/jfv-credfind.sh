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
#
# ---- NOTES FOR HUMANS *AND* LLMs MODIFYING THIS SCRIPT ----
# Common traps that have burned people (fix these BEFORE anything else):
#   1. DO NOT replace `putf` / `printf '%s'` with `echo -n`. `echo -n` behaviour is
#      shell-dependent; some shells append a newline. A single stray newline makes
#      every HA1/HA2/response mismatch even when the correct password is right
#      there in memory. If your busybox lacks `printf`, use awk (see putf).
#   2. USE THE REALM FROM THE `Authorization:` HEADER (`field realm`) for HA1 —
#      NOT the `<Realm>` field from the provisioning XML. They can differ on some
#      builds/circles; the digest response is computed against the header realm.
#   3. HONOUR `algorithm=`. Default MD5. `MD5-sess` computes HA1 differently:
#      HA1 = MD5( MD5(user:realm:pass) : nonce : cnonce ). `AKAv[12]-MD5*` means
#      SIM-based IMS-AKA — the response is Milenage-derived, not a static password,
#      and CANNOT be memory-scraped. Bail cleanly in that case.
#   4. `head -N` is missing on some firmwares; use `sed -n Np`. `cut` is fine.
#   5. If it prints "no memory token reproduced" on YOUR line: run `JFV_DEBUG=1 sh
#      jfv-credfind.sh` to dump the actual algorithm/realm/qop it saw + a redacted
#      AUTH line. Post THAT to a bug report — the maintainer can't diagnose without
#      it. Also try running IMMEDIATELY after a JUICE restart (kill hgw-voice-app;
#      it respawns) — some builds only hold the plaintext during a live REGISTER
#      window and scrub it in between.
# ----
set -u
DEBUG="${JFV_DEBUG:-0}"
# JFV_WIDE=1 dumps ALL anonymous writable regions instead of just [heap]+[stack].
# Off by default: on a slow ONT (600 MHz MIPS) dumping+`strings`ing tens of MB is slow.
# Turn it on if the default reports "no memory token" — the credential may live in a
# malloc arena outside the main heap (seen on JCOW404-family builds).
WIDE="${JFV_WIDE:-0}"
dbg(){ [ "$DEBUG" = "1" ] && echo "[debug] $*"; }

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
AUTH_ALL=$(grep -h 'Authorization: Digest' /tmp/juicelogs/*.txt 2>/dev/null | grep 'response=')
AUTH_TOTAL=$(echo "$AUTH_ALL" | grep -c .)
AUTH=$(echo "$AUTH_ALL" | grep "uri=\"sip:$REALM\"" | tail -1)
dbg "authorized Digest lines in log (any URI): $AUTH_TOTAL"
if [ -z "$AUTH" ]; then
  echo "!! no authenticated REGISTER (Authorization: Digest, uri=sip:$REALM) in the log."
  echo "   Trigger a fresh REGISTER (restart JUICE), wait ~5s, re-run."
  [ "$AUTH_TOTAL" -gt 0 ] && echo "   (Log has $AUTH_TOTAL other Digest lines with different URIs; try JFV_DEBUG=1 to inspect.)"
  [ "$DEBUG" = "1" ] && echo "$AUTH_ALL" | sed -n '$p' | sed 's/nonce="[^"]*"/nonce="<REDACTED>"/;s/response="[^"]*"/response="<REDACTED>"/;s/cnonce="[^"]*"/cnonce="<REDACTED>"/' | sed 's/^/[debug] latest-any-URI: /'
  exit 1
fi
# NOTE: require a non-letter just before the field name, else the greedy `.*` lets `nonce`
# also match inside `cnonce` (suffix collision) and captures the wrong value.
field(){ putf "$AUTH" | sed -n "s/.*[^a-zA-Z]$1=\"\([^\"]*\)\".*/\1/p" | first; }
ufield(){ putf "$AUTH" | sed -n "s/.*[^a-zA-Z]$1=\([^,\" ]*\).*/\1/p" | first; }   # unquoted (nc, qop)
NONCE=$(field nonce); RESP=$(field response); URI=$(field uri); CNONCE=$(field cnonce)
NC=$(ufield nc); [ -z "$NC" ] && NC=00000001
QOP=$(ufield qop); [ -z "$QOP" ] && QOP=auth
UN=$(field username); [ -z "$UN" ] && UN="$USER"
# Use the realm the CHALLENGER sent (from the header), not the XML — the digest
# `response` is computed against the header realm; they can differ from the XML
# `<Realm>` field on some builds/circles, in which case NO token can ever match.
XML_REALM="$REALM"
HDR_REALM=$(field realm); [ -n "$HDR_REALM" ] && REALM="$HDR_REALM"
[ "$DEBUG" = "1" ] && [ "$XML_REALM" != "$HDR_REALM" ] && [ -n "$HDR_REALM" ] \
    && dbg "realm mismatch: XML='$XML_REALM' vs header='$HDR_REALM' — using header (correct)"
# algorithm: default MD5. MD5-sess computes HA1 differently. AKA* means SIM-based
# IMS-AKA — the response is Milenage-derived, not a password we can memory-scrape.
HDR_ALGO=$(ufield algorithm); [ -z "$HDR_ALGO" ] && HDR_ALGO=MD5
echo "[+] captured digest: algorithm=$HDR_ALGO realm=$REALM qop=$QOP"
echo "                     nonce=$(putf "$NONCE" | cut -c1-12)… response=$RESP"
if [ "$DEBUG" = "1" ]; then
  # redact nonce/response/cnonce, print the raw AUTH line so the exact format is visible
  dbg "AUTH line (nonce/response/cnonce redacted):"
  echo "$AUTH" | sed 's/nonce="[^"]*"/nonce="<R>"/g;s/response="[^"]*"/response="<R>"/g;s/cnonce="[^"]*"/cnonce="<R>"/g' | sed 's/^/[debug]   /'
fi
case "$HDR_ALGO" in
  AKAv1-MD5|AKAv2-MD5|AKAv1-MD5-sess|AKAv2-MD5-sess)
    echo "!! algorithm=$HDR_ALGO — this line uses SIM-based IMS-AKA (not plain MD5 digest)."
    echo "   The response is derived from Milenage on the SIM, not a static password."
    echo "   Password recovery via memory scraping does not apply here — sorry."
    exit 2 ;;
esac

# --- 3. dump JUICE heap -> unique candidate tokens ---------------------------
PID=$(pidof hgw-voice-app 2>/dev/null | awk '{print $1}')
[ -z "$PID" ] && { echo "!! hgw-voice-app (JUICE) not running"; exit 1; }
echo "[+] JUICE pid: $PID"
DUMP=/tmp/jfv-heap.$$; : > "$DUMP"
if [ "$DEBUG" = "1" ]; then
  dbg "process memory map (writable regions, sizes only — no addresses):"
  # busybox awk lacks strtonum; do the hex math in the shell.
  grep -E ' rw[-x]p ' /proc/$PID/maps 2>/dev/null | while read L; do
    ah=$(echo "$L"|cut -d- -f1); bh=$(echo "$L"|cut -d' ' -f1|cut -d- -f2)
    sz=$(( (0x$bh - 0x$ah) / 1024 ))
    kind=$(echo "$L"|awk '{print $NF}'); case "$kind" in \[*\]) : ;; *) kind='[anon]';; esac
    # portable formatting via awk (busybox printf may be missing; awk is universal)
    _kind="$kind" _sz="$sz" awk 'BEGIN{ printf "[debug]   %-8s %6d KiB\n", ENVIRON["_kind"], ENVIRON["_sz"] }'
  done | sort -u
fi
# Default: dump [heap]+[stack] (fast, and where the credential usually lives).
# JFV_WIDE=1: dump every ANONYMOUS writable region (rw-p with no pathname or a
# [bracket] tag) — catches a credential in a malloc arena outside the main heap.
# Either way we SKIP file-/device-backed maps: reading a device map (/dev/...) can
# BLOCK and hang the dump, and file maps don't hold the runtime credential.
# Match private-writable perms with OR without the exec bit — on JioFiber ONTs the
# [heap] is `rwxp` (executable!), so a plain ` rw-p ` grep would miss it entirely.
grep -E ' rw[-x]p ' /proc/$PID/maps 2>/dev/null | while read line; do
  path=$(echo "$line" | awk '{print $6}')
  if [ "$WIDE" = "1" ]; then
    case "$path" in "" | \[*\]) : ;; *) continue ;; esac       # any anonymous region
  else
    case "$path" in "[heap]" | "[stack]") : ;; *) continue ;; esac
  fi
  a=$(echo "$line" | cut -d- -f1); b=$(echo "$line" | cut -d' ' -f1 | cut -d- -f2)
  sp=$(( 0x$a / 4096 )); cnt=$(( (0x$b - 0x$a) / 4096 ))
  [ "$cnt" -gt 0 ] && [ "$cnt" -lt 24576 ] && \
    dd if=/proc/$PID/mem bs=4096 skip="$sp" count="$cnt" 2>/dev/null >> "$DUMP"
done
# printable tokens, plausible password shape, unique. Slightly wider than tight (6-32)
# so shorter/longer credentials from other circles/firmwares aren't silently missed.
# NOTE: use `strings` + `grep -oE`, NOT `tr -c ... '\n'` / bare `awk length` — on this ONT's
# busybox those misbehave (tr doesn't emit newlines; bare `length` evaluates to 0).
if [ "$DEBUG" = "1" ]; then
  RAW=$(wc -c < "$DUMP" 2>/dev/null); dbg "dumped $RAW bytes; token counts at various widths:"
  for w in 6,32 8,24 4,64 8,64; do
    n=$(strings "$DUMP" | grep -oE "[A-Za-z0-9._\$@/+=!#-]{${w}}" | sort -u | grep -c .)
    dbg "  {$w} unique: $n"
  done
fi
CANDS=$(strings "$DUMP" | grep -oE '[A-Za-z0-9._$@/+=!#-]{6,32}' | sort -u)
rm -f "$DUMP"
N=$(echo "$CANDS" | grep -c .)
echo "[+] $N unique candidate tokens from JUICE memory"

# --- 4. verify: which token reproduces the log digest? -----------------------
HA2=$(md5 "REGISTER:$URI")
# MD5-sess: session key = MD5(MD5(user:realm:pass):nonce:cnonce), used as HA1.
# Detect once outside the hot loop.
SESS=0; [ "$HDR_ALGO" = "MD5-sess" ] && SESS=1
echo "$CANDS" | while IFS= read -r C; do
  [ -z "$C" ] && continue
  HA1=$(md5 "$UN:$REALM:$C")
  [ "$SESS" = 1 ] && HA1=$(md5 "$HA1:$NONCE:$CNONCE")
  if [ -n "$QOP" ]; then R=$(md5 "$HA1:$NONCE:$NC:$CNONCE:$QOP:$HA2"); else R=$(md5 "$HA1:$NONCE:$HA2"); fi
  if [ "$R" = "$RESP" ]; then
    echo ""; echo "===================================================="
    echo "  VERIFIED PASSWORD:  $C"
    echo "  (reproduces the ONT's own REGISTER digest)"
    echo "===================================================="
    echo ""; echo "Bridge env:  IMS_IMPI=$UN   IMS_PASSWORD=$C   SIP_REALM=$REALM"
    # Opt-in only: write plaintext to /tmp for scripting. Off by default so we don't leave
    # a live carrier credential on the disk. Set JFV_WRITE=1 if you want it.
    [ "${JFV_WRITE:-0}" = "1" ] && { echo "$C" > /tmp/jfv-password.txt; echo "(also wrote /tmp/jfv-password.txt — delete when done)"; }
    exit 0
  fi
done
[ -f /tmp/jfv-password.txt ] && exit 0
cat <<'MSG'
!! no memory token reproduced the digest.
   Diagnostic pointers, in order of likelihood:
   1. Some firmwares hold the plaintext ONLY briefly around a REGISTER and scrub it
      between. Kill JUICE (`kill $(pidof hgw-voice-app)`; it respawns) and re-run
      this script within a few seconds.
   2. Different `algorithm=` than plain MD5? Re-run with `JFV_DEBUG=1` — the
      diagnostic will name it; if AKAv[12]-MD5 this recovery approach cannot work
      on your line (SIM-based) and no patching will help.
   3. XML realm ≠ header realm? `JFV_DEBUG=1` prints both.
   4. Password might live outside [heap]+[stack] (a malloc arena). Re-run with
      `JFV_WIDE=1 sh jfv-credfind.sh` to dump ALL anonymous regions (slower on a
      weak CPU). `JFV_DEBUG=1` prints the full rw-region map so you can see them.
   5. If you file an issue, please attach the FULL `JFV_DEBUG=1` output — it's
      already redacted (nonce/response/cnonce masked) and contains no secrets.
MSG
exit 1
