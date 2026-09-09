#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# ///
"""
jfv-credfind.py — recover & VERIFY your IMS/VoLTE SIP digest password, from your PC.

    uv run jfv-credfind.py <router-ip> <router-password>
    uv run jfv-credfind.py 192.168.29.1 myrouterpw
    uv run jfv-credfind.py 192.168.29.1 myrouterpw --telnet      # if the ONT uses telnet :23
    uv run jfv-credfind.py 192.168.29.1 myrouterpw --user root

Reaches into YOUR OWN carrier ONT/router over SSH (dropbear :22) or telnet (:23) and asks it
to do only what MUST run on the box: locate the SIP log, pull every authenticated
`Authorization: Digest` line, find the voice/IMS daemon, and dump its heap as printable
strings. Everything fragile — tokenizing and the MD5 digest math — runs HERE in Python, so
busybox quirks can't bite. It then prints the ONE token that REPRODUCES the box's own SIP
digest: a verified match, no guessing.

Portable by design: it keys off the STANDARD SIP Authorization header (RFC 3261/2617), not
vendor-specific file paths. It fast-paths the known JioFiber layout, then falls back to
discovery (search for the SIP log; probe /proc for the voice daemon) on other firmware, and
prints a diagnostic of exactly what it found so you can see which step matched or failed.

No pip installs needed (pure stdlib) — run with `uv run` or plain `python3`, from any machine
that can reach the router IP (on the LAN, or via your overlay/VPN).

Scope/ethics: a line YOU own only. Every value is yours; nothing transfers between lines.
The recovered password is your secret — never commit or share it.

---- NOTES FOR HUMANS *AND* LLMs MODIFYING THIS SCRIPT ----
The most common ways this recovery gets subtly broken when someone re-writes it:
  1. In the REMOTE shell block, DO NOT swap `putf` / `printf '%s'` for `echo -n` —
     `echo -n` behaviour is shell-dependent; some shells append a newline. In the
     .sh variant a stray newline makes every HA1/HA2/response mismatch even when
     the correct password is right there in memory. This script keeps hashing on
     the Python side (byte-exact), so the trap is confined to the .sh — but if you
     port this back to shell, use awk (`putf`), never `echo -n`.
  2. Use the realm from the `Authorization:` HEADER for HA1, not the provisioning
     XML's `<Realm>` — the digest response is computed against the header realm and
     the two can differ on some builds/circles. `verify()` below does this correctly.
  3. Honour `algorithm=`. Default MD5. `MD5-sess` computes HA1 differently:
     HA1 = MD5( MD5(user:realm:pass) : nonce : cnonce ). `AKAv[12]-MD5*` means
     SIM-based IMS-AKA — the response is Milenage-derived, not a static password,
     and CANNOT be memory-scraped. `verify()` handles both.
  4. `head -N` is missing on some stripped busybox firmwares (e.g. JCOW404); the
     REMOTE block uses `sed -n Np` instead. Same for `printf`.
  5. If it prints "no memory token reproduced any digest" on someone's line, ask
     them to re-run with `--debug` and post THAT output — algorithm/realm/qop are
     right there, and the AUTH lines are already redacted (nonce/response/cnonce
     masked) so it's safe to share in a bug report.
"""
import sys, os, re, time, socket, hashlib, argparse

def md5(s): return hashlib.md5(s.encode("utf-8", "ignore")).hexdigest()

MARK_SEND = "echo --JFVDONE$((500+79))--"   # types this...
MARK_SEEN = "--JFVDONE579--"                # ...but prints this (survives command echo)
TOKRE = re.compile(r"[A-Za-z0-9+/=._$@-]{8,24}")
# SIP methods to try for HA2 (we recover the same password from any of them)
METHODS = ("REGISTER", "INVITE", "SUBSCRIBE", "PUBLISH", "MESSAGE", "OPTIONS")

# The busybox command we run on the box. It does NOT tokenize or hash — that's Python's job.
# It DISCOVERS the SIP log + voice process instead of hard-coding them, with a fast-path for
# the known JioFiber layout. Everything is bounded (maxdepth/size) so it can't run away.
REMOTE = r'''
# putf: portable "print string with no trailing newline" (some stripped busybox
# firmwares — e.g. JCOW404-family — lack `printf`; `echo -n` is shell-dependent).
# awk is universal in busybox; the string is passed via env (not `awk -v`) so
# backslashes/quotes in values are byte-exact preserved.
putf(){ _s="$1" awk 'BEGIN{ printf "%s", ENVIRON["_s"] }'; }

# --- 1. the SIP log(s): fast-path the known path, else discover by content ---
LOGS=$(ls /tmp/juicelogs/*.txt 2>/dev/null)
[ -z "$LOGS" ] && LOGS=$(find /tmp /var /nvram /flash /pfrm2.0 /opt /mnt /data /usr/local 2>/dev/null \
  -maxdepth 4 -type f -size -8192k 2>/dev/null | xargs grep -lE 'Authorization: *Digest' 2>/dev/null | sed -n '1,20p')
echo DIAG_LOGS="$(echo $LOGS)"
echo AUTH_BEGIN
grep -hE 'Authorization: *Digest' $LOGS 2>/dev/null | grep 'response=' | sort -u
echo AUTH_END

# --- 2. identity/realm from provisioning (display only; verification uses the header) ---
XML=$(cat /flash/juice/*.dat /pfrm2.0/etc/juice/*.dat 2>/dev/null)
[ -z "$XML" ] && XML=$(cat $(grep -rlE 'Private_User_Identity|name="Realm"|LBO_P-CSCF' /flash /pfrm2.0 /nvram /etc 2>/dev/null | sed -n '1p') 2>/dev/null)
U=$(putf "$XML" | grep -o 'name="UserName" value="[^"]*"' | sed -n '1p' | sed 's/.*value="//;s/"//')
[ -z "$U" ] && U=$(putf "$XML" | grep -o 'Private_User_Identity[^>]*value="[^"]*"' | sed -n '1p' | sed 's/.*value="//;s/"//;s/^sip://')
R=$(putf "$XML" | grep -o 'name="Realm" value="[^"]*"' | sed -n '1p' | sed 's/.*value="//;s/"//')
echo IDENTITY=$U
echo REALM=$R

# --- 3. the voice/IMS process(es): known names, else probe /proc/*/comm ---
PIDS=$(for N in hgw-voice-app juiced juice voiced imsd imsagent ims mmpbxd voipd voip callmgr callmanager pjsua asterisk sipapp; do pidof "$N" 2>/dev/null; done)
if [ -z "$(echo $PIDS)" ]; then
  for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
    N=$(cat /proc/$pid/comm 2>/dev/null)
    echo "$N" | grep -qiE 'voice|ims|sip|voip|juice|mmpbx|hgw|call|pjs|b2bua|volte' && PIDS="$PIDS $pid"
  done
fi
echo DIAG_PIDS="$(echo $PIDS)"

# --- 4. dump writable regions of each candidate, strings them ---
# Default ($WIDE=0): [heap]+[stack] only (fast, and where the credential usually is).
# $WIDE=1 (--wide): every ANONYMOUS rw-p region (no pathname or [bracket] tag) — catches
# a credential in a malloc arena outside the main heap. Either way skip file-/device-
# backed maps (reading /dev/... can BLOCK; file maps don't hold the runtime credential).
: > /tmp/jfv-heap.bin
for P in $PIDS; do
  # match private-writable with OR without the exec bit — JioFiber ONT [heap] is `rwxp`
  grep -E ' rw[-x]p ' /proc/$P/maps 2>/dev/null | while read L; do
    path=$(echo "$L"|awk '{print $6}')
    if [ "${WIDE:-0}" = "1" ]; then
      case "$path" in "" | \[*\]) : ;; *) continue ;; esac
    else
      case "$path" in "[heap]" | "[stack]") : ;; *) continue ;; esac
    fi
    a=$(echo "$L"|cut -d- -f1); b=$(echo "$L"|cut -d' ' -f1|cut -d- -f2)
    sp=$((0x$a/4096)); c=$(((0x$b-0x$a)/4096))
    [ "$c" -gt 0 ] && [ "$c" -lt 24576 ] && dd if=/proc/$P/mem bs=4096 skip=$sp count=$c 2>/dev/null >> /tmp/jfv-heap.bin
  done
done
echo STR_BEGIN
strings /tmp/jfv-heap.bin 2>/dev/null | sort -u
echo STR_END
rm -f /tmp/jfv-heap.bin
'''.strip()

# --- transport A: SSH via the local ssh binary + a pty (old-dropbear compat) --
def ssh_run(host, user, pw, cmd):
    import pty, select
    argv = ["ssh", "-p", "22", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "PubkeyAuthentication=no",
            "-o", "HostKeyAlgorithms=+ssh-rsa", "-o", "KexAlgorithms=+diffie-hellman-group14-sha1",
            "-o", "ServerAliveInterval=5", "-o", "ConnectTimeout=30", "%s@%s" % (user, host)]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv); os._exit(1)
    def readfor(sec, until=None):
        end = time.time() + sec; out = b""
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.3)
            if r:
                try: d = os.read(fd, 65536)
                except OSError: break
                if not d: break
                out += d
                if until and until in out: break
        return out
    o = readfor(35, until=b"assword:")
    if b"timed out" in o.lower() or b"refused" in o.lower() or b"denied" in o.lower():
        return None
    if b"password:" in o.lower():
        os.write(fd, pw.encode() + b"\n"); readfor(8, until=b"#")
    os.write(fd, b"stty -echo 2>/dev/null\n"); readfor(2)   # stop the pty echoing our command
    os.write(fd, (cmd + "\n" + MARK_SEND + "\n").encode())
    out = readfor(240, until=MARK_SEEN.encode()).decode("utf-8", "replace")
    try: os.write(fd, b"exit\n")
    except Exception: pass
    return out if MARK_SEEN in out or "STR_END" in out else None

# --- transport B: telnet via a raw socket (stdlib; telnetlib is gone in 3.13) -
def telnet_run(host, user, pw, cmd):
    try: s = socket.create_connection((host, 23), 15)
    except Exception: return None
    s.settimeout(20)
    def rd(until, secs=20):
        end = time.time() + secs; buf = b""
        while time.time() < end and until not in buf:
            try: d = s.recv(65536)
            except socket.timeout: break
            except Exception: break
            if not d: break
            buf += d
        return buf
    rd(b"ogin:"); s.sendall(user.encode() + b"\n")
    rd(b"assword:"); s.sendall(pw.encode() + b"\n"); rd(b"#", 10)
    s.sendall(b"stty -echo 2>/dev/null\n"); rd(b"#", 3)
    s.sendall(cmd.encode() + b"\n" + MARK_SEND.encode() + b"\n")
    out = rd(MARK_SEEN.encode(), 240).decode("utf-8", "replace")
    try: s.close()
    except Exception: pass
    return out if MARK_SEEN in out or "STR_END" in out else None

def between(out, a, b):
    return out.split(a, 1)[1].split(b, 1)[0] if a in out and b in out.split(a, 1)[1] else ""

AKA_ALGOS = ("AKAv1-MD5", "AKAv2-MD5", "AKAv1-MD5-sess", "AKAv2-MD5-sess")

def verify(authlines, toks):
    """Try each digest line × each SIP method against the token set.
    Returns:
      (pw, un, realm, method, algo)  -- verified match
      ("__AKA__", algo)              -- line uses SIM-based IMS-AKA (unrecoverable)
      None                           -- no line matched
    """
    aka_seen = None
    for auth in authlines:
        d = dict(re.findall(r'(\w+)="([^"]*)"', auth))
        d.update(dict(re.findall(r'(\w+)=([^",\s]+)', auth)))
        resp = d.get("response")
        realm, un, nonce, uri = d.get("realm"), d.get("username"), d.get("nonce"), d.get("uri")
        if not (resp and realm and un and nonce and uri):
            continue
        nc = d.get("nc", "00000001"); cnonce = d.get("cnonce", ""); qop = d.get("qop", "")
        algo = d.get("algorithm", "MD5")
        if algo in AKA_ALGOS:
            aka_seen = algo; continue                          # skip; try any non-AKA lines
        sess = (algo == "MD5-sess")
        for m in METHODS:
            ha2 = md5("%s:%s" % (m, uri))
            for c in toks:
                ha1 = md5("%s:%s:%s" % (un, realm, c))
                if sess: ha1 = md5("%s:%s:%s" % (ha1, nonce, cnonce))
                r = (md5("%s:%s:%s:%s:%s:%s" % (ha1, nonce, nc, cnonce, qop, ha2)) if qop
                     else md5("%s:%s:%s" % (ha1, nonce, ha2)))
                if r == resp:
                    return c, un, realm, m, algo
    if aka_seen: return ("__AKA__", aka_seen)
    return None

def main():
    ap = argparse.ArgumentParser(description="Recover your IMS/VoLTE SIP password from your own ONT/router.")
    ap.add_argument("host", help="router IP, e.g. 192.168.29.1")
    ap.add_argument("password", help="the router's SSH/telnet root password")
    ap.add_argument("--user", default="root")
    ap.add_argument("--telnet", action="store_true", help="use telnet :23 instead of SSH :22")
    ap.add_argument("--tries", type=int, default=4, help="connection attempts (flaky links)")
    ap.add_argument("--debug", action="store_true",
                    help="print redacted AUTH lines, algorithm+realm per line, and token-count breakdown "
                         "(no secrets — nonce/response/cnonce are masked). Attach the output to a bug report.")
    ap.add_argument("--wide", action="store_true",
                    help="dump ALL anonymous writable regions, not just [heap]+[stack] — try this if the "
                         "default reports no match (slower on weak CPUs; the credential may live in a "
                         "malloc arena outside the main heap on some firmwares).")
    a = ap.parse_args()
    remote = ("WIDE=1\n" if a.wide else "WIDE=0\n") + REMOTE
    def dbg(m):
        if a.debug: print("[debug]", m)
    run = telnet_run if a.telnet else ssh_run
    print("[+] connecting to %s@%s (%s)…" % (a.user, a.host, "telnet" if a.telnet else "ssh"))
    out = None
    for i in range(a.tries):
        try:
            out = run(a.host, a.user, a.password, remote)
        except Exception as e:
            out = None; print("    attempt %d: %s" % (i + 1, e))
        if out and "STR_END" in out and "AUTH_END" in out:
            break
        out = None
        if i + 1 < a.tries:
            print("    attempt %d didn't land (flaky link?) — retrying…" % (i + 1)); time.sleep(3)
    if not out:
        sys.exit("!! couldn't get a clean session from the ONT.\n"
                 "   Check the IP/password/reachability; try --telnet; the link may be flaky (raise --tries).")

    # --- diagnostics: show exactly what the box found (helps on unknown models) ---
    logs = (re.search(r'DIAG_LOGS=(.*)', out) or [None, ""])[1].strip()
    pids = (re.search(r'DIAG_PIDS=(.*)', out) or [None, ""])[1].strip()
    ident = (re.search(r'IDENTITY=(\S+)', out) or [None, ""])[1]
    realm = (re.search(r'REALM=(\S+)', out) or [None, ""])[1]
    authlines = [l.strip() for l in between(out, "AUTH_BEGIN", "AUTH_END").splitlines()
                 if "Authorization" in l and "response=" in l]
    toks = set(TOKRE.findall(between(out, "STR_BEGIN", "STR_END")))
    print("[+] SIP log(s): %s" % (logs or "(none found)"))
    print("[+] voice PID(s): %s" % (pids or "(none found)"))
    if ident or realm:
        print("[+] provisioning: identity=%s realm=%s" % (re.sub(r"\d", "#", ident) or "?", realm or "?"))
    print("[+] %d authenticated digest line(s), %d candidate tokens from memory"
          % (len(authlines), len(toks)))
    # Per-line summary of algorithm+realm — always print if we have any auth lines.
    # This alone diagnoses the top-3 failure modes (MD5-sess/AKA/realm-mismatch).
    for i, auth in enumerate(authlines[-3:]):
        d = dict(re.findall(r'(\w+)="([^"]*)"', auth))
        d.update(dict(re.findall(r'(\w+)=([^",\s]+)', auth)))
        print("      digest[%d]: algorithm=%s realm=%s qop=%s"
              % (i, d.get("algorithm","MD5"), d.get("realm","?"), d.get("qop","?")))
        if a.debug:
            red = re.sub(r'(nonce|response|cnonce)="[^"]*"', r'\1="<R>"', auth)
            dbg("  " + red)

    if a.debug:
        dbg("token-count breakdown at various widths:")
        raw = between(out, "STR_BEGIN", "STR_END")
        for pat, lbl in [(r"[A-Za-z0-9._$@/+=!#-]{6,32}", "{6,32} chars +!#"),
                         (r"[A-Za-z0-9._$@/+=-]{8,24}",   "{8,24} chars (old)"),
                         (r"[A-Za-z0-9._$@/+=-]{4,64}",   "{4,64} chars (wide)")]:
            dbg("  %-24s unique: %d" % (lbl, len(set(re.findall(pat, raw)))))

    # --- guidance if a step came up empty ---
    if not authlines:
        sys.exit("!! no authenticated SIP digest found in the logs.\n"
                 "   The daemon may not log Authorization headers, or the log wasn't located.\n"
                 "   Trigger a fresh REGISTER (restart the voice app) and retry; or point at the log dir.")
    if not toks:
        sys.exit("!! couldn't read voice-process memory (no candidate tokens).\n"
                 "   The voice daemon wasn't found or its heap wasn't readable (need root).")

    hit = verify(authlines, toks)
    if hit and hit[0] == "__AKA__":
        sys.exit("!! algorithm=%s — this line uses SIM-based IMS-AKA (Milenage), not plain\n"
                 "   MD5 digest. The response is derived on the SIM, not from a static password.\n"
                 "   Password recovery via memory scraping does not apply here — sorry." % hit[1])
    if hit:
        c, un, realm2, method, algo = hit
        print("\n" + "=" * 52)
        print("  ✅ VERIFIED PASSWORD:  %s" % c)
        print("  (reproduces the box's own %s digest, algorithm=%s)" % (method, algo))
        print("=" * 52)
        print("\nBridge env:")
        print("  IMS_IMPI=%s" % un)
        print("  IMS_PASSWORD=%s   # <- your secret; keep out of git" % c)
        print("  SIP_REALM=%s" % realm2)
        return
    sys.exit("!! no memory token reproduced any digest.\n"
             "   Diagnostic pointers, in order of likelihood:\n"
             "   1. Re-run IMMEDIATELY after a fresh REGISTER — some firmwares hold the\n"
             "      plaintext only briefly around a REGISTER and scrub it in between.\n"
             "      Kill the voice daemon (it respawns) and run this again within seconds.\n"
             "   2. Run with --debug to see per-line algorithm/realm/qop. MD5-sess is\n"
             "      handled automatically; AKAv[12]-MD5 cannot be recovered this way.\n"
             "   3. Run with --wide to dump all anonymous regions (not just heap/stack)\n"
             "      — the credential may live in a malloc arena outside the main heap.\n"
             "   4. Widen the token filter in TOKRE (default {8,24}) if your password\n"
             "      might be shorter/longer or use uncommon chars.\n"
             "   5. If you file an issue, please attach the FULL --debug output — the\n"
             "      nonce/response/cnonce are already redacted so it's safe to share.")

if __name__ == "__main__":
    main()
