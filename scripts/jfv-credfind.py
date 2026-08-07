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
# --- 1. the SIP log(s): fast-path the known path, else discover by content ---
LOGS=$(ls /tmp/juicelogs/*.txt 2>/dev/null)
[ -z "$LOGS" ] && LOGS=$(find /tmp /var /nvram /flash /pfrm2.0 /opt /mnt /data /usr/local 2>/dev/null \
  -maxdepth 4 -type f -size -8192k 2>/dev/null | xargs grep -lE 'Authorization: *Digest' 2>/dev/null | head -20)
echo DIAG_LOGS="$(echo $LOGS)"
echo AUTH_BEGIN
grep -hE 'Authorization: *Digest' $LOGS 2>/dev/null | grep 'response=' | sort -u
echo AUTH_END

# --- 2. identity/realm from provisioning (display only; verification uses the header) ---
XML=$(cat /flash/juice/*.dat /pfrm2.0/etc/juice/*.dat 2>/dev/null)
[ -z "$XML" ] && XML=$(cat $(grep -rlE 'Private_User_Identity|name="Realm"|LBO_P-CSCF' /flash /pfrm2.0 /nvram /etc 2>/dev/null | head -1) 2>/dev/null)
U=$(printf '%s' "$XML"|grep -o 'name="UserName" value="[^"]*"'|head -1|sed 's/.*value="//;s/"//')
[ -z "$U" ]&&U=$(printf '%s' "$XML"|grep -o 'Private_User_Identity[^>]*value="[^"]*"'|head -1|sed 's/.*value="//;s/"//;s/^sip://')
R=$(printf '%s' "$XML"|grep -o 'name="Realm" value="[^"]*"'|head -1|sed 's/.*value="//;s/"//')
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

# --- 4. dump [heap]+[stack] of each candidate, strings them (busybox-safe) ---
: > /tmp/jfv-heap.bin
for P in $PIDS; do
  for TAG in [heap] [stack]; do
    L=$(grep -F "$TAG" /proc/$P/maps 2>/dev/null | head -1); [ -z "$L" ] && continue
    a=$(echo "$L"|cut -d- -f1); b=$(echo "$L"|cut -d' ' -f1|cut -d- -f2)
    sp=$((0x$a/4096)); c=$(((0x$b-0x$a)/4096))
    [ "$c" -gt 0 ]&&[ "$c" -lt 24576 ]&&dd if=/proc/$P/mem bs=4096 skip=$sp count=$c 2>/dev/null >> /tmp/jfv-heap.bin
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

def verify(authlines, toks):
    """Try each digest line × each SIP method against the token set. Return (pw, un, realm, method)."""
    for auth in authlines:
        d = dict(re.findall(r'(\w+)="([^"]*)"', auth))
        d.update(dict(re.findall(r'(\w+)=([^",\s]+)', auth)))
        resp = d.get("response")
        realm, un, nonce, uri = d.get("realm"), d.get("username"), d.get("nonce"), d.get("uri")
        if not (resp and realm and un and nonce and uri):
            continue
        nc = d.get("nc", "00000001"); cnonce = d.get("cnonce", ""); qop = d.get("qop", "")
        for m in METHODS:
            ha2 = md5("%s:%s" % (m, uri))
            for c in toks:
                ha1 = md5("%s:%s:%s" % (un, realm, c))
                r = (md5("%s:%s:%s:%s:%s:%s" % (ha1, nonce, nc, cnonce, qop, ha2)) if qop
                     else md5("%s:%s:%s" % (ha1, nonce, ha2)))
                if r == resp:
                    return c, un, realm, m
    return None

def main():
    ap = argparse.ArgumentParser(description="Recover your IMS/VoLTE SIP password from your own ONT/router.")
    ap.add_argument("host", help="router IP, e.g. 192.168.29.1")
    ap.add_argument("password", help="the router's SSH/telnet root password")
    ap.add_argument("--user", default="root")
    ap.add_argument("--telnet", action="store_true", help="use telnet :23 instead of SSH :22")
    ap.add_argument("--tries", type=int, default=4, help="connection attempts (flaky links)")
    a = ap.parse_args()
    run = telnet_run if a.telnet else ssh_run
    print("[+] connecting to %s@%s (%s)…" % (a.user, a.host, "telnet" if a.telnet else "ssh"))
    out = None
    for i in range(a.tries):
        try:
            out = run(a.host, a.user, a.password, REMOTE)
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

    # --- guidance if a step came up empty ---
    if not authlines:
        sys.exit("!! no authenticated SIP digest found in the logs.\n"
                 "   The daemon may not log Authorization headers, or the log wasn't located.\n"
                 "   Trigger a fresh REGISTER (restart the voice app) and retry; or point at the log dir.")
    if not toks:
        sys.exit("!! couldn't read voice-process memory (no candidate tokens).\n"
                 "   The voice daemon wasn't found or its heap wasn't readable (need root).")

    hit = verify(authlines, toks)
    if hit:
        c, un, realm2, method = hit
        print("\n" + "=" * 52)
        print("  ✅ VERIFIED PASSWORD:  %s" % c)
        print("  (reproduces the box's own %s digest)" % method)
        print("=" * 52)
        print("\nBridge env:")
        print("  IMS_IMPI=%s" % un)
        print("  IMS_PASSWORD=%s   # <- your secret; keep out of git" % c)
        print("  SIP_REALM=%s" % realm2)
        return
    sys.exit("!! no memory token reproduced any digest.\n"
             "   The password may be held obfuscated between REGISTERs — re-run IMMEDIATELY after a\n"
             "   fresh REGISTER (restart the voice app, wait ~5s), or widen TOKRE's length/charset.")

if __name__ == "__main__":
    main()
