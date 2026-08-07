# Recovering your line's IMS SIP digest password

The bridge registers to the IMS core with a **static MD5 digest password** — the same
secret your ONT/router uses to register upstream. It is stored **encrypted** in the voice
config and held **decrypted in memory** by the router's voice daemon. These two scripts
recover it from **your own** router and **verify** it, so you never guess:

| Script | Runs on | Use it when |
|---|---|---|
| `jfv-credfind.py` | your **PC/Mac** (SSH/telnet to the router) | the normal case — nothing to install |
| `jfv-credfind.sh` | **on the router** (busybox) | you prefer to run it on the box itself |

Both do the same thing and print the same result: the one password that **reproduces your
router's own SIP `REGISTER` digest** — a cryptographic match, not a guess.

> **Scope — read first.** This works only on a line **you own**, using a credential **you
> extract from your own router**. Every value is yours and nothing transfers between lines.
> You need **root/admin on your own router** (SSH `:22` or telnet `:23`). The recovered
> password is a live carrier credential — **never commit or share it.**

---

## Quick start (from your PC)

```bash
# needs Python 3.8+ (uv or plain python3); no pip installs
uv run jfv-credfind.py <router-ip> <router-password>
#   e.g.  uv run jfv-credfind.py 192.168.29.1 myrouterpw
#   telnet instead of ssh:   ... 192.168.29.1 myrouterpw --telnet
#   different login user:    ... 192.168.29.1 myrouterpw --user root
```

(`192.168.29.1` is the usual JioFiber gateway; use whatever your router's LAN IP is.)

On success it prints, for example:

```
✅ VERIFIED PASSWORD:  <your-secret>
   (reproduces the box's own REGISTER digest)

Bridge env:
  IMS_IMPI=<your-impi>@<your-realm>
  IMS_PASSWORD=<your-secret>   # <- your secret; keep out of git
  SIP_REALM=<your-realm>
```

Drop those three values into your `bridge.env` and you're done with provisioning.

## Or run it on the router

```sh
# copy jfv-credfind.sh onto the box, then:
sh jfv-credfind.sh
```

---

## How it works

1. **Find the SIP log** (fast-path the known JioFiber path, else search for any file with
   an `Authorization: Digest` header).
2. **Pull an authenticated `REGISTER`** — the digest line carries `username`, `realm`,
   `nonce`, `uri`, `response`, `cnonce`, `nc`, `qop` (a standard RFC 3261/2617 header).
3. **Find the voice daemon** (known names, else probe `/proc/*/comm`) and **dump its
   `[heap]`/`[stack]`** as printable strings — the decrypted password lives there.
4. **Verify offline:** for every candidate token, compute
   `HA1 = MD5(username:realm:token)`, `HA2 = MD5(METHOD:uri)`,
   `MD5(HA1:nonce:nc:cnonce:qop:HA2)` and compare to the captured `response`.
   The token that reproduces it **is** your password — proven, no live registration needed.

The `.py` version does all tokenizing and hashing **on your PC** (pure stdlib `hashlib`),
so the router only has to dump memory — no dependence on the box's `awk`/`tr`, which vary
across firmware.

## Portability

It **fast-paths** the JioFiber layout and otherwise **discovers** everything (log location,
voice process, realm from the header, the SIP method), then **self-diagnoses** — it prints
which log it used, which PID(s) it read, and how many digest lines / tokens it found, so on a
different ONT/firmware you can see exactly which step matched or needs adjusting. It keys off
the **standard SIP Authorization header**, not vendor-specific paths, so the approach carries
to other IMS/VoLTE routers that log the digest.

## Requirements

- **Root/admin on your own router** over SSH `:22` (dropbear) or telnet `:23`.
- The router logs an authenticated SIP `REGISTER` (most ENG/debug voice builds do). If none
  is present, trigger a fresh registration (restart the voice app) and re-run.
- `python3` on your PC for `jfv-credfind.py`; busybox `strings`/`dd`/`grep`/`md5sum` on the
  box for `jfv-credfind.sh`.

## Troubleshooting

| Symptom | Meaning / fix |
|---|---|
| `couldn't get a clean session` | wrong IP/password, or a flaky link — try `--telnet`, raise `--tries` |
| `no authenticated SIP digest found` | the voice daemon isn't logging digests, or the log wasn't located — restart the voice app to force a fresh `REGISTER`, then retry |
| `no candidate tokens` | the voice process wasn't found or its memory wasn't readable (need root) |
| `no memory token reproduced any digest` | the plaintext may be held only briefly around a `REGISTER` — re-run right after a fresh registration |
