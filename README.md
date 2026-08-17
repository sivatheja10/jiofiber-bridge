# jiofiber-bridge

**Use your JioFiber landline from anywhere in the world — outbound *and* inbound — on an ordinary SIP app.**

JioFiber (and other Jio Fiber Voice / "JioCall over broadband" lines) delivers voice through Jio's IMS core using a proprietary client called **JUICE** that normally only runs on the ISP-supplied router or the JioCall app. This project puts a small headless **bridge** on the same LAN as the router, registers to the IMS core exactly the way a genuine JioCall device does, and re-presents the line as a plain SIP trunk. Point Asterisk at that trunk and any softphone (Zoiper, Groundwire, Linphone, a desk phone) can place and receive calls on the landline from any network on earth.

> Getting **outbound** working is fiddly but documented in scattered places. Getting **inbound** to actually ring your remote phone is the part that defeats most people — the IMS core silently forks the call only to devices that advertise the right RCS/MMTEL feature set with the right client identity. This repo solves that. See [The three hard problems](#the-three-hard-problems).

Everything here is a **template**. There are **no** real numbers, IP addresses, passwords, or provider hostnames in the tree — you fill those into `bridge.env` and the Asterisk configs. Adapt the Jio-specific realm/registrar values to whatever your IMS provider uses.

---

## Contents

- [Architecture](#architecture)
- [The three hard problems](#the-three-hard-problems)
- [What you need](#what-you-need)
- [Repo layout](#repo-layout)
- [Step 1 — Build the patched pjproject](#step-1--build-the-patched-pjproject)
- [Step 2 — Configure the bridge](#step-2--configure-the-bridge)
- [Step 3 — Provision the device (whitelist + password)](#step-3--provision-the-device-whitelist--password)
- [Step 4 — Run the bridge as a service](#step-4--run-the-bridge-as-a-service)
- [Step 5 — Asterisk: your phones + the trunk](#step-5--asterisk-your-phones--the-trunk)
- [Step 6 — Softphones](#step-6--softphones)
- [Step 7 — Monitoring & self-heal](#step-7--monitoring--self-heal)
- [Number formats, DTMF, caller-ID](#number-formats-dtmf-caller-id)
- [Quirks & gotchas](#quirks--gotchas)
- [The 403 decoder](#the-403-decoder)
- [Security notes](#security-notes)
- [Acknowledgements](#acknowledgements)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Architecture

```
  Remote phone (anywhere)                     Your home (behind JioFiber)
  ┌───────────────────┐                       ┌──────────────────────────┐
  │  Softphone         │   SIP/RTP over        │  ISP router (JUICE/IMS)   │
  │  (Zoiper/          │   the overlay net     │  192.168.x.1 : TLS :5068  │
  │   Groundwire/…)    │                       │        ▲                  │
  └─────────┬─────────┘                        │        │ TLS reg + AMR    │
            │ SIP register                     │        │                  │
            ▼                                  │  ┌─────┴──────────────┐   │
  ┌───────────────────┐   overlay (Tailscale/  │  │  jiofiber-bridge   │   │
  │  Asterisk (VPS)    │◄──WireGuard) SIP trunk │  │  (this project)    │   │
  │  public registrar  │   PCMU over overlay    │  │  B2BUA, on the LAN │   │
  │  contexts:         │──────────────────────► │  │  AMR◄►PCMU         │   │
  │  from-phones       │                        │  └────────────────────┘   │
  │  from-jio          │                        └──────────────────────────┘
  └───────────────────┘
```

Two hops, on purpose:

1. **The bridge** must sit **on the home LAN** because the IMS core only talks to the router, and because RTP to/from the router has to originate on the LAN interface. It is a **B2BUA** (back-to-back user agent): one leg speaks JUICE/IMS (TLS signalling, **AMR / AMR-WB** audio) to the router; the other leg is a plain **SIP/PCMU** trunk. It transcodes AMR↔PCMU through pjproject's conference bridge.
2. **Asterisk** lives on a small public box (VPS) and is where your phones actually register. It normalizes dialed numbers, rings your phones on inbound, and carries caller-ID. The bridge and Asterisk find each other over a private **overlay network** (Tailscale or WireGuard) so no SIP port is ever exposed to the internet from your home, and the VPS only exposes the phone-facing registrar.

Why split it? The home end has a dynamic residential IP and can't safely expose SIP; the VPS has a stable address your phones can always reach. The overlay glues them with zero port-forwarding at home.

---

## The three hard problems

**1. Identity — the IMS core only talks to a "known" device.**
JUICE registration uses RFC 5626 outbound with a `+sip.instance` that Jio expects in a very specific shape (`<00000000-0000-1000-8000-0000XXXXXXXX>`, uppercase, **no** `urn:uuid:` prefix), plus a rotating per-device password and a device that has been **whitelisted** against your account via an OTP flow. Stock pjsua formats the instance differently and the core **silently drops** the REGISTER — no error, just nothing. Fixed by [a pjproject patch](patches/pjproject-jiofiber.patch) and the [provisioning step](#step-3--provision-the-device-whitelist--password).

**2. Media — AMR must be negotiated *and echoed correctly* or calls die at ~1–2 min.**
The core offers AMR/AMR-WB with a `mode-set` and expects you to advertise AMR in your SDP with a matching `mode-set`. If you accept the call but don't echo `mode-set` back, audio flows for a minute or two and then the core tears the call down (`de-registration by user`, cause 500). Fixed in the [AMR patch](patches/pjproject-jiofiber.patch). One-way audio is a *separate* problem — see [multi-homed RTP](#quirks--gotchas).

**3. Inbound forking — the core only rings devices that advertise the full RCS/MMTEL feature set.**
This is the one nobody documents. On an incoming call the IMS core forks INVITEs only to registered contacts whose registration advertised the right IMS feature tags (`+g.3gpp.icsi-ref` mmtel, `+g.3gpp.iari-ref` rcs, `+g.gsma.rcs.telephony`, video) **and** a JioCall-like `User-Agent`. Register with only `mmtel` (the "obvious" tag) and outbound works but **your phone never rings**. The bridge sets the full tag set in `reg_contact_params` — see `b2bua/jio_b2bua.c` and the [feature-tag note](#quirks--gotchas).

---

## What you need

- **A machine on the home LAN**, always on, same subnet as the JioFiber router. A tiny always-on box, an old laptop, a Pi-class device, or a Proxmox/VM works. Linux with root (the identity trick uses `unshare --uts`).
- **A small public VPS** for Asterisk (1 vCPU / 1 GB is plenty).
- **An overlay network** joining the two: [Tailscale](https://tailscale.com) (easiest) or WireGuard. All examples use overlay IPs like `100.x.x.x`.
- Build tools on the home box: `gcc make` + the AMR codec dev headers (`libopencore-amrnb-dev`, `libopencore-amrwb-dev` or vendored opencore-amr).
- **Asterisk 18+** on the VPS.
- Your **IMS account details**: the public identity (`sip:<number>@<realm>`), the auth username, the IMS **realm**, and the **registrar/router** address. For JioFiber these look like `sip:<number>@<region>.wln.ims.jio.com` and the router at `192.168.x.1:5068` over TLS. Yours may differ — put them in `bridge.env`.
- The ability to trigger your provider's **device-add OTP** (for Jio, via the JioCall/JFC provisioning flow).

---

## Repo layout

```
b2bua/jio_b2bua.c            The B2BUA. Reads identity from env; args are the secrets/IPs.
patches/pjproject-jiofiber.patch   3 patches: AMR mode-set, +sip.instance format, contact_params guard.
patches/config_site.h        pjproject build config (AMR NB/WB on, video off).
bridge.env.example           Copy to bridge.env and fill in. Sourced by the scripts.
DIRECT-IMS.md                Advanced: register straight to the P-CSCF (DIRECT_IMS=1), bypassing JUICE.
scripts/register.sh          Sets device hostname, fetches the rotating password, runs the B2BUA.
scripts/healthcheck.sh       Verifies the TLS reg is up; restarts + alerts on failure.
scripts/jfv-credfind.py      Recover+VERIFY your line's IMS SIP digest password (from your PC). See scripts/CREDENTIAL-RECOVERY.md.
scripts/jfv-credfind.sh      Same, but runs on the router (busybox). Own line only.
asterisk/pjsip.conf          Your phones (6001/6002) + the static trunk to the bridge.
asterisk/extensions.conf     Number normalization (out) + ring-all with caller-ID (in).
asterisk/rtp.conf            RTP port range.
systemd/jiofiber-bridge.*    Run the bridge under unshare, restart-always.
systemd/jiofiber-health.*    Timer that runs the health check every 2 min.
```

---

## Step 1 — Build the patched pjproject

The bridge links against pjproject with three source patches. Stock pjproject will *not* register to Jio.

```bash
git clone https://github.com/pjsip/pjproject
cd pjproject
git apply /path/to/jiofiber-bridge/patches/pjproject-jiofiber.patch
cp /path/to/jiofiber-bridge/patches/config_site.h pjlib/include/pj/config_site.h

./configure --disable-video --enable-shared
make dep && make

# Build the bridge as a pjsua sample so it links against the tree you just built:
cp /path/to/jiofiber-bridge/b2bua/jio_b2bua.c pjsip-apps/src/samples/
make -C pjsip-apps/build samples
# Binary lands in pjsip-apps/bin/samples/<target-triple>/jio_b2bua
```

What the patches do (see the file for the exact diffs):

- **AMR `mode-set` advertise** (`pjmedia .../opencore_amr.c`): puts a `mode-set` back into the SDP fmtp (NB `0,1,2,3,4,5,6,7`, WB adds `8`). Without this, calls drop after ~1–2 min.
- **`+sip.instance` format** (`pjsip/.../pjsua_acc.c`): emits the instance as `<00000000-0000-1000-8000-0000XXXXXXXX>` — the shape Jio requires. Without this, REGISTER is silently dropped.
- **`contact_params` accumulation guard** (`pjsua_acc.c`): stops the RFC 5626 instance param being appended on every re-register, which after many hours produces `PJ_ETOOSMALL` and split-second outbound failures.

---

## Step 2 — Configure the bridge

```bash
cp bridge.env.example bridge.env
$EDITOR bridge.env
```

Fill in identity + topology. Nothing here is a secret except `SIP_AUTH_USER` context and the password (which is fetched at runtime, not stored):

| Var | Meaning | Example |
|---|---|---|
| `SIP_PUBLIC_ID` | Your public IMS identity | `sip:<number>@<region>.wln.ims.jio.com` |
| `SIP_AUTH_USER` | Auth username | `<number>@<region>.wln.ims.jio.com` |
| `SIP_REALM` | IMS realm | `<region>.wln.ims.jio.com` |
| `REGISTRAR` | Router/registrar (TLS) | `sip:192.168.x.1:5068;transport=tls` |
| `ROUTER_IP` | Router LAN IP (for RTP + health) | `192.168.x.1` |
| `BRIDGE_OVERLAY_IP` | This box on the overlay | `100.x.x.x` |
| `ASTERISK_OVERLAY_IP` | Asterisk on the overlay | `100.x.x.y` |
| `DEVICE_HOST` | Device hostname/identity | `homebridge01` |
| `BASE` / `BIN` / `JFC` | Paths to install dir, binary, provisioning helper | |
| `NTFY_TOPIC` | ntfy topic for alerts (optional) | |

The bridge auto-detects which LAN IP to bind RTP to (`ip -4 route get $ROUTER_IP`), so you don't hardcode it. The overlay side of RTP binds to `BRIDGE_OVERLAY_IP`. This split is what fixes one-way audio (see quirks).

---

## Step 3 — Provision the device (whitelist + password)

The IMS core will only accept a device that your account has explicitly added, and the device password **rotates every time you fetch it**. So provisioning is: (a) add the device with a one-time OTP, (b) always fetch the *current* password right before you register.

1. **Pick a stable device identity** (`DEVICE_HOST`, e.g. `homebridge01`). The bridge runs under `unshare --uts` and sets this as the process's hostname — the IMS provisioning ties the whitelist to that identity **without** changing your host machine's real hostname.
2. **Trigger the add-device OTP** from your provider's app/flow for your number. For Jio this is the JioCall / JFC provisioning path; you'll receive an OTP by SMS.
3. **Run the provisioning helper with `op_type=add`** and the OTP to whitelist `DEVICE_HOST`. (`scripts/register.sh` calls the same helper with `-l 5` to *fetch* the current password on every start; the add is a one-time variant of that call.)
4. From then on you never store the password — `register.sh` fetches the live one each boot.

> If you re-provision with a new OTP, the password rotates; any previously fetched password is now invalid (this is the source of most `403 Invalid password` confusion — see the [403 decoder](#the-403-decoder)).

### Alternative: recover the *static* upstream digest password

The rotating password above is JUICE's own local credential. Your ONT also holds a
**static** IMS digest password — the one it uses to register **upstream to the core**. If
you need that (to audit your own line, or to register directly to the core), recover **and
cryptographically verify** it from your own router with:

```bash
uv run scripts/jfv-credfind.py <router-ip> <router-password>
# e.g.  uv run scripts/jfv-credfind.py 192.168.29.1 <router-pw>   (add --telnet if it uses telnet)
```

It finds the token in the router's voice-daemon memory that reproduces the router's own SIP
`REGISTER` digest — a verified match, not a guess — and prints `IMS_IMPI` / `IMS_PASSWORD` /
`SIP_REALM` for you. Full usage, the on-box variant, and portability notes are in
[`scripts/CREDENTIAL-RECOVERY.md`](scripts/CREDENTIAL-RECOVERY.md). **Your own line only; never
commit the recovered secret** (`.gitignore` already keeps `*.env` out of git).

Once you have that static credential you can register **directly to the IMS core (P-CSCF)**,
bypassing JUICE entirely — the `DIRECT_IMS=1` option. See [`DIRECT-IMS.md`](DIRECT-IMS.md).

---

## Step 4 — Run the bridge as a service

```bash
sudo mkdir -p /opt/jiofiber-bridge
sudo cp -r b2bua scripts bridge.env /opt/jiofiber-bridge/
sudo cp <pjproject>/pjsip-apps/bin/samples/*/jio_b2bua /opt/jiofiber-bridge/bin/
sudo cp systemd/jiofiber-bridge.service systemd/jiofiber-health.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now jiofiber-bridge.service
sudo systemctl enable --now jiofiber-health.timer
```

`register.sh` runs the binary as:

```
jio_b2bua <auth_user> <password> <bridge_overlay_ip> <asterisk_overlay_ip> <bridge_lan_ip>
```

- `acc_jio` → registers to the router over **TLS:5062**, advertises the full IMS feature tags, binds RTP to the **LAN** IP:4000.
- `acc_trunk` → plain **UDP:5070** to Asterisk, binds RTP to the **overlay** IP:5000.

Check it's up: `journalctl -u jiofiber-bridge -f` should show a `200 OK` to REGISTER and the feature tags in the Contact.

---

## Step 5 — Asterisk: your phones + the trunk

Copy `asterisk/*.conf` to `/etc/asterisk/` on the VPS and fill in the placeholders:

- `<ASTERISK_PUBLIC_IP>` → the VPS public IP (for `external_media_address`/`external_signaling_address`).
- `<BRIDGE_OVERLAY_IP>` → the bridge's overlay IP (the trunk `contact` and `identify` match).
- `<RANDOM_PASSWORD_6001>` / `<RANDOM_PASSWORD_6002>` → strong per-phone secrets.

`pjsip.conf` defines two phone endpoints (`6001`, `6002`) with `qualify_frequency=30` (keeps NAT open and shows reachability), and a static `jio-trunk` identified by the bridge's overlay IP (no auth needed — it's a trusted private link). `local_net=100.64.0.0/10` keeps Asterisk from NAT-rewriting overlay traffic.

`extensions.conf`:
- **`from-phones`** normalizes what you dial into what the core accepts, then sends it to `jio-trunk` (see [number formats](#number-formats-dtmf-caller-id)).
- **`from-jio`** takes inbound calls the bridge presents to request-URI user `s`, lifts the caller number out of the `X-Jio-Caller` header the bridge injects, sets it as CALLERID, and rings **both** phones in parallel for 35 s.

`rtp.conf` just sets a small RTP port range — open those UDP ports plus the SIP port (`5560`) on the VPS firewall, scoped to your phones where you can.

Reload: `asterisk -rx 'core reload'`.

### Optional: an inbound IVR (menu)

Instead of ringing every phone at once, you can answer with a menu ("press 1 for …, press 2 for …") and route by keypress. Use `asterisk/extensions-ivr.conf` as a drop-in replacement for the `[from-jio]` block, add a `4001` endpoint (already templated in `pjsip.conf`), and record a prompt.

Record the menu prompt as an **8 kHz mono, 16-bit PCM WAV**. Two things bite here — both cost a silent caller before you notice:

**1. The WAV must be canonical** — the `data` chunk immediately after `fmt `. Asterisk's reader rejects extra header chunks (macOS `afconvert` inserts an `FLLR` filler chunk; `ffmpeg` adds a `LIST/INFO` chunk unless you pass `-fflags +bitexact`). `sox` reliably writes a clean header. Verify with `asterisk -rx 'file convert menu.wav /tmp/t.ulaw'` — it must exit 0.

```bash
say -v Samantha -o menu.aiff "To speak with Alex, press 1. To speak with the family, press 2."
sox menu.aiff -b 16 -e signed-integer -r 8000 -c 1 menu.wav
```

**2. Put the file where Asterisk actually resolves it — or use an absolute path.** The `custom/` sounds prefix and the language-prefix search depend on `astdatadir`, which is distro-specific (`core show settings | grep -i 'data directory'` — often `/usr/share/asterisk`, with `sounds/custom` symlinked to `/usr/local/share/asterisk/sounds`). The foolproof approach is to reference the prompt by **absolute path** in the dialplan, which skips all sounds-dir/language resolution:

```
same => n(menu),Background(/usr/local/share/asterisk/sounds/menu)   ; no extension
```

Drop `menu.wav` at that path (`chown asterisk`) and you're done. (`asterisk/extensions-ivr.conf` uses this absolute-path form.)

The IVR **answers** the call to play the menu — that's expected (the caller hears the menu, not ringback). DTMF from the caller reaches Asterisk over the same RFC 4733 relay path the bridge already uses, so digit collection works on live PSTN callers. `dtmf_mode=rfc4733` must be set on the trunk (it is in the template).

### Using a different PBX (Grandstream UCM, FreePBX, …): IVRs must ANSWER, not play early media

You don't have to use the shipped Asterisk configs — anything that speaks SIP can sit on the trunk side. One rule matters, and it's the one that bites people migrating from an **analog (FXO) trunk**:

> **An interactive IVR must answer the call (send `200 OK`) before playing its prompt.** Playing the prompt as *early media* (`183 Session Progress`, no answer) leaves the caller's leg unanswered — the caller "keeps ringing, no answer, no ring tone", and the core's ring timer tears the call down after ~a minute regardless.

This is answer supervision, and it's the industry-standard behavior (RFC 3960 limits early media to call-progress indications like ringback and announcements): billing starts at answer, unanswered calls are killed by the core's ring timer, and pre-answer DTMF (RFC 4733) is not reliably relayed by carrier cores — so a pre-answer menu can't even collect digits dependably. An FXO trunk masked all of this because analog lines have **no** answer supervision — the PBX can put any audio on the wire without ever signaling answer. SIP makes the distinction real.

Concretely, on a **Grandstream UCM**: point the inbound route of the bridge trunk at an **IVR (auto-attendant)** — which answers before playing — rather than a ring group with a "custom ringback tone", and disable **Enable Early Media** on the trunk's advanced settings. On **FreePBX**: inbound route → IVR destination (answers by default).

If you genuinely can't make your PBX answer first, the bridge has an escape hatch: set `EARLY_ANSWER=1` in `bridge.env`. On the PBX's first `183` the bridge answers the caller immediately (the SBC "answer on early media" pattern), so the caller hears the prompt and the ring timer never fires. Trade-off: the call is answered — and billed — from that moment, even if nobody ever picks up. Default is off.

**Caller-ID on other PBXes:** the bridge presents the caller's number in the custom `X-Jio-Caller` header (which the shipped Asterisk dialplan reads) **and** in standard `P-Asserted-Identity` / `Remote-Party-ID` headers. On a UCM/FreePBX, just enable "trust inbound identity headers (PAI/RPID)" on the trunk and inbound caller-ID works with no dialplan.

---

## Step 6 — Softphones

Register each phone to Asterisk on the VPS public IP, port `5560`:

- **iOS:** **Groundwire** is strongly recommended — it holds registration in the background via push. Linphone/Zoiper on iOS **drop registration when backgrounded**, so inbound won't ring reliably.
- **Android:** Zoiper or Linphone both hold registration fine.
- Codec: **PCMU (G.711 µ-law)** only on the phone side. DTMF: **RFC 4733**.

Give phone 1 → `6001`, phone 2 → `6002` (both ring together on inbound; add more endpoints the same way).

---

## Step 7 — Monitoring & self-heal

`scripts/healthcheck.sh` (run every 2 min by `jiofiber-health.timer`) checks there is an **established TLS connection to `ROUTER_IP:5068`**. If not, it restarts `jiofiber-bridge` and (optionally) posts to an [ntfy](https://ntfy.sh) topic so you get a phone alert. It also warns if the overlay is relaying through DERP instead of a direct path (added latency).

For a dashboard, point [Gatus](https://github.com/TwiN/gatus) at the VPS SIP port and the overlay, and route its alerts to the same ntfy topic.

---

## Number formats, DTMF, caller-ID

**Dialing out** — the core is picky; `from-phones` normalizes for you so you can dial naturally:

| You dial | Sent to core | Why |
|---|---|---|
| `+<CC><10-digit mobile>` (E.164) | `0` + national 10-digit | core wants the STD `0` prefix on off-net mobiles |
| bare 10-digit mobile (starts 6–9) | `0` + the 10 digits | same |
| `0…` (already STD/landline) | as-is | already correct |
| `+<other country>` | strip the `+` | international |
| `1800…` / service numbers | as-is | |

> Off-net mobiles **must** carry the STD `0` or the core answers `484 Address Incomplete`.

**DTMF** — end-to-end via RFC 4733 on the phone side, relayed digit-for-digit by the bridge (`on_dtmf_digit` → `pjsua_call_dial_dtmf`). Digits arrive correctly in both directions. You may hear a brief warble on the tone — that's a cosmetic AMR transcoding artifact, not a delivery failure.

**Caller-ID (inbound)** — the bridge extracts the calling number from the inbound INVITE and passes it downstream in an `X-Jio-Caller` header (the shipped `from-jio` dialplan copies it into CALLERID) and in standard `P-Asserted-Identity`/`Remote-Party-ID` headers (for PBXes that trust identity headers instead — UCM, FreePBX).

---

## Quirks & gotchas

- **Silent REGISTER drop** = wrong `+sip.instance` format. Must be `<00000000-0000-1000-8000-0000XXXXXXXX>`, uppercase, no `urn:uuid:`. → instance patch.
- **Calls die at ~1–2 min** (`de-registration by user`, cause 500) = AMR `mode-set` not echoed. → AMR patch.
- **Split-second outbound failures after many hours** (`PJ_ETOOSMALL`) = `contact_params` growing on each re-register. → contact_params guard patch.
- **Outbound `PJ_ERESOLVE`** = set the outbound proxy to the router/registrar (the bridge does this).
- **`484 Address Incomplete`** on mobiles = missing STD `0`. → dialplan normalization.
- **One-way audio** = RTP bound to the wrong interface on a multi-homed box. The bridge is multi-homed (LAN + overlay); it pins `acc_jio` RTP to the **LAN** IP and `acc_trunk` RTP to the **overlay** IP. `register.sh` auto-detects the LAN IP with `ip -4 route get $ROUTER_IP`. Get this backwards and you get audio in exactly one direction.
- **Phone never rings on inbound** even though outbound works = registered with only the `mmtel` feature tag. The core forks inbound only to contacts advertising the **full** RCS/MMTEL tag set **and** a JioCall-like `User-Agent`. → the bridge's `reg_contact_params`.
- **Premature `200 OK`** = the B2BUA answered the trunk leg before the far end did. Fixed by mirroring provisional responses (180/183) and propagating the real answer/failure code across the two legs.
- **Downstream PBX IVR "keeps ringing, no answer, no audio"** (classic on Grandstream UCM after migrating from an FXO trunk) = the PBX is playing the IVR/custom ringtone as **early media** (`183`) and never answering. Configure the PBX to answer first (inbound route → auto-attendant, early media off) — see [IVRs must answer](#using-a-different-pbx-grandstream-ucm-freepbx--ivrs-must-answer-not-play-early-media) — or set `EARLY_ANSWER=1`.
- **iOS softphone stops ringing after a while** = backgrounded Linphone/Zoiper dropped registration. Use Groundwire (push).
- **~0.5 s latency** is inherent to the geographic round-trip + AMR framing; not a bug.
- **Overlay via DERP relay** adds latency — prefer a direct path; the health check warns about this.

---

## The 403 decoder

`403` from the core almost always means one of three specific things:

| 403 text | Meaning | Fix |
|---|---|---|
| **Device not whitelisted** | `DEVICE_HOST` isn't provisioned | run the add-device OTP flow with `op_type=add` and this exact hostname |
| **Invalid password** | you're using a stale password | the password rotates on every fetch — fetch it fresh (`register.sh` does this each start); don't reuse a saved one |
| (silent, no 403 at all) | wrong `+sip.instance` shape | the instance patch |

Most "it worked yesterday, `403` today" cases are a password that rotated because the device was re-fetched or re-provisioned elsewhere.

---

## Security notes

- No SIP port is exposed from your **home** — the only inbound path there is over the encrypted overlay.
- The bridge accepts trunk calls (i.e. outbound dialing) **only from `ASTERISK_OVERLAY_IP`** — anything else on the overlay gets a `403`. Overlay networks are often shared (other devices, other tailnet users); without this check any of them could dial out through your landline.
- The VPS exposes just the phone-facing registrar (`5560`) and the RTP range; firewall them to your phones' networks where practical and use strong per-phone passwords.
- The device password is **never stored** in the repo or on disk — it's fetched live at process start.
- Keep `bridge.env` and `/etc/asterisk/*.conf` (with real passwords) out of git. This repo ships only `*.example` / placeholder templates.

---

## Acknowledgements

This project stands on the shoulders of prior reverse-engineering and open-source telephony work. Huge thanks to:

- **[JFC-Group](https://github.com/JFC-Group)** — the community that first mapped out how JioFiber's JUICE/IMS client provisions and registers. In particular **[JFC-microsip](https://github.com/JFC-Group/JFC-microsip)** (the provisioning/config flow that `jfc_configure.py` derives from) and the JFC pjproject work that proved the patch path. Without their groundwork the `+sip.instance` shape, the OTP whitelist flow, and the rotating-password behaviour would have stayed a black box.
- **[pjproject / PJSIP](https://github.com/pjsip/pjproject)** — the SIP/media stack the B2BUA is built on; the three patches here are small deltas against it.
- **[opencore-amr](https://sourceforge.net/projects/opencore-amr/)** — the AMR-NB/AMR-WB codec that makes IMS audio interoperate with plain PCMU.
- **[Asterisk](https://www.asterisk.org/)** — the public registrar / dialplan front end for the phones.
- **[Tailscale](https://tailscale.com)** / **[WireGuard](https://www.wireguard.com/)**, **[ntfy](https://ntfy.sh)**, and **[Gatus](https://github.com/TwiN/gatus)** — the overlay, alerting, and monitoring glue.

This repo's contribution is the end-to-end integration — a self-healing B2BUA that also solves **inbound** forking (the IMS feature-tag set), correct AMR `mode-set` echo, and multi-homed RTP — packaged as a reproducible, fully-templated guide.

If you built on something here or spot missing attribution, please open an issue or PR.

---

## Disclaimer

This interoperates with your **own** telephone line for **personal** use, the same way the official app on your own router does. It reimplements a client to a service you pay for. Check your provider's terms; you're responsible for how you use it. Provided as-is, no warranty. Not affiliated with, or endorsed by, any ISP or provider.

---

## License

**MIT** — see [`LICENSE`](LICENSE). You may use, modify, and redistribute this repository's own source, scripts, configs, and docs; it is provided **as-is, with no warranty and no liability** (see the licence text).

One caveat, spelled out in [`NOTICE`](NOTICE): the bridge **links pjproject** (GPLv2) and the files under `patches/` are modifications to pjproject, so a **compiled binary is a GPLv2 combined work** and those patch files are GPLv2. MIT covers this repo's original code; the GPLv2 obligations come from the upstream telephony stack you build against.
