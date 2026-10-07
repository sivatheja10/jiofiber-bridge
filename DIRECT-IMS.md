# Advanced: register directly to the IMS core (P-CSCF)

The default path (documented in the main README) registers the bridge to the
router's on-box **JUICE** server, exactly as the router's own VoIP client does.
This document describes the alternative: instead of registering to JUICE, the
bridge registers **straight to Jio's IMS core** — the P-CSCF — over IPv6/TLS
using a **static digest credential** recovered from your own router. It removes
the rotating local password, the device whitelist and the dependence on JUICE
the software, but it is a bigger step, it talks to a live carrier core, it
*still* requires a device on the Jio LAN, and it **competes with the router for
the line's single registration** (next section). Enable it with `DIRECT_IMS=1`.

> **Scope & safety — read first.**
> - Use this **only on your own line**. The digest credential is *yours*,
>   recovered from *your* router — nobody else's.
> - **Registrations are NOT additive.** The core keeps **one** registration per
>   line. Registering directly **displaces the router's own registration**, and
>   the router re-registers and displaces yours. See
>   [One registration per line](#one-registration-per-line) before enabling this.
> - You are talking to a **live carrier IMS core**. Go slowly, change one thing
>   at a time, and don't hammer REGISTER.
> - **Never commit or share the recovered password.** Keep it out of git and out
>   of any pasted logs.

## One registration per line

An earlier version of this document said the direct registration "coexists"
with the router's. **That was wrong.** It was measured at moments when the
router's registration had already died, so only one binding existed at a time.

What actually happens:

- The core keeps **one contact per line**. Every device shares the line's single
  private identity (IMPI), and the core doesn't run the RFC 5626 / 3GPP
  "multiple registrations" mechanism: it accepts `reg-id` and `Supported: outbound`
  but never answers with `Require: outbound`. In practice a new contact from the
  same IMPI **replaces** the previous one, which matches the single-registration
  rule in 3GPP TS 24.229 §5.4.1.2.2. A distinct `+sip.instance` doesn't help.
- When the bridge registers, the router's JUICE receives a reg-event `NOTIFY`
  with its contact `state="terminated" event="rejected"`, and it normally
  re-registers within about a second. **That displaces the bridge.** The bridge
  isn't subscribed to reg-event, so it keeps believing its `200 OK`, and every
  outbound INVITE gets **`403 Forbidden - 10009`** from the P-CSCF within about
  10 ms, with no `100 Trying`.
- **Only the most recent registrant can place calls.** Whichever device holds
  the binding also receives inbound calls (JUICE passes them on to its LAN
  clients).
- **Running both is fragile.** Each bridge re-REGISTER (hourly with
  `IMS_REG_EXPIRES=3600`) knocks the router off. If JUICE ever fails to
  re-register, it may not retry at all; we saw it stay dead for six days. Every
  call through the router (and through the default JUICE-mode bridge) then fails
  with an instant local **`503 Service Unavailable`**.

**Use direct mode as a replacement or a cold standby, not alongside JUICE.**
Run the default JUICE path, and start `DIRECT_IMS=1` only while JUICE has
confirmed lost its upstream registration. Jio's own multi-device design works
the same way: JioJoin, the set-top box and LAN softphones all register to JUICE,
which holds the one upstream registration.

## What it does and does NOT give you

**Removes** your dependence on **JUICE (the software)**:
- the device **whitelist** JUICE enforces,
- the **rotating local password** JUICE hands out,
- the router acting as your **registrar**.

**Does NOT remove** your dependence on the router **hardware**. The P-CSCF lives
on Jio's internal network and is reachable **only from the Jio access network** —
a public VPS **cannot** reach it (verified). So:
- the bridge must run on a device **on the Jio LAN**, and
- **nothing works if the router/ONT is offline.**

"Remote from anywhere" access does not come from this core-facing leg. It comes
from the **softphone → Asterisk → overlay** side of the stack (the trunk leg),
exactly as with the JUICE path. This document only changes how the *Jio-facing*
leg registers.

## Requirements

- A **Linux host on the Jio LAN** that has a **global Jio IPv6**. Confirm with:
  ```bash
  ip -6 addr show scope global    # must show a 2405:… address
  ```
- **Root on your own router**, to recover the static digest credential.
- The **patched pjproject build** (identical to Step 1 of the main README).
- The static credential **recovered and verified** with
  [`scripts/jfv-credfind.py`](scripts/jfv-credfind.py). See
  [`scripts/CREDENTIAL-RECOVERY.md`](scripts/CREDENTIAL-RECOVERY.md) for the full
  procedure.

## Step 1 — discover your P-CSCF

Ask the router's DNS resolver (the usual JioFiber gateway is `192.168.29.1`;
`<REALM>` is your home domain, e.g. `<circle>.wln.ims.jio.com`):

```bash
dig NAPTR <REALM> @192.168.29.1
dig SRV   _sips._tcp.<REALM> @192.168.29.1     # -> port 5061, host pcscf.<REALM>
dig AAAA  pcscf.<REALM> @192.168.29.1          # -> a pool of P-CSCF IPv6 addresses
```

Pick one P-CSCF IPv6 from the pool; call it `<PCSCF_V6>`. Sanity-check the TLS
endpoint:

```bash
openssl s_client -connect "[<PCSCF_V6>]:5061" -servername <REALM>
```

You want:
- a **Jio IMS certificate**, and
- **`No client certificate CA names sent`** — i.e. the core is **not** asking for
  mutual TLS.

Then confirm the auth challenge is **plain MD5 digest**: the `WWW-Authenticate`
header must carry `qop="auth"` and **must NOT** carry `algorithm=AKAv1-MD5`. If
you see `AKAv1-MD5`, your line uses **SIM-based IMS-AKA** and this static-digest
method **will not work** for you.

## Step 2 — enable direct mode

Set `DIRECT_IMS=1` in `bridge.env` and fill in the block below. In direct mode
the Jio-leg identity and password come from these env vars, **not** from argv.

| Variable | Meaning |
|---|---|
| `DIRECT_IMS` | `1` to enable direct-to-P-CSCF mode (default path is JUICE). |
| `IMS_IMPI` | Digest **username**: `<MSISDN>@<REALM>` (no `+`). |
| `IMS_PASSWORD` | **Static** digest password from `jfv-credfind.py`. **Never commit.** |
| `IMS_REALM` | Digest realm: `<circle>.wln.ims.jio.com`. |
| `IMS_AOR` | Address-of-record: `sip:+<MSISDN>@<REALM>`. |
| `PCSCF_V6` | P-CSCF IPv6, **bare** (no brackets), e.g. `2405:…`. |
| `PCSCF_PORT` | P-CSCF TLS port: `5061`. |
| `JIO_LAN_V6` | This host's **Jio global IPv6**; binds the TLS6 transport + media. |
| `SIP_LOCAL_PORT` | Local SIP source port: `5062`. |
| `RTP_LOCAL_PORT` | Local RTP base port: `4000`. |
| `IMS_REG_EXPIRES` | REGISTER `Expires`, in seconds: `3600`. |
| `IMS_UA` | `User-Agent` to present: `JCOW407/JUICEJFV-1.3.32`. |
| `IMS_PANI` | `P-Access-Network-Info`: `GPON;PSAPId=+<MSISDN>`. |
| `IMS_KEEPALIVE` | TLS/TCP keepalive interval, in seconds: `10`. |

Example `bridge.env` fragment:

```bash
DIRECT_IMS=1
IMS_IMPI=<MSISDN>@<REALM>
IMS_PASSWORD=<from jfv-credfind.py — never commit>
IMS_REALM=<circle>.wln.ims.jio.com
IMS_AOR=sip:+<MSISDN>@<REALM>
PCSCF_V6=<PCSCF_V6>
PCSCF_PORT=5061
JIO_LAN_V6=<this host's 2405:… global IPv6>
SIP_LOCAL_PORT=5062
RTP_LOCAL_PORT=4000
IMS_REG_EXPIRES=3600
IMS_UA=JCOW407/JUICEJFV-1.3.32
IMS_PANI=GPON;PSAPId=+<MSISDN>
IMS_KEEPALIVE=10
```

**On the positional args:** the binary still takes its 5 positional arguments,
but in direct mode `argv[1]`, `argv[2]`, and `argv[5]` (the Jio-leg
identity/password) are **unused** — pass placeholders. `argv[3]` (bridge overlay
IP) and `argv[4]` (Asterisk overlay IP) are **still used** for the trunk leg.

## The must-haves (why each matters)

Each row is a hard-won requirement; omit it and you get the failure named.

| Requirement | Why it matters — the failure if omitted |
|---|---|
| `+u.jio.jfv;q=0.5` in the REGISTER `Contact` | The router's own capability tag; advertise it the same way. We originally credited it with fixing **`403-10009`** on outbound, but that test predates the [one-registration](#one-registration-per-line) finding, so a displaced registration may have been the real cause. Keep it either way. |
| Initial REGISTER carries a **typed** empty-auth header (pjsip `auth_pref.initial_auth`, realm set **specifically**, not `*`) | Without it the core returns **`483 Too Many Hops`**. Do **not** hand-add an empty `Authorization` header — it gets duplicated on the 401 retry and causes a **401 loop**. |
| `Expires >= 3600` | Else **`423 Interval Too Brief`**. |
| **10 s** TLS/TCP keepalive | The core/NAT drops an idle flow at ~15–20 s. The result is a **"ghost" registration**: 200 OK'd but refuses calls. This is the master fix for "registered but no calls". |
| **Transport pinning** (`c.transport_id` = the TLS6 transport) | The core's `Record-Route` has no `transport=`; without pinning the in-dialog 2xx-ACK fails, so calls connect with **no audio and drop at ~30 s**. |
| **IPv6 media** (`ipv6_media_use = IPV6_ONLY`, RTP bound to the Jio IPv6) | Jio's media relay is **IPv6**; media must leave from the Jio IPv6. |
| `User-Agent: JCOW407/JUICEJFV-1.3.32` and `P-Access-Network-Info: GPON;PSAPId=+<MSISDN>` | The core expects an **on-line fixed-line device profile**. |

## Response-code decoder

| Response | Meaning / fix |
|---|---|
| `483 Too Many Hops` | Missing **typed initial-auth** (`IMS_INIT` / `auth_pref.initial_auth`). |
| `423 Interval Too Brief` | `Expires` < 3600 — raise `IMS_REG_EXPIRES`. |
| `401` | **Normal** challenge; answered by the digest. |
| `403-10009` (on outbound, within ~10 ms, no `100 Trying`) | **Your registration has been displaced**, almost always by the router's JUICE re-registering ([one registration per line](#one-registration-per-line)). Less likely: `+u.jio.jfv` is missing from the REGISTER `Contact`. |
| `503 Service Unavailable` with `User-Agent: JCOW…/JUICEJFV…` (JUICE mode) | Generated **locally** by the router: JUICE has lost its upstream registration. Restart the router's voice service, or reboot the router. |
| `200 OK` (with `P-Associated-URI`) | **Registered.** |
| `481` (on de-REGISTER) | Reused the register's nonce — get a fresh challenge, or just let it expire. |
| `480` (on outbound) | Wrong number format. Dial **`91` + national number** with **no leading `+`**; toll-free `1800…` works as-is. |

## Verify success

You have a good registration when:
- the log shows **`>>> acc=0 REG status=200 OK`**, and the `200` carries a
  **`P-Associated-URI`**.

A `200 OK` doesn't prove you still hold the binding, and the router having a
TLS connection to the core only shows the router is connected, not which of you
holds the line. The real proof is a **live call**: place and
answer one, confirm **audio both ways**, and confirm it does **not drop at
~30 s**. That single test exercises the transport-pinning and IPv6-media
requirements above. If it gets `403-10009` right after a good registration, the
router has taken the line back.
