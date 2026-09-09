#!/usr/bin/env python3
"""Offline unit tests for jfv-credfind.py's verify(). No network/router needed.

Run:  python3 tests/test_verify.py   (exits non-zero on any failure)

Covers the digest algorithms and edge cases that have actually bitten real users:
plain MD5, MD5-sess, SIM-based AKA bailout, header-vs-XML realm, missing password,
and mixed AKA+MD5 log lines.
"""
import importlib.util, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "scripts", "jfv-credfind.py")
spec = importlib.util.spec_from_file_location("jfv", SCRIPT)
jfv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jfv)
md5 = jfv.md5


def mk(un, realm, pw, *, nonce="abcdef123456", cnonce="deadbeef", nc="00000001",
       uri=None, method="REGISTER", qop="auth", algo="MD5", sess=False):
    uri = uri or ("sip:" + realm)
    ha1 = md5(f"{un}:{realm}:{pw}")
    if sess:
        ha1 = md5(f"{ha1}:{nonce}:{cnonce}")
    ha2 = md5(f"{method}:{uri}")
    resp = md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}") if qop else md5(f"{ha1}:{nonce}:{ha2}")
    return (f'Authorization: Digest username="{un}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", response="{resp}", cnonce="{cnonce}", nc={nc}, qop={qop}, algorithm={algo}')


UN = "919000000000@x.wln.ims.jio.com"
REALM = "x.wln.ims.jio.com"
PW = "TestPass_42-with/special._chars+="
TOKS = {"garbage_token_1", "another_decoy_9", PW, "libc_2.31_stuff"}

FAILS = []
def check(name, got, ok):
    tag = "PASS" if ok else "FAIL"
    print(f"[{tag}] {name}: {got}")
    if not ok:
        FAILS.append(name)


# T1: plain MD5 recovers the password
r = jfv.verify([mk(UN, REALM, PW)], TOKS)
check("plain MD5", r, bool(r) and r[0] == PW and r[3] == "REGISTER" and r[4] == "MD5")

# T2: MD5-sess computes HA1 as a session key and still recovers
r = jfv.verify([mk(UN, REALM, PW, algo="MD5-sess", sess=True)], TOKS)
check("MD5-sess", r, bool(r) and r[0] == PW and r[4] == "MD5-sess")

# T3/T4: AKA algorithms are flagged unrecoverable, not silently failed
r = jfv.verify([mk(UN, REALM, PW, algo="AKAv1-MD5")], TOKS)
check("AKAv1-MD5 bailout", r, r == ("__AKA__", "AKAv1-MD5"))
r = jfv.verify([mk(UN, REALM, PW, algo="AKAv2-MD5-sess", sess=True)], TOKS)
check("AKAv2-MD5-sess bailout", r, r == ("__AKA__", "AKAv2-MD5-sess"))

# T5: header realm (used for HA1) differs from XML realm — header must win
r = jfv.verify([mk(UN, "other.example.com", PW)], TOKS)
check("header realm wins", r, bool(r) and r[0] == PW and r[2] == "other.example.com")

# T6: password not among the tokens -> None (no false positive)
r = jfv.verify([mk(UN, REALM, PW)], {"only", "decoys", "here"})
check("no match -> None", r, r is None)

# T7: a mix of an AKA line and a plain MD5 line -> skip AKA, recover from MD5
r = jfv.verify([mk(UN, REALM, PW, algo="AKAv1-MD5"), mk(UN, REALM, PW)], TOKS)
check("mixed AKA+MD5", r, bool(r) and r[0] == PW and r[4] == "MD5")

if FAILS:
    print(f"\n{len(FAILS)} test(s) FAILED: {FAILS}")
    sys.exit(1)
print("\nall verify() tests passed")
