#!/usr/bin/env python3
"""Verify a HONE Flipper capture log (see ../CAPTURE_LOG.md).

  hone_chain_verify.py --pub identity.pub [--heads heads.bin] queue files in order...

Checks every frame signature (v2 and v3), every v3 prev link, and which signed
chain heads (heads.bin) the log reaches. Prints a summary; never prints keys.
Exit 1 on any bad signature or broken link."""
import argparse, hashlib, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def frames(path):
    b = open(path, "rb").read()
    i = 0
    while i < len(b):
        l = b[i]
        f = b[i + 1:i + 1 + l]
        i += 1 + l
        if len(f) == l and l >= 32:
            yield f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pub", required=True)
    ap.add_argument("--heads")
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()
    pk_raw = open(a.pub, "rb").read()[:32]
    pk = Ed25519PublicKey.from_public_key_bytes(pk_raw) if hasattr(Ed25519PublicKey, "from_public_key_bytes") \
        else Ed25519PublicKey.from_public_bytes(pk_raw)
    devid = pk_raw[:8]

    heads = {}
    if a.heads:
        hb = open(a.heads, "rb").read()
        for o in range(0, len(hb) - 87, 88):
            seq, rtc = struct.unpack_from("<II", hb, o)
            head, sig = hb[o + 8:o + 24], hb[o + 24:o + 88]
            msg = b"HH1" + devid + struct.pack("<II", seq, rtc) + head
            try:
                pk.verify(sig, msg)
                heads[seq] = head
            except InvalidSignature:
                print("bad head signature at seq", seq)

    n = bad_sig = bad_link = v3 = 0
    prev_hash = None
    reached = []
    last_seq = None
    for p in a.files:
        for f in frames(p):
            n += 1
            ver = f[1:2]
            hlen = 48 if ver == b"3" else 32
            body_len = f[3]
            signed = hlen + body_len
            try:
                pk.verify(f[signed:signed + 64], f[:signed])
            except InvalidSignature:
                bad_sig += 1
            seq = struct.unpack_from("<I", f, 12)[0]
            if ver == b"3":
                v3 += 1
                if prev_hash is not None and f[32:48] != prev_hash[:16]:
                    bad_link += 1
                    print("broken link before seq", seq)
            h = hashlib.sha256(f).digest()
            if seq in heads:
                reached.append(seq) if heads[seq] == h[:16] else print("head mismatch at", seq)
            prev_hash = h
            last_seq = seq
    print(f"frames {n} (v3 {v3}), bad signatures {bad_sig}, broken links {bad_link}, "
          f"last seq {last_seq}, signed heads matched {len(reached)}/{len(heads)}"
          + (f", newest matched head {max(reached)}" if reached else ""))
    sys.exit(1 if bad_sig or bad_link else 0)


if __name__ == "__main__":
    main()
