#!/usr/bin/env python3
"""List the crypto-looking identifiers in upstream sources that no rule matches.

For every library directory under UPSTREAM it prints the algorithm keys the rules find, then the
identifiers (macros and function names declared in .h/.c/.inc files) that contain an algorithm word
but match no rule, grouped by that word. Use it to see what a library names that the pack does not.

    python tools/mine_gaps.py UPSTREAM RULES [library ...]
"""
import collections
import os
import re
import sys
from pathlib import Path

from gangmu.cbom import cbom_roots, load_algo_roots

WORDS = ["aes", "des", "rc4", "arc4", "chacha", "poly1305", "salsa", "sm2", "sm3", "sm4", "sm9", "zuc",
         "md2", "md4", "md5", "sha", "keccak", "shake", "blake", "ripemd", "whirl", "hmac", "cmac", "gmac",
         "ghash", "kmac", "siphash", "hkdf", "pbkdf", "kdf", "drbg", "rsa", "dsa", "ecdsa", "ecdh", "ecc",
         "ed25519", "ed448", "x25519", "x448", "curve25519", "curve448", "dh", "dhm", "kyber", "mlkem",
         "ml_kem", "dilithium", "mldsa", "ml_dsa", "sphincs", "slh", "falcon", "lms", "xmss", "hss",
         "camellia", "aria", "seed", "blowfish", "idea", "cast", "rc2", "rc5", "ascon", "argon", "scrypt",
         "srp", "jpake", "hpke", "ntru", "bike", "hqc", "frodo", "mceliece", "mayo", "uov", "snova",
         "cross", "gost", "streebog", "kuznyechik", "magma", "twofish", "serpent", "xtea", "eax", "ocb",
         "siv", "gcm", "ccm", "xts", "pkcs1", "oaep", "pss", "ecies", "sae", "secp", "brainpool", "eddsa"]
WORD_RE = re.compile("|".join(re.escape(w) for w in WORDS), re.I)
DECL = re.compile(rb"(?:#\s*define\s+([A-Za-z_]\w+)|([A-Za-z_]\w+)\s*\()")
SKIP = {".git", "test", "tests", "testing", "doc", "docs", "demos", "examples", "fuzz", "benchmark"}


def identifiers(root: Path) -> "collections.Counter[str]":
    out: "collections.Counter[str]" = collections.Counter()
    for here, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for name in files:
            if not name.endswith((".h", ".c", ".inc")):
                continue
            try:
                data = (Path(here) / name).read_bytes()
            except OSError:
                continue
            for m in DECL.finditer(data):
                ident = (m.group(1) or m.group(2)).decode()
                if len(ident) > 3 and WORD_RE.search(ident):
                    out[ident] += 1
    return out


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    upstream, rules = Path(sys.argv[1]), sys.argv[2]
    libs = sys.argv[3:] or sorted(p.name for p in upstream.iterdir() if p.is_dir())
    algos = load_algo_roots(cbom_roots([rules]))
    for lib in libs:
        found: "collections.Counter[str]" = collections.Counter()
        missed = collections.defaultdict(list)
        for ident in identifiers(upstream / lib):
            keys = [a.key for a, rx in algos.regexes if rx.search(ident.encode())]
            if keys:
                found.update(keys)
            else:
                missed[WORD_RE.search(ident).group(0).lower()].append(ident)
        print(f"\n######## {lib}")
        print("found:", " ".join(f"{k}:{n}" for k, n in sorted(found.items())))
        for word, names in sorted(missed.items(), key=lambda kv: -len(kv[1])):
            names = sorted(set(names))
            print(f"  [{word}] {len(names)}: " + " ".join(names[:40]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
