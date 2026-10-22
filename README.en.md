# gangmu-cbom-rules

The free CBOM rule base for [gangmu](https://github.com/GANGMU-SBOM/gangmu): which cryptographic
algorithms `gangmu cbom` looks for in firmware and source, and what each means against a quantum
computer. The table used to live in the tool's code; as data it can be extended with a small YAML pull
request, with no tool release.

```bash
# This pack is not on PyPI yet: install it from source (needs gangmu 0.9.0 or later)
pip install gangmu-sbom
pip install git+https://github.com/GANGMU-SBOM/gangmu-cbom-rules.git
gangmu cbom firmware/                         # installed packs of kind "cbom" are read automatically
gangmu cbom firmware/ --rules rules/          # or point at a directory while editing
```

A rule with the key of a built-in replaces it; a new key adds an algorithm. The first four files under
`rules/algorithms/` are an export of gangmu's built-in table, and `tests/test_rules.py` checks them
entry by entry. The `*-extra.yaml` files and the candidates file add algorithms the built-in table lacks (legacy and
regional ciphers such as Camellia, ARIA, Blowfish and ZUC; MD2/MD4, RIPEMD-160, BLAKE2, SHAKE, KMAC, Argon2, scrypt;
Ed448, X448, DSA, SM9, HPKE, SRP, EC J-PAKE; NTRU, BIKE, MAYO, UOV, SNOVA, CROSS and hybrid groups such as
X25519MLKEM768). The newer files add the modes that sit on top of the AES core (GCM, CCM, XTS, OCB, EAX, AES-SIV, GMAC, Poly1305, SipHash),
Twofish, RC5, XTEA, KASUMI, the Russian GOST family, a NULL-cipher marker (`broken`), the TLS 1.2 PRF and SP 800-56C/108 KDFs, ECIES, WPA3 SAE, secp256k1,
QR-UOV and a hybrid ML-DSA-44+Ed25519 signature. Each identifier was checked against the upstream source it comes from, and the tests carry one sample per rule
plus lookalike names that must not match. Rule data is CDLA-Permissive-2.0, packaging code Apache-2.0, and published community rules
will not be relicensed. **How this differs from the SBOM rules.** This pack says which algorithms are present and what a quantum computer does to them. Which library and
version a directory is, and its CVEs, is the SBOM's job (gangmu-rules). Algorithm rules hold identifiers only, never directory markers, hashes or
version probes. The library tables in `rules/libraries/` are the join: they name a library by its SBOM rule id but only record which algorithms its source
provides. `tools/mine_gaps.py` lists the crypto identifiers in an upstream tree that no rule matches. See the Chinese README for the rule format.
