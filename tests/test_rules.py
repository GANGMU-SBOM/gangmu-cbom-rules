"""Every rule loads, and the seed table says what gangmu's built-in table says."""
import pytest

pytest.importorskip("gangmu.cbom")
from gangmu.cbom import ALGOS, load_algo_roots  # noqa: E402
from gangmu.core.packs import RuleRoot, check_manifest, read_manifest  # noqa: E402

import gangmu_cbom_rules  # noqa: E402


def _root():
    root = RuleRoot(gangmu_cbom_rules.path(), "pack:cbom")
    root.manifest = read_manifest(root.path)
    return root


def test_manifest_is_a_cbom_pack_this_gangmu_can_read():
    root = _root()
    assert root.kind == "cbom"
    check_manifest(root.path, root.manifest)


def test_every_algorithm_rule_loads():
    algos = load_algo_roots([_root()])
    assert len(algos.algos) >= len(ALGOS)


def test_the_seed_matches_the_built_in_table_exactly():
    """If gangmu changes a built-in, this fails until the seed is updated -- or the
    built-in is deliberately overridden here, which then belongs in a separate file."""
    loaded = {a.key: a for a in load_algo_roots([_root()]).algos}
    for built_in in ALGOS:
        mine = loaded[built_in.key]
        assert (mine.name, mine.primitive, mine.quantum, mine.patterns, mine.note) == (
            built_in.name, built_in.primitive, built_in.quantum, built_in.patterns,
            built_in.note), built_in.key


@pytest.mark.parametrize("text, key", [
    (b"int r = FrodoKEM_keypair(pk, sk);", "frodokem"),
    (b"OQS_KEM_alg_classic_mceliece_348864", "classic-mceliece"),
    (b"PQCLEAN_HQC128_CLEAN_crypto_kem_enc", "hqc"),
    (b"falcon_sign_dyn(rng, sig)", "fn-dsa"),
])
def test_candidate_algorithms_are_found(text, key):
    algos = load_algo_roots([_root()])
    regex = dict((a.key, r) for a, r in algos.regexes)[key]
    assert regex.search(text)


# One identifier per added rule, copied from the upstream project named in the comment.
EXTRA_SAMPLES = [
    ("mbedtls_camellia_setkey_enc(&ctx, key, 128);", "camellia"),        # Mbed TLS 3.6
    ("mbedtls_aria_crypt_ecb(&ctx, in, out);", "aria"),                  # Mbed TLS 3.6
    ("SEED_set_key(key, &ks);", "seed"),                                 # OpenSSL
    ("BF_cbc_encrypt(in, out, n, &k, iv, BF_ENCRYPT);", "blowfish"),     # OpenSSL
    ("IDEA_set_encrypt_key(key, &ks);", "idea"),                         # OpenSSL
    ("CAST_set_key(&ks, 16, key);", "cast5"),                            # OpenSSL
    ("wc_Rc2CbcEncrypt(&rc2, out, in, sz);", "rc2"),                     # wolfSSL
    ("crypto_secretbox_xsalsa20poly1305(c, m, mlen, n, k);", "salsa20"),  # libsodium
    ("crypto_aead_xchacha20poly1305_ietf_encrypt(c, &cl, m, ml, 0, 0, 0, n, k);", "xchacha20-poly1305"),
    ("wc_AsconAEAD128_Init(&ctx);", "ascon"),                            # wolfSSL
    ("ascon_aead_encrypt(c, k, n, a, m);", "ascon"),                     # ascon-c
    ("zuc_generate_keystream(&state, 4, out);", "zuc"),                  # GmSSL
    ("wc_InitCmac(&cmac, key, 16, WC_CMAC_AES, NULL);", "cmac"),         # wolfSSL
    ("mbedtls_nist_kw_wrap(&kw, MBEDTLS_KW_MODE_KW, in, n, out, &on, 40);", "aes-kw"),
    ("wc_InitMd2(&md2);", "md2"),                                        # wolfSSL
    ("MD4_Init(&ctx);", "md4"),                                          # OpenSSL
    ("mbedtls_ripemd160_starts(&ctx);", "ripemd160"),                    # Mbed TLS 3.6
    ("WHIRLPOOL_Update(&c, p, n);", "whirlpool"),                        # OpenSSL
    ("blake2b_init_key(S, 32, key, 16);", "blake2"),                     # libsodium
    ("shake256_inc_absorb(&st, in, n);", "shake"),                       # PQClean
    ("wc_Kmac128_Update(&kmac, in, n);", "kmac"),                        # wolfSSL
    ("wc_Argon2Init(&ctx);", "argon2"),                                  # wolfSSL
    ("EVP_PBE_scrypt(pw, n, salt, sl, N, r, p, 0, out, ol);", "scrypt"),  # OpenSSL
    ("wc_ed448_make_key(&rng, 57, &key);", "ed448"),                     # wolfSSL
    ("wc_curve448_shared_secret_ex(&a, &b, out, &n, EC448_BIG_ENDIAN);", "x448"),
    ("EVP_PKEY_DSA", "dsa"),                                             # OpenSSL
    ("sm9_sign_init(&ctx);", "sm9"),                                     # GmSSL
    ("OSSL_HPKE_CTX *ctx;", "hpke"),                                     # OpenSSL
    ("wc_SrpInit(&srp, SRP_TYPE_SHA, SRP_CLIENT_SIDE);", "srp"),         # wolfSSL
    ("mbedtls_ecjpake_read_round_one(&ctx, buf, len);", "ecjpake"),      # Mbed TLS 3.6
    ("OQS_KEM_alg_ntru_hps2048509", "ntru"),                             # liboqs
    ("crypto_kem_sntrup761_keypair(pk, sk);", "ntru-prime"),             # OpenSSH
    ("OQS_KEM_alg_bike_l1", "bike"),                                     # liboqs
    ("OQS_SIG_alg_mayo_1", "mayo"),                                      # liboqs
    ("OQS_SIG_alg_uov_ov_Is", "uov"),
    ("OQS_SIG_alg_snova_SNOVA_I_S", "snova"),
    ("OQS_SIG_alg_cross_rsdp_128_fast", "cross"),
    ('"mlkem768x25519-sha256"', "pqc-hybrid"),                           # OpenSSH
    ("TLSEXT_GROUP X25519MLKEM768", "pqc-hybrid"),                       # OpenSSL
]


@pytest.mark.parametrize("text, key", EXTRA_SAMPLES)
def test_added_algorithms_are_found(text, key):
    algos = load_algo_roots([_root()])
    regex = dict((a.key, r) for a, r in algos.regexes)[key]
    assert regex.search(text.encode())


def test_every_added_rule_has_a_sample():
    """A rule nobody exercises is a rule nobody has checked against real code."""
    algos = load_algo_roots([_root()])
    added = {a.key for a in algos.algos} - {a.key for a in ALGOS}
    added -= {"frodokem", "classic-mceliece", "hqc", "fn-dsa"}   # covered by the candidates test
    assert added == {key for _, key in EXTRA_SAMPLES}


@pytest.mark.parametrize("text, key", [
    (b"ECDSA_do_sign(dgst, n, key);", "dsa"),           # ECDSA is its own rule, not DSA
    (b"mbedtls_sha384_starts(&ctx, 1);", "sha-3"),      # the SHA-384 / SHA-3 mix-up of the first seed
    (b"mbedtls_camellia_free(&ctx);", "aria"),
    (b"ARIA_encrypt_ctx(x);", "aria"),
    (b"crypto_aead_chacha20poly1305_ietf_encrypt(c);", "xchacha20-poly1305"),
    (b"XWING_KEM", "pqc-hybrid"),                       # not verified in any upstream source
    (b"my_BF_encrypt_wrapper(x);", "blowfish"),
    (b"MY_SHAKE128_RATE_X", "shake"),
])
def test_lookalikes_are_not_taken_for_the_algorithm(text, key):
    algos = load_algo_roots([_root()])
    regex = dict((a.key, r) for a, r in algos.regexes)[key]
    assert not regex.search(text)


def test_every_library_table_loads_and_names_known_algorithms():
    algos = load_algo_roots([_root()])
    known = {a.key for a in algos.algos}
    assert {lib.name for lib in algos.libraries.values()} >= {"Mbed TLS", "wolfSSL", "OpenSSL"}
    for lib in algos.libraries.values():
        assert lib.releases, lib.name
        for rel in lib.releases:
            assert rel.algorithms, (lib.name, rel.introduced)
            assert set(rel.algorithms) <= known, (lib.name, set(rel.algorithms) - known)


def test_known_facts_hold():
    """A few things that are true of the upstream projects, so a bad derivation shows up."""
    algos = load_algo_roots([_root()])
    by = {lib.name: {r.introduced: set(r.algorithms) for r in lib.releases}
          for lib in algos.libraries.values()}
    mbed = by["Mbed TLS"]
    assert "rc4" in mbed["2.16.0"] and "rc4" not in mbed["3.6.0"]   # RC4 removed in 3.0
    assert "ml-kem" not in mbed["3.6.0"] and "ml-dsa" not in mbed["3.6.0"]
    assert "sm2" in by["OpenSSL"]["3.0.0"]
    assert "ml-kem" in by["OpenSSL"]["3.5.0"] and "ml-kem" not in by["OpenSSL"]["3.0.0"]
    assert "sm4" in by["GmSSL"]["3.1.0"]
    # Removed in Mbed TLS 3.0 (MD2, MD4, Blowfish); added in OpenSSL 3.0 (KMAC) and 3.5 (hybrid groups).
    assert {"md2", "md4", "blowfish"} <= mbed["2.28.0"]
    assert not {"md2", "md4", "blowfish"} & mbed["3.6.0"]
    assert "kmac" not in by["OpenSSL"]["1.1.1"] and "kmac" in by["OpenSSL"]["3.0.0"]
    assert "pqc-hybrid" in by["OpenSSL"]["3.5.0"] and "pqc-hybrid" not in by["OpenSSL"]["3.0.0"]
    assert "zuc" in by["GmSSL"]["3.1.0"] and "sm9" in by["GmSSL"]["3.1.0"]


def test_wheel_carries_the_rules(tmp_path):
    """A built wheel must contain the rule tree, or an installed pack is empty."""
    import subprocess
    import sys
    import zipfile
    from pathlib import Path

    repo = Path(__file__).resolve().parents[1]
    out = tmp_path / "dist"
    subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps",
                    "-w", str(out), str(repo)], check=True, capture_output=True)
    names = zipfile.ZipFile(next(out.glob("*.whl"))).namelist()
    assert "gangmu_cbom_rules/data/rulebase.json" in names
    assert any(n.startswith("gangmu_cbom_rules/data/algorithms/") for n in names)
    assert any(n.startswith("gangmu_cbom_rules/data/libraries/") for n in names)


def test_the_three_places_that_name_the_version_agree():
    """pyproject.toml, the package and the manifest were once 2026.10.9, 2026.10.9 and
    2026.10.15; gangmu reports the manifest's, pip the package's."""
    import json
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    declared = re.search(r'^version = "([^"]+)"', (root / "pyproject.toml").read_text(), re.M)
    manifest = json.loads((root / "rules" / "rulebase.json").read_text())["version"]
    assert declared and declared.group(1) == gangmu_cbom_rules.__version__ == manifest
