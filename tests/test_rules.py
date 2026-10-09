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
