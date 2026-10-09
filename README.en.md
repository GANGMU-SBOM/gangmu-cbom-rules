# gangmu-cbom-rules

The free CBOM rule base for [gangmu](https://github.com/GANGMU-SBOM/gangmu): which cryptographic
algorithms `gangmu cbom` looks for in firmware and source, and what each means against a quantum
computer. The table used to live in the tool's code; as data it can be extended with a small YAML pull
request, with no tool release.

```bash
# Not on PyPI yet: install from source (gangmu 0.9.0 or later; use git main until it is released)
pip install git+https://github.com/GANGMU-SBOM/gangmu.git@main
pip install git+https://github.com/GANGMU-SBOM/gangmu-cbom-rules.git
gangmu cbom firmware/                         # installed packs of kind "cbom" are read automatically
gangmu cbom firmware/ --rules rules/          # or point at a directory while editing
```

A rule with the key of a built-in replaces it; a new key adds an algorithm. The first four files under
`rules/algorithms/` are an export of gangmu's built-in table, and `tests/test_rules.py` checks them
entry by entry. Rule data is CDLA-Permissive-2.0, packaging code Apache-2.0, and published community rules
will not be relicensed. See the Chinese README for the rule format.
