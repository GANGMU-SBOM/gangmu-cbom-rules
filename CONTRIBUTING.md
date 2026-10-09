# 贡献规则 · Contributing

最容易的第一个 PR：给 `rules/algorithms/` 里的某个算法补一个标识符，或新增一个算法。

1. 改或加一条 YAML（格式见 README）。`patterns` 写标识符的正则，不要自己加 `\b` 或前缀边界。
2. 新增算法时在 `tests/test_rules.py` 的参数列表里加一行：一段会命中的真实标识符。
3. `pip install -e '.[dev]' && pytest -q` 通过。
4. 在 PR 里写明标识符出自哪个库的哪个文件（链接即可）。对没有标准化的方案，`note` 里写明状态。

提交请带 `Signed-off-by`（`git commit -s`）。
