# 纲目 CBOM 规则库 · gangmu-cbom-rules

**免费的密码算法规则库：`gangmu cbom` 在固件和源码里找哪些算法、各算法对量子计算机意味着什么，都写在这里，社区共同维护。**

[纲目 Gangmu](https://github.com/GANGMU-SBOM/gangmu) 的 `gangmu cbom` 命令列出固件里的密码算法并输出 CycloneDX 1.6 CBOM。
算法表原来写在工具代码里；现在它是数据，可以用规则包补充或覆盖，新增一个算法就是提一个小 YAML 的 PR，不用改工具、不用等工具发版。

[English](README.en.md) · [贡献规则](CONTRIBUTING.md)

## 安装

```bash
pip install gangmu-sbom gangmu-cbom-rules
gangmu cbom firmware/            # 自动读取已安装的 kind 为 cbom 的规则包
gangmu cbom firmware/ --rules rules/   # 或者指定目录，便于本地改规则
```

需要 gangmu 0.9.0 或更高版本（`requires_gangmu`）。

## 里面有什么

| 文件 | 内容 |
| --- | --- |
| `rules/algorithms/symmetric.yaml` | AES、DES/3DES、RC4、ChaCha20-Poly1305、SM4 |
| `rules/algorithms/hash-mac-kdf.yaml` | SM3、MD5、SHA-1/2/3、HMAC、HKDF/PBKDF2、DRBG |
| `rules/algorithms/public-key.yaml` | SM2、RSA、ECDSA、ECDH、Ed25519、X25519、Diffie-Hellman |
| `rules/algorithms/post-quantum.yaml` | ML-KEM、ML-DSA、SLH-DSA、LMS/XMSS |
| `rules/algorithms/post-quantum-candidates.yaml` | FrodoKEM、Classic McEliece、HQC、FN-DSA（尚无最终标准的方案） |

前四个文件是 gangmu 内置算法表的原样导出，`tests/test_rules.py` 会逐项比对，防止两边悄悄分叉。同名 `key` 替换内置项，新 `key` 新增。

## 库能力表（`rules/libraries/`）

`gangmu cbom --libraries` 先做 SBOM 识别，再按识别出的库和版本，从这里查出它**提供**的算法，作为"库推断"证据（置信度不超过 0.6）。
"提供"不等于"调用"：源码里有、默认是否启用都算提供；版本未知的库只列出，不猜。

| 文件 | 库 |
| --- | --- |
| `mbedtls.yaml` `wolfssl.yaml` `openssl.yaml` `tongsuo.yaml` `gmssl.yaml` | Mbed TLS、wolfSSL、OpenSSL、铜锁、GmSSL |

这些文件由 `tools/derive_libraries.py` 生成，不要手改：脚本克隆每个版本区间的第一个和最后一个上游标签，用 gangmu 自己的算法表扫描源码，只保留两端都出现的算法（所以区间中途才加入的算法会被漏掉，宁缺毋滥）。
Mbed TLS 只扫 `library/`，因为它的 PSA 头文件为未实现的算法也定义了常量。要加一个版本区间，改 `tools/libraries.json` 后重新运行脚本，并检查 `tests/test_rules.py::test_known_facts_hold`。

## 规则格式

```yaml
algorithms:
  - key: frodokem            # 小写字母、数字、. _ -
    name: FrodoKEM
    primitive: kem           # CycloneDX algorithmProperties.primitive 的取值
    quantum: pqc             # vulnerable | symmetric | pqc | broken | neutral
    patterns: ['FrodoKEM\w*', 'PQCLEAN_FRODOKEM\w*']   # 标识符的正则，工具会自动加上标识符边界
    note: 一句话说明。
```

规则有错（未知的 primitive、写不出的正则）时 `gangmu cbom` 退出码为 2，并指出文件和条目。

## 许可

规则数据 CDLA-Permissive-2.0（见 `rules/LICENSE`），打包代码 Apache-2.0（见 `LICENSE`）。已发布的规则不会改为限制性许可。
需要付费的是厂商专有的数据和合规映射，放在另外的包里。
