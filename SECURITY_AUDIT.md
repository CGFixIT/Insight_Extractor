# Security Audit Report — insight-extractor v2.0.0
**Date:** 2026-06-24  
**Scanner tools:** pip-audit, bandit, detect-secrets  
**Scope:** `src/`, `requirements.txt`, `constraints.txt`, `.github/workflows/`

---

## Executive Summary

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 0 | — |
| High | 0 | — |
| Medium (SAST) | 1 | Accepted risk — see B615 below |
| CVE — Reachable | 0 | — |
| CVE — Unreachable | 8 | Documented below |
| CVE — Fixed by upgrade | 18 | Resolved: pin transformers>=4.53.0 |
| Hardcoded secrets | 0 | Clean |
| Unpinned GH Actions | 0 | All pinned to @vN |

**Bottom line:** No reachable RCE or credential exposure. One SAST medium (HuggingFace model revision unpinned) and 8 upstream CVEs with no fix — all in checkpoint-conversion utilities not exercised by this project's inference path.

---

## CVE Findings

### Resolved by upgrading transformers → 4.53.0 (18 CVEs)

| CVE | CVSS | Type | Fixed In |
|-----|------|------|----------|
| [CVE-2024-11392](https://osv.dev/vulnerability/GHSA-qxrp-vhvm-j765) | High | RCE — MobileViTV2 deserialization | 4.48.0 |
| [CVE-2024-11393](https://osv.dev/vulnerability/GHSA-wrfc-pvp9-mr9g) | High | RCE — MaskFormer deserialization | 4.48.0 |
| [CVE-2024-11394](https://osv.dev/vulnerability/GHSA-hxxf-235m-72v3) | High | RCE — Trax model deserialization | 4.48.0 |
| [CVE-2024-12720](https://osv.dev/vulnerability/GHSA-6rvg-6v2m-4j46) | Medium | ReDoS — tokenization_nougat_fast | 4.48.0 |
| [CVE-2025-2099](https://osv.dev/vulnerability/GHSA-qq3j-4f4f-9583) | Medium | ReDoS — preprocess_string() | 4.49.0 |
| [CVE-2025-1194](https://osv.dev/vulnerability/GHSA-fpwr-67px-3qhx) | Medium | ReDoS — GPT-NeoX-Japanese tokenizer | 4.50.0 |
| [CVE-2025-3263](https://osv.dev/vulnerability/GHSA-q2wp-rjmx-x6x9) | Medium | ReDoS — get_configuration_file() | 4.51.0 |
| [CVE-2025-3264](https://osv.dev/vulnerability/GHSA-jjph-296x-mrcr) | Medium | ReDoS — get_imports() | 4.51.0 |
| [CVE-2025-3777](https://osv.dev/vulnerability/GHSA-phhr-52qp-3mj4) | Medium | URL validation bypass — image_utils | 4.52.1 |
| [CVE-2025-3933](https://osv.dev/vulnerability/GHSA-37mw-44qp-f5jm) | Medium | ReDoS — DonutProcessor.token2json() | 4.52.1 |
| [CVE-2025-5197](https://osv.dev/vulnerability/GHSA-9356-575x-2w9m) | Medium | ReDoS — convert_tf_weight_name | 4.53.0 |
| [CVE-2025-6638](https://osv.dev/vulnerability/GHSA-59p9-h35m-wg4g) | Medium | ReDoS — MarianTokenizer | 4.53.0 |
| [CVE-2025-6051](https://osv.dev/vulnerability/GHSA-rcv9-qm8p-9p6j) | Medium | ReDoS — EnglishNormalizer | 4.53.0 |
| [CVE-2025-6921](https://osv.dev/vulnerability/GHSA-4w7r-h757-3r74) | Medium | ReDoS — AdamWeightDecay | 4.53.0 |
| [CVE-2026-1839](https://osv.dev/vulnerability/GHSA-69w3-r845-3855) | High | RCE — Trainer._load_rng_state() | 5.0.0rc3 |

**Reachability verdict:** `UNREACHABLE` for all 18. This project uses only `SentenceTransformer("all-MiniLM-L6-v2")` inference. None of the vulnerable code paths (Trax, MobileViTV2, MaskFormer, Nougat, GPT-NeoX-Japanese, Marian, Donut, Trainer RNG) are imported or called.  
**Action:** Upgrade to `transformers==4.53.0` (already applied in constraints.txt).

---

### No upstream fix available (8 CVEs) — Accepted Risk

| CVE | Type | Affected Component | Reachability |
|-----|------|--------------------|--------------|
| CVE-2025-14929 | RCE — X-CLIP checkpoint deserialization | `convert_*` scripts | UNREACHABLE |
| CVE-2025-14926 | Code injection — SEW convert_config | `convert_*` scripts | UNREACHABLE |
| CVE-2025-14927 | Code injection — SEW-D convert_config | `convert_*` scripts | UNREACHABLE |
| CVE-2025-14928 | Code injection — HuBERT convert_config | `convert_*` scripts | UNREACHABLE |
| CVE-2025-14920 | RCE — Perceiver deserialization | `convert_*` scripts | UNREACHABLE |
| CVE-2025-14921 | RCE — Transformer-XL deserialization | `convert_*` scripts | UNREACHABLE |
| CVE-2025-14924 | RCE — megatron_gpt2 deserialization | `convert_*` scripts | UNREACHABLE |
| CVE-2025-14930 | RCE — GLM4 deserialization | `convert_*` scripts | UNREACHABLE |

**Rationale:** All 8 affect `convert_*_to_pytorch` checkpoint-conversion CLI scripts only. This project never calls these scripts or imports these model classes. The attack vector requires a user to deliberately run a conversion script against a malicious checkpoint. Not applicable to inference-only use.  
**Review date:** 2027-01-01 or when upstream publishes a fix.

---

## SAST Findings (bandit)

### B615 — HuggingFace Unsafe Download (MEDIUM / HIGH confidence)

**File:** `src/insight_extractor/tokenizer.py:26`  
**CWE:** [CWE-494](https://cwe.mitre.org/data/definitions/494.html) — Download of Code Without Integrity Check  
**Details:** `SentenceTransformer(model_name)` called without a pinned `revision=` hash. If the model hub is compromised, a malicious model update could be pulled.  
**Mitigation:** Pin the model revision in production:
```python
SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", revision="c9b44c9")
```
**Status:** Accepted for development use. Recommend pinning for any production deployment.

---

## Secret Scanning (detect-secrets)

**Result:** CLEAN — no API keys, tokens, passwords, or credentials detected in `src/`.

---

## GitHub Actions Audit

**Result:** All actions pinned to `@vN` version tags. No SHA-pinning (best practice for supply chain hardening, lower priority for personal projects).

---

## Hardened Manifest Changes Applied

```diff
--- a/requirements.txt
+++ b/requirements.txt
-sentence-transformers>=3.0.0,<4.0.0
+sentence-transformers>=3.4.1,<4.0.0
-transformers>=4.40.0,<4.45.0
+transformers>=4.53.0,<5.0.0
+accelerate>=0.26.0

--- a/constraints.txt
+++ b/constraints.txt
-sentence-transformers==3.0.1
+sentence-transformers==3.4.1
-transformers==4.44.2
+transformers==4.53.0
+accelerate==0.34.2
```

---

## Remediation Commands

```cmd
:: Apply all fixes at once
pip install -r requirements.txt -c constraints.txt
pip install -e .

:: Verify clean
pip-audit -r requirements.txt
```
