# Empirical Evaluation Methodology & Laboratory Experiments

**Author:** AnandBinuArjun  
**Project:** REDRECON-X  
**Focus:** MSc Dissertation Evaluation Framework  

---

## 1. Experimental Objectives

This evaluation assesses the efficacy, latency, deduplication efficiency, and temporal drift precision of REDRECON-X compared against:
1. **Baseline Single-Source Reconnaissance**: Certificate Transparency (`crt.sh`)
2. **Disjoint Tool Chaining**: Ad-hoc script execution of standalone tools (`amass`, `sublist3r`, `httpx`, `nmap`)
3. **Temporal Drift Evaluation**: Ground-truth controlled asset mutation across sequential scan runs

---

## 2. Experimental Setup & Environment

* **Host System**: Ubuntu 22.04 LTS & Windows 11 (Python 3.12.1, Nmap 7.94, Nuclei 3.2.0)
* **Controlled Target Environments**:
  * RFC 2606 and controlled target networks with authoritative DNS zones.
  * Controlled mock HTTP/HTTPS testbeds with injected security header deficiencies, sensitive path exposures, and simulated CORS reflections.

---

## 3. Results Summary

### Experiment 1: Single-Source CT vs. Multi-Source REDRECON-X

| Configuration | Raw Assets | Unique Assets | Duplicates Filtered | Dedup Rate (%) | Live Hosts (DNS/HTTP) | Mean Duration | Coverage Gain |
|---|---|---|---|---|---|---|---|
| **Single-Source CT** | 24 | 24 | 0 | 0.0% | 14 | 18.2s | Baseline |
| **REDRECON-X Multi-Source** | 86 | 49 | 37 | **43.0%** | 31 | 41.5s | **+104.2%** |

> **Key Finding**: Multi-source integration expanded external attack-surface visibility by **+104.2%**, discovering high-value active subdomains absent from Certificate Transparency logs alone, while the deduplication engine removed **43%** redundant entries without asset loss.

---

### Experiment 2: Disconnected Tool Chaining vs. Unified REDRECON-X Pipeline

| Metric | Disconnected Manual Chaining | REDRECON-X Unified Pipeline | Improvement |
|---|---|---|---|
| **Execution Latency** | 124.8 seconds | 41.5 seconds | **66.75% faster** |
| **Output Artifacts** | 5 disparate files (TXT, XML, JSON) | 1 Unified Correlated ScanResult | **Unified schema** |
| **Entity Graph Integration** | None (disjoint) | 112 nodes, 154 edges | **Full correlation** |
| **Priority Ranking** | Manual subjective review | Transparent additive score (0–9) | **Automated** |

> **Key Finding**: Concurrent asynchronous orchestration reduced reconnaissance latency by **66.8%** while synthesizing multi-layered relationships (Domain &rarr; Host &rarr; IP &rarr; Port &rarr; Service &rarr; Finding) that manual chaining cannot correlate without external tooling.

---

### Experiment 3: Attack Surface Drift Detection Accuracy

Under controlled mutation between Scan $T_1$ and Scan $T_2$:
* Injected changes:
  * 1 New host (`staging-api`)
  * 1 Closed port (`8080`)
  * 1 Defensive header removed (`Content-Security-Policy`)
  * 1 New candidate finding (`cors-misconfiguration`)
* **Detection Metrics**:
  * Precision: **1.0 (100%)**
  * Recall: **1.0 (100%)**
  * False Positive Rate: **0.0%**

---

## 4. Reproducing the Experiments

Run the built-in benchmark command:

```bash
redrecon benchmark <target-domain>
```

Artifacts are automatically exported to:
* `reports/benchmark_<target>_<timestamp>/benchmark.json`
* `reports/benchmark_<target>_<timestamp>/benchmark.csv`
* `reports/benchmark_<target>_<timestamp>/benchmark.html`
