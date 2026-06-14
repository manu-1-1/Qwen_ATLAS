# Qwen-ATLAS: RAG System v4 Benchmarking Report

This report compares the performance, efficiency, and accuracy of **Vector RAG (Ollama nomic-embed-text)** and **Vectorless RAG v4 (Pure LLM Selector)** across **41 queries**.

## High-Level Summary Comparison

| Metric | Vector RAG (Ollama nomic-embed-text) | Vectorless RAG v4 (Pure LLM Selector) |
| --- | --- | --- |
| **Initialization Time** | 6.621 s | 0.242 s |
| **Memory Growth on Load** | 249.8 MB | 35.9 MB |
| **Disk / Storage Size** | 21.04 MB | 45.46 MB |
| **Average Query Latency** | 959.26 ms | 22580.77 ms |
| **Retrieval Accuracy (Recall)** | 32/41 (78.0%) | 35/41 (85.4%) |
| **Average Context Length** | 191.5 words | 894.7 words |


## Category Breakdown

| Category | Vector RAG (Ollama) | Vectorless v4 |
| --- | --- | --- |
| Analyst Semantic Query | 5/7 | 7/7 |
| Group Information | 5/5 | 5/5 |
| Group to Techniques | 2/4 | 3/4 |
| Mitigation Lookup | 5/5 | 5/5 |
| Tactic-Filtered Group Query | 0/5 | 2/5 |
| Technique ID Lookup | 5/5 | 3/5 |
| Technique Name Lookup | 5/5 | 5/5 |
| Technique to Groups | 5/5 | 5/5 |


## Detailed Query Logs

| ID | Query | Expected | Vector Ollama | Vectorless v4 (Pure LLM) |
| --- | --- | --- | --- | --- |
| A1 | `What is T1003?` | `T1003` | ✓ (2.0ms) | ✓ (35434.5ms) |
| A2 | `What is T1055?` | `T1055` | ✓ (1.3ms) | ✓ (29554.8ms) |
| A3 | `What is T1195.002?` | `T1195.002` | ✓ (1.2ms) | ✗ (33253.4ms) |
| A4 | `What is T1110.003?` | `T1110.003` | ✓ (2.3ms) | ✓ (27703.4ms) |
| A5 | `What is T1021.001?` | `T1021.001` | ✓ (2.1ms) | ✗ (37621.3ms) |
| B1 | `What is Process Injection?` | `T1055, Process Injection` | ✓ (18.3ms) | ✓ (37325.0ms) |
| B2 | `What is OS Credential Dumping?` | `T1003, OS Credential Dumping` | ✓ (10.6ms) | ✓ (32752.5ms) |
| B3 | `Explain Password Spraying.` | `T1110.003, Password Spraying` | ✓ (5.5ms) | ✓ (37892.9ms) |
| B4 | `What is PowerShell?` | `T1059.001, PowerShell` | ✓ (20.1ms) | ✓ (26141.2ms) |
| B5 | `What is Windows Command Shell?` | `T1059.003, Windows Command Shell` | ✓ (29.0ms) | ✓ (17112.5ms) |
| C1 | `What is APT29?` | `APT29, G0016` | ✓ (3276.6ms) | ✓ (16676.0ms) |
| C2 | `What is APT33?` | `APT33, G0014` | ✓ (2277.7ms) | ✓ (14343.1ms) |
| C3 | `What is Lazarus Group?` | `Lazarus Group, Lazarus, G0032` | ✓ (2214.5ms) | ✓ (15965.0ms) |
| C4 | `What is FIN7?` | `FIN7, G0046` | ✓ (2239.1ms) | ✓ (16447.9ms) |
| C5 | `What is Kimsuky?` | `Kimsuky, G0094` | ✓ (2258.8ms) | ✓ (15374.5ms) |
| D1 | `What techniques does APT29 use?` | `APT29, G0016` | ✗ (2251.1ms) | ✓ (14775.6ms) |
| D2 | `What techniques does Cozy Bear use?` | `APT29, Cozy Bear, G0016` | ✓ (2278.7ms) | ✓ (15396.5ms) |
| D3 | `What techniques does The Dukes use?` | `APT29, The Dukes, G0016` | ✓ (2232.4ms) | ✗ (18611.4ms) |
| D4 | `What techniques does Lazarus Group use?` | `Lazarus Group, Lazarus, G0032` | ✗ (2195.7ms) | ✓ (14376.6ms) |
| E1 | `Which groups use T1003?` | `T1003` | ✓ (0.2ms) | ✓ (16052.9ms) |
| E2 | `Who uses T1055?` | `T1055` | ✓ (0.1ms) | ✓ (32042.5ms) |
| E3 | `Which groups use T1110.003?` | `T1110.003` | ✓ (0.0ms) | ✓ (8410.6ms) |
| E4 | `Which groups use T1195.002?` | `T1195.002` | ✓ (0.0ms) | ✓ (10067.7ms) |
| E5 | `Which groups use T1021.001?` | `T1021.001` | ✓ (0.0ms) | ✓ (9751.1ms) |
| F1 | `How can T1003 be mitigated?` | `T1003, Mitigation` | ✓ (6.3ms) | ✓ (15540.9ms) |
| F2 | `How can T1055 be mitigated?` | `T1055, Mitigation` | ✓ (1.6ms) | ✓ (27451.4ms) |
| F3 | `What mitigations exist for T1110.003?` | `T1110.003, Mitigation` | ✓ (4.5ms) | ✓ (17670.2ms) |
| F4 | `How can Password Spraying be mitigated?` | `Password Spraying, T1110, Mitigation` | ✓ (34.3ms) | ✓ (27677.0ms) |
| F5 | `How can Process Injection be mitigated?` | `Process Injection, T1055, Mitigation` | ✓ (3.9ms) | ✓ (17244.1ms) |
| G1 | `What credential access techniques does APT29 use?` | `APT29, G0016` | ✗ (2177.6ms) | ✓ (37380.6ms) |
| G2 | `What persistence techniques does APT29 use?` | `APT29, G0016` | ✗ (2165.7ms) | ✓ (18048.1ms) |
| G3 | `What discovery techniques does Lazarus Group use?` | `Lazarus, G0032` | ✗ (2212.6ms) | ✗ (19834.8ms) |
| G4 | `What lateral movement techniques does FIN7 use?` | `FIN7, G0046` | ✗ (2219.2ms) | ✗ (16825.1ms) |
| G5 | `What execution techniques does APT33 use?` | `APT33, G0014` | ✗ (2250.0ms) | ✗ (17962.4ms) |
| H1 | `How do attackers dump credentials?` | `credential dumping, T1003, LSASS` | ✗ (36.6ms) | ✓ (37045.9ms) |
| H2 | `Explain credential dumping to a SOC analyst.` | `credential dumping, T1003` | ✓ (2214.4ms) | ✓ (18103.1ms) |
| H3 | `Why is password spraying dangerous?` | `password spraying, T1110, brute force` | ✓ (44.0ms) | ✓ (18332.3ms) |
| H4 | `What should defenders monitor for Process Injection?` | `process injection, T1055, monitor, detection` | ✓ (7.8ms) | ✓ (32113.6ms) |
| H5 | `What indicators suggest PowerShell abuse?` | `powershell, T1059.001` | ✓ (23.6ms) | ✓ (17230.3ms) |
| H6 | `What attack chain would APT29 likely use after initial access?` | `APT29, Cozy Bear` | ✗ (2253.8ms) | ✓ (38613.3ms) |
| I1 | `How do I prevent that credential theft technique used by APT29?` | `T1003, mitigation, Credential, T1552` | ✓ (2356.5ms) | ✓ (15655.8ms) |

## Key Observations

### 1. Pure LLM Selection Accuracy vs. Vector Search

Vectorless RAG v4 bypasses all deterministic query routing and relies purely on candidate pre-filtering followed by LLM-based selection. It achieves an accuracy (recall) of **85.4% (35/41)**, which is significantly higher than Vector RAG (Ollama)'s **78.0% (32/41)**. This demonstrates that the tree structure and LLM selection process are very accurate at identifying correct threat entities, even without direct regex/lookup routing. However, bypassing the routing superhighway comes at a severe latency cost, as every query must query the local LLM, raising average latency to **~22.5 seconds per query**.

### 2. Fair Comparison of Vectorless RAG v4 and Vector RAG (Ollama)

Both systems use local Ollama to compile context, but they choose different paths. Vector RAG uses nomic-embed-text to run cosine similarity queries on SQLite/Chroma, which has a fast search time but lower retrieval accuracy. Vectorless RAG v4 uses tree relationships and LLM scoring, which takes longer but achieves higher accuracy with a significantly smaller memory footprint (only ~36 MB memory growth).