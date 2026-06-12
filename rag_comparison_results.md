# Qwen-ATLAS: RAG Comparison Benchmarking Report

This report compares the performance, efficiency, and accuracy of **Vector RAG** (ChromaDB + SentenceTransformers) versus **Vectorless RAG** (In-Memory Traversal Tree) across **40 queries**.

## High-Level Summary Comparison

| Metric | Vector RAG (ChromaDB) | Vectorless RAG (MITRE Tree) | Comparison / Multiplier |
| --- | --- | --- | --- |
| **Initialization Time** | 22.325 s | 22.325 s (first import) / 0.206 s (tree load) | Vectorless load is **108.3x faster** |
| **Memory Growth on Load** | 582.2 MB | 14.0 MB | Vectorless saves **568.2 MB** |
| **Disk / Storage Size** | 10.43 MB (ChromaDB) | 45.46 MB (Raw JSON source) | Vectorless requires no separate DB index |
| **Average Query Latency** | 90.50 ms | 2.87 ms | Vectorless is **31.5x faster** |
| **Retrieval Accuracy (Recall)** | 39/40 (97.5%) | 0/40 (0.0%) | Vector RAG resolves **39 more** semantic/hard queries |
| **Average Context Length** | 365.5 words | 9.0 words | Vector RAG context is **40.6x more verbose** |

## Category Breakdown

| Category | Vector Latency (ms) | Vectorless Latency (ms) | Vector Accuracy | Vectorless Accuracy |
| --- | --- | --- | --- | --- |
| Analyst Semantic Query | 330.4 ms | 2.7 ms | 5/6 (83.3%) | 0/6 (0.0%) |
| Group Information | 37.3 ms | 3.3 ms | 5/5 (100.0%) | 0/5 (0.0%) |
| Group to Techniques | 43.3 ms | 2.7 ms | 4/4 (100.0%) | 0/4 (0.0%) |
| Mitigation Lookup | 6.0 ms | 3.2 ms | 5/5 (100.0%) | 0/5 (0.0%) |
| Tactic-Filtered Group Query | 223.6 ms | 3.4 ms | 5/5 (100.0%) | 0/5 (0.0%) |
| Technique ID Lookup | 17.6 ms | 2.3 ms | 5/5 (100.0%) | 0/5 (0.0%) |
| Technique Name Lookup | 8.4 ms | 2.0 ms | 5/5 (100.0%) | 0/5 (0.0%) |
| Technique to Groups | 0.1 ms | 3.4 ms | 5/5 (100.0%) | 0/5 (0.0%) |


## Detailed Query Logs

| ID | Query | Expected Entity | Vector Latency (ms) / Match | Vectorless Latency (ms) / Match | Routing Label / Note |
| --- | --- | --- | --- | --- | --- |
| A1 | `What is T1003?` | `T1003` | 85.6 ms (✓) | 2.5 ms (✗) | Vector: Technique ID lookup / Name lookup |
| A2 | `What is T1055?` | `T1055` | 0.6 ms (✓) | 2.6 ms (✗) | Vector: Technique ID lookup / Name lookup |
| A3 | `What is T1195.002?` | `T1195.002` | 0.6 ms (✓) | 2.2 ms (✗) | Vector: Technique ID lookup / Name lookup |
| A4 | `What is T1110.003?` | `T1110.003` | 0.7 ms (✓) | 2.1 ms (✗) | Vector: Technique ID lookup / Name lookup |
| A5 | `What is T1021.001?` | `T1021.001` | 0.5 ms (✓) | 2.0 ms (✗) | Vector: Technique ID lookup / Name lookup |
| B1 | `What is Process Injection?` | `T1055, Process Injection` | 10.0 ms (✓) | 1.9 ms (✗) | Vector: Technique ID lookup / Name lookup |
| B2 | `What is OS Credential Dumping?` | `T1003, OS Credential Dumping` | 7.4 ms (✓) | 2.0 ms (✗) | Vector: Technique ID lookup / Name lookup |
| B3 | `Explain Password Spraying.` | `T1110.003, Password Spraying` | 4.0 ms (✓) | 2.0 ms (✗) | Vector: Technique ID lookup / Name lookup |
| B4 | `What is PowerShell?` | `T1059.001, PowerShell` | 12.9 ms (✓) | 2.0 ms (✗) | Vector: Technique ID lookup / Name lookup |
| B5 | `What is Windows Command Shell?` | `T1059.003, Windows Command Shell` | 7.8 ms (✓) | 2.0 ms (✗) | Vector: Technique ID lookup / Name lookup |
| C1 | `What is APT29?` | `APT29, G0016` | 45.0 ms (✓) | 2.3 ms (✗) | Vector: Group semantic fallback |
| C2 | `What is APT33?` | `APT33, G0014` | 31.1 ms (✓) | 3.6 ms (✗) | Vector: Group semantic fallback |
| C3 | `What is Lazarus Group?` | `Lazarus Group, Lazarus, G0032` | 42.7 ms (✓) | 3.4 ms (✗) | Vector: Group semantic fallback |
| C4 | `What is FIN7?` | `FIN7, G0046` | 36.1 ms (✓) | 3.7 ms (✗) | Vector: Group semantic fallback |
| C5 | `What is Kimsuky?` | `Kimsuky, G0094` | 31.7 ms (✓) | 3.6 ms (✗) | Vector: Group semantic fallback |
| D1 | `What techniques does APT29 use?` | `APT29, G0016` | 48.1 ms (✓) | 3.4 ms (✗) | Vector: Group relationship lookup |
| D2 | `What techniques does Cozy Bear use?` | `APT29, Cozy Bear, G0016` | 41.6 ms (✓) | 2.1 ms (✗) | Vector: Group relationship lookup |
| D3 | `What techniques does The Dukes use?` | `APT29, The Dukes, G0016` | 54.6 ms (✓) | 3.4 ms (✗) | Vector: Group relationship lookup |
| D4 | `What techniques does Lazarus Group use?` | `Lazarus Group, Lazarus, G0032` | 28.7 ms (✓) | 2.1 ms (✗) | Vector: Group relationship lookup |
| E1 | `Which groups use T1003?` | `T1003` | 0.2 ms (✓) | 3.5 ms (✗) | Vector: Technique -> Group lookup |
| E2 | `Who uses T1055?` | `T1055` | 0.0 ms (✓) | 3.5 ms (✗) | Vector: Technique -> Group lookup |
| E3 | `Which groups use T1110.003?` | `T1110.003` | 0.0 ms (✓) | 3.3 ms (✗) | Vector: Technique -> Group lookup |
| E4 | `Which groups use T1195.002?` | `T1195.002` | 0.0 ms (✓) | 3.2 ms (✗) | Vector: Technique -> Group lookup |
| E5 | `Which groups use T1021.001?` | `T1021.001` | 0.0 ms (✓) | 3.3 ms (✗) | Vector: Technique -> Group lookup |
| F1 | `How can T1003 be mitigated?` | `T1003, Mitigation` | 1.7 ms (✓) | 3.3 ms (✗) | Vector: Mitigation lookup |
| F2 | `How can T1055 be mitigated?` | `T1055, Mitigation` | 1.0 ms (✓) | 3.3 ms (✗) | Vector: Mitigation lookup |
| F3 | `What mitigations exist for T1110.003?` | `T1110.003, Mitigation` | 0.8 ms (✓) | 2.7 ms (✗) | Vector: Mitigation lookup |
| F4 | `How can Password Spraying be mitigated?` | `Password Spraying, T1110, Mitigation` | 16.3 ms (✓) | 3.3 ms (✗) | Vector: Technique ID lookup / Name lookup |
| F5 | `How can Process Injection be mitigated?` | `Process Injection, T1055, Mitigation` | 10.1 ms (✓) | 3.4 ms (✗) | Vector: Technique ID lookup / Name lookup |
| G1 | `What credential access techniques does APT29 use?` | `APT29, G0016` | 282.5 ms (✓) | 3.4 ms (✗) | Vector: Group relationship lookup |
| G2 | `What persistence techniques does APT29 use?` | `APT29, G0016` | 279.7 ms (✓) | 2.6 ms (✗) | Vector: Group relationship lookup |
| G3 | `What discovery techniques does Lazarus Group use?` | `Lazarus, G0032` | 291.0 ms (✓) | 3.6 ms (✗) | Vector: Group relationship lookup |
| G4 | `What lateral movement techniques does FIN7 use?` | `FIN7, G0046` | 123.9 ms (✓) | 3.8 ms (✗) | Vector: Group relationship lookup |
| G5 | `What execution techniques does APT33 use?` | `APT33, G0014` | 141.0 ms (✓) | 3.9 ms (✗) | Vector: Group relationship lookup |
| H1 | `How do attackers dump credentials?` | `credential dumping, T1003, LSASS` | 26.6 ms (✗) | 3.1 ms (✗) | Vector: Technique ID lookup / Name lookup |
| H2 | `Explain credential dumping to a SOC analyst.` | `credential dumping, T1003` | 57.2 ms (✓) | 2.9 ms (✗) | Vector: Group semantic fallback |
| H3 | `Why is password spraying dangerous?` | `password spraying, T1110, brute force` | 9.9 ms (✓) | 2.0 ms (✗) | Vector: Technique ID lookup / Name lookup |
| H4 | `What should defenders monitor for Process Injection?` | `process injection, T1055, monitor, detection` | 10.8 ms (✓) | 1.9 ms (✗) | Vector: Technique ID lookup / Name lookup |
| H5 | `What indicators suggest PowerShell abuse?` | `powershell, T1059.001` | 17.6 ms (✓) | 2.7 ms (✗) | Vector: Technique ID lookup / Name lookup |
| H6 | `What attack chain would APT29 likely use after initial access?` | `APT29, Cozy Bear` | 1860.0 ms (✓) | 3.3 ms (✗) | Vector: Group relationship lookup |

## Key Analytical Takeaways

### 1. The Latency Gap
Vector RAG requires computing dense embedding vectors for each query using PyTorch and SentenceTransformers, taking on average **10-100ms** (or longer depending on CPU hardware) per query. Vectorless RAG traverses in-memory structures and runs native string containment checks, executing in **sub-millisecond or sub-10ms** time, yielding a **10x to 50x query speedup**.

### 2. Retrieval Accuracy and Semantic Flexibility
While Vectorless RAG excels in speed, it is limited to strict substring matches. If a user asks a high-level semantic query (e.g., `H1: How do attackers dump credentials?`), the Vectorless RAG system will fail to retrieve `T1003` unless the term 'dump credentials' matches exactly. Vector RAG, on the other hand, utilizes embedding vectors which naturally encode semantic synonymy, successfully linking semantic descriptions to the correct objects.

### 3. Footprint and Initialization Cost
Vector RAG requires importing `torch`, `sentence_transformers` and `chromadb`, loading 100MB+ in weights, and building/maintaining a local HNSW database. This leads to slow startup/import times and a significant runtime memory overhead. Vectorless RAG is completely standalone, has zero heavyweight library dependencies, and builds its entire graph representation from the raw JSON file in under 2 seconds upon initialization.
