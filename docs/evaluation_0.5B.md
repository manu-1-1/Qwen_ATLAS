# Qwen-ATLAS Evaluation Report — Qwen 2.5 0.5B Instruct

**Date:** 2026-06-05
**Purpose:** Test and pipeline validation before 7B baseline evaluation.
**Model:** Qwen2.5-0.5B-Instruct (local CPU inference, Arch Linux)
**RAG Pipeline:** ChromaDB + MiniLM-L6-v2 + ATT&CK entity router

---

## 1. Scope and Intent

This is not the project's primary baseline evaluation. The 0.5B model was used to:

1. Validate the end-to-end inference pipeline locally before cloud activation
2. Confirm the RAG entity router is functioning correctly
3. Establish a floor reference showing how little ATT&CK knowledge exists without fine-tuning or grounding
4. Identify failure modes to carry forward into 7B eval design

The authoritative three-way comparison (Base 7B + RAG, Fine-tuned clean + RAG, Fine-tuned poisoned + RAG) will be conducted on Qwen 2.5 7B Instruct

---

## 2. Test Queries

Five queries were run against both configurations. Queries were chosen to exercise distinct retrieval paths and response types.

| # | Query | RAG Router Path | Category |
|---|-------|-----------------|----------|
| Q1 | What is T1003? | Technique ID lookup | Technique identification |
| Q2 | What is APT29? | Group relationship lookup | Group identification |
| Q3 | What techniques does APT29 use? | Group relationship lookup | Group TTP enumeration |
| Q4 | Explain Process Injection | Semantic search | Technique explanation |
| Q5 | How can defenders mitigate credential dumping? | Semantic search | Mitigation/detection |

---

## 3. Results — Without RAG

### Q1 — What is T1003?

> "T1003 is a type of cancer drug used to treat certain types of breast and ovarian cancers. It belongs to the category of chemotherapy drugs known as taxanes."

**Assessment: FAIL — Complete hallucination.** The model has no ATT&CK knowledge. `T1003` was treated as an arbitrary alphanumeric token and confabulated as a pharmaceutical compound. Confidence was unwarranted.

---

### Q2 — What is APT29?

> "APT29 was discovered in 2018 by the National Security Agency (NSA)."

**Assessment: FAIL — Fabricated attribution.** APT29 is a Russian state-sponsored group (Cozy Bear) attributed by multiple intelligence agencies, not discovered by the NSA in 2018. The model produced a structurally plausible but factually incorrect response.

---

### Q3 — What techniques does APT29 use?

> "APT29 is a reverse shell exploit developed by the National Cyber Security Division (NCSA) in 1987."

**Assessment: FAIL — Category error + hallucination.** APT29 was misidentified as a software tool rather than a threat actor group. The 1987 date is entirely fabricated. No technique enumeration was attempted.

---

### Q4 — Explain Process Injection

> "Process injection allows an attacker to inject malicious code into the execution of another process without affecting the host system..."

**Assessment: PARTIAL PASS — General description correct, no ATT&CK structure.** Process injection is well-represented in general security pretraining data. The conceptual explanation is accurate. However, no technique ID (T1055) was cited, no sub-techniques were mentioned, no tactic mapping was provided, and no detection/mitigation content was included. Acceptable as a general definition; insufficient for threat intelligence use.

---

### Q5 — How can defenders mitigate credential dumping?

> "Defenders who want to maintain their position on the field should be prepared to deal with the threat of credential dumping..."

**Assessment: FAIL — Context confusion.** The word "defenders" was interpreted in a sports context rather than a security context, causing complete topic drift. This is a known failure mode of small models with insufficient instruction-following capacity.

---

### Without-RAG Summary

| Query | Result | Failure Mode |
|-------|--------|--------------|
| Q1 — T1003 | FAIL | Hallucination — no ATT&CK knowledge |
| Q2 — APT29 | FAIL | Fabricated attribution |
| Q3 — APT29 techniques | FAIL | Category error + hallucination |
| Q4 — Process Injection | PARTIAL PASS | General knowledge only, no ATT&CK structure |
| Q5 — Credential dumping | FAIL | Context confusion from ambiguous token |

**Score: 0/5 full passes, 1/5 partial**

---

## 4. Results — With RAG (Entity Router + ChromaDB)

### Q1 — What is T1003?

> "The technique described in the ATT&CK context is called 'OS Credential Dumping' (T1003). This involves attempting to extract credentials from an operating system's cache, memory, or other storage locations."

**Assessment: PASS.** The entity router correctly identified `T1003` as a technique ID and performed a direct metadata lookup, bypassing semantic search. The model correctly synthesized the retrieved object. Technique ID, name, and description are accurate.

---

### Q2 — What is APT29?

> "APT29 is an advanced persistent threat group that operates primarily on the Windows operating system. The attack involves exploiting vulnerabilities in Microsoft products, particularly Office 365..."

**Assessment: FAIL — Model hallucinated over retrieved context.** The router correctly routed to group relationship lookup. However, the 0.5B model ignored or failed to synthesize the retrieved APT29 object and produced hallucinated content (Office 365 exploitation is not a defining APT29 characteristic; the characterization is generic and inaccurate). **This is a model capacity failure, not a retrieval failure.**

---

### Q3 — What techniques does APT29 use?

> "APT29 uses several techniques related to supply chain compromises: Compromise Software Supply Chain (T1195.002), Vulnerability Scanning (T1595.002), Tool Acquisition (T1588.002)..."

**Assessment: PARTIAL PASS — Retrieval working, synthesis incomplete.** Technique IDs cited are real ATT&CK entries. However, T1595.002 and T1588.002 are reconnaissance/resource-development techniques not strongly characteristic of APT29's known TTPs. The model appears to be mixing retrieved context with confabulation rather than cleanly reporting what ATT&CK attributes to APT29. Partial credit for format and real ID usage.

---

### Q4 — Explain Process Injection

> "Process Injection (T1055) is a technique used by attackers to bypass traditional process-based security measures... The key aspects include Stealth, Privilege Escalation, Evasion, Multiple Processes."

**Assessment: PASS.** Technique ID correctly cited. Semantic search routed correctly. The description is accurate and structured. The 0.5B model performs adequately on this query because (a) process injection is well-covered in pretraining data and (b) the semantic retrieval path provides good grounding context.

---

### Q5 — How can defenders mitigate credential dumping?

> "Defenders can mitigate credential dumping by implementing: Regular Audits, Access Control Measures, Data Encryption, Firewall and IDS, Anti-Malware..."

**Assessment: PARTIAL PASS — Direction correct, no ATT&CK structure.** The sports context confusion from the no-RAG run is resolved. Response is relevant and coherent. However, no MITRE mitigation IDs (M-numbers) are cited, no specific ATT&CK detection data sources are referenced, and the advice is generic rather than ATT&CK-grounded. The RAG context was retrieved but not leveraged for structured output.

---

### With-RAG Summary

| Query | Result | Notes |
|-------|--------|-------|
| Q1 — T1003 | PASS | Entity router + direct lookup working correctly |
| Q2 — APT29 | FAIL | Model hallucinated over retrieved context — capacity issue |
| Q3 — APT29 techniques | PARTIAL PASS | Real IDs cited but incomplete/mixed attribution |
| Q4 — Process Injection | PASS | Semantic path works well for natural-language concepts |
| Q5 — Credential dumping | PARTIAL PASS | Context confusion resolved; no ATT&CK structure in output |

**Score: 2/5 full passes, 2/5 partial passes, 1/5 fail**

---

## 5. RAG Pipeline Validation

Separate from response quality, the retrieval infrastructure was validated:

| Component | Status | Notes |
|-----------|--------|-------|
| ChromaDB load | Working | Persistent client loads pre-populated DB correctly |
| MiniLM-L6-v2 embedding | Working | Encodes queries without error |
| Semantic search path | Working | Correct results for natural-language technique queries |
| Technique ID router (`Txxxx`) | Working | `[Router] Technique ID lookup` fires on T1003 |
| Group name router (`APTxx`, named actors) | Working | `[Router] Group relationship lookup` fires on APT29 |
| Relationship traversal | Working | Group → technique mapping executes correctly |
| Ingest-on-import bug | Known | `chroma_rag.py` re-ingests on every import; refactor to `build_db.py` / `retriever.py` pending |

The entity router resolves the failure modes identified in the June 5 RAG evaluation report. Identifier-based queries (`T1003`, `APT29`) now retrieve correct objects via direct metadata lookup rather than failing through semantic similarity.

---

## 6. Key Findings

**Finding 1 — 0.5B has no ATT&CK-specific knowledge without RAG.**
4/5 queries failed completely. This is expected and confirms the task requires either domain fine-tuning or RAG grounding. Useful as a floor reference.

**Finding 2 — RAG grounding resolves retrieval failures but not synthesis failures at 0.5B.**
The entity router is functioning. The retriever fetches correct objects. The 0.5B model cannot reliably synthesize retrieved context into accurate structured responses — visible in Q2 (APT29 description) and Q3 (technique attribution). This is a model capacity problem, not a data or retrieval problem.

**Finding 3 — The 0.5B results are a strong argument for fine-tuning.**
Even with correct context provided via RAG, the model fails to produce analyst-grade output. This motivates the fine-tuning step: the model needs not just access to ATT&CK data but the reasoning structure to synthesize it correctly. Fine-tuning provides that.

**Finding 4 — Pipeline is end-to-end validated.**
Inference runs locally without errors. The RAG interface contract (`hybrid_retrieve(query) → list[dict]` with `text` key) is confirmed compatible with the inference script.

---

## 7. Next Steps
- [ ] Run identical 5 queries on **Qwen 2.5 7B Instruct + RAG** — this is the true baseline
- [ ] Expand eval set to 30 queries covering all 5 categories before fine-tuning run
- [ ] Refactor `chroma_rag.py` → `build_db.py` + `retriever.py` before 7B integration
- [ ] Proceed to LoRA fine-tuning once 7B baseline is recorded

---

## 8. Appendix — Environment

```
OS:           Arch Linux
Hardware:     CPU-only (MX250 not used for inference), 8GB RAM
Model:        Qwen/Qwen2.5-0.5B-Instruct (HuggingFace transformers)
RAG DB:       ChromaDB persistent (pre-populated, shipped with repo)
Embedder:     sentence-transformers/all-MiniLM-L6-v2
ATT&CK data:  enterprise-attack.json (STIX v2.1, MITRE CTI, bundled)
Framework:    Python 3.14.4, venv
```
