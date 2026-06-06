# Qwen-ATLAS Evaluation Report — Qwen 2.5 7B Instruct Baseline

**Date:** 2026-06-06
**Evaluator:** Karthik
**Purpose:** True baseline evaluation before LoRA fine-tuning
**Model:** Qwen/Qwen2.5-7B-Instruct
**Compute:** Kaggle (T4 GPU)
**RAG Pipeline:** ChromaDB + MiniLM-L6-v2 + ATT&CK entity router

---

## 1. Scope and Intent

This is the primary baseline evaluation for the Qwen-ATLAS project. Results from this report serve as the reference point for measuring improvement after LoRA fine-tuning on clean data, and degradation after fine-tuning on poisoned data.

The three-way comparison structure:

| Variant | Report |
|---------|--------|
| Base 7B + RAG (this report) | `docs/evaluation_7B_baseline.md` |
| Fine-tuned clean + RAG | `docs/evaluation_7B_finetuned.md` |
| Fine-tuned poisoned + RAG | `docs/evaluation_7B_poisoned.md` |

The 0.5B smoke test (`docs/evaluation_0.5B.md`) is not part of this comparison — it was a pipeline validation exercise only.

---

## 2. Test Queries

Ten queries were run against both plain (no RAG) and RAG-augmented configurations. Queries exercise all three router paths and cover the primary threat intelligence use cases.

| # | Query | Router Path | Category |
|---|-------|-------------|----------|
| Q1 | What is T1003? | Technique ID lookup | Technique identification |
| Q2 | Explain T1055 | Technique ID lookup | Technique explanation |
| Q3 | What techniques does APT29 use? | Group relationship lookup | Group TTP enumeration |
| Q4 | What credential access techniques does APT29 use? | Group relationship lookup | Group TTP (tactic-filtered) |
| Q5 | What is APT33? | Group relationship lookup | Group identification |
| Q6 | How can T1003 be mitigated? | Technique ID lookup | Mitigation |
| Q7 | Which groups use T1003? | Technique → Group lookup | Reverse attribution |
| Q8 | What is Process Injection? | Semantic search | Technique explanation |
| Q9 | What platforms are affected by T1003? | Technique ID lookup | Technique metadata |
| Q10 | What is T1195.002? | Technique ID lookup | Sub-technique identification |

---

## 3. Results — Plain (No RAG)

### Q1 — What is T1003?

> "T1003 specifically refers to Network Service Scanning."

**Assessment: FAIL — Wrong technique mapping.** The 7B model has ATT&CK knowledge but it is imprecise. It recognises the identifier format but maps T1003 to an incorrect technique. T1003 is OS Credential Dumping, not Network Service Scanning.

---

### Q2 — Explain T1055

> "Process injection is a technique where malicious code or a payload is inserted into the memory space of a legitimate process..."

**Assessment: PASS — General description correct.** T1055 is well-represented in pretraining data. The conceptual explanation is accurate and the technique name is correct. No technique ID was cited in the response body, no sub-techniques mentioned, no tactic mapping or detection content included. Sufficient as a general explanation; insufficient for structured threat intelligence output.

---

### Q3 — What techniques does APT29 use?

> "APT29 often targets specific websites... Phishing... Exploits and Malware Delivery... Living Off the Land..."

**Assessment: PARTIAL FAIL — No ATT&CK structure.** The model correctly identifies APT29 as Cozy Bear and produces plausible TTP descriptions. However, no technique IDs are cited, no ATT&CK tactic mapping is provided, and the descriptions are general security knowledge rather than ATT&CK-attributed techniques. Unusable for analyst workflows.

---

### Q4 — What credential access techniques does APT29 use?

> "Phishing... Watering Hole Attacks... Exploiting Vulnerabilities... Mimikatz..."

**Assessment: FAIL — Generic response, no ATT&CK grounding.** Mimikatz is a real APT29 tool but the response does not map it to T1003 or any credential access technique ID. The rest of the response describes initial access and lateral movement techniques, not credential access. Tactic scoping was ignored.

---

### Q5 — What is APT33?

> "APT33, also known as OilRig, is a sophisticated state-sponsored cyber espionage group..."

**Assessment: FAIL — Attribution error.** APT33 is Elfin, a suspected Iranian group. OilRig is a separate Iranian group (APT34). The model conflated two distinct threat actors. This class of misattribution is exactly the failure mode Qwen-ATLAS is designed to prevent.

---

### Q6 — How can T1003 be mitigated?

> "T1003 involves the adversary using legitimate credentials or other means to maintain persistence..."

**Assessment: FAIL — Technique conflation.** The model described T1078 (Valid Accounts) behavior instead of T1003 (OS Credential Dumping). The mitigation advice that follows is consequently misaligned. Despite producing a structured-looking response, the foundational technique identification was wrong.

---

### Q7 — Which groups use T1003?

> "T1003 is a financial transaction message format used primarily in the banking and financial services industry... part of the SWIFT standard..."

**Assessment: FAIL — Complete domain hallucination.** The model produced a detailed, confident response about SWIFT banking protocols with no connection to cybersecurity. This is the most severe failure in the evaluation set — the model had no grounding and confabulated an entirely unrelated domain narrative.

---

### Q8 — What is Process Injection?

> "Process injection is a technique used in software development and cybersecurity to inject or load code into the address space of another process..."

**Assessment: PASS — Conceptually correct.** Same pattern as Q2. Accurate general description, no ATT&CK structure, no technique ID cited.

---

### Q9 — What platforms are affected by T1003?

> "T1003 refers to Exfiltration Over Alternative Protocol... affects systems supporting FTP, SMTP, DNS..."

**Assessment: FAIL — Wrong technique.** T1003 was mapped to T1048 (Exfiltration Over Alternative Protocol). The platform answer that follows is consequently irrelevant. Correct answer is Linux, macOS, Windows.

---

### Q10 — What is T1195.002?

> "T1195 does not directly correspond to any publicly known technique in the MITRE ATT&CK framework as of my last update."

**Assessment: FAIL — Training data gap.** The model's ATT&CK knowledge does not reliably cover sub-techniques. T1195.002 is Compromise Software Supply Chain, a documented ATT&CK technique. The model acknowledged uncertainty rather than hallucinating, which is preferable behaviour, but the answer is still incorrect.

---

### Plain (No RAG) Summary

| Query | Result | Failure Mode |
|-------|--------|--------------|
| Q1 — T1003 identification | FAIL | Wrong technique mapping |
| Q2 — T1055 explanation | PASS | No ATT&CK structure |
| Q3 — APT29 techniques | PARTIAL FAIL | No technique IDs or tactic mapping |
| Q4 — APT29 credential access | FAIL | Tactic scoping ignored, no IDs |
| Q5 — APT33 identification | FAIL | Actor conflation (APT33 ≠ OilRig) |
| Q6 — T1003 mitigation | FAIL | Technique conflation with T1078 |
| Q7 — Groups using T1003 | FAIL | Complete domain hallucination (SWIFT) |
| Q8 — Process Injection | PASS | No ATT&CK structure |
| Q9 — T1003 platforms | FAIL | Wrong technique (T1048) |
| Q10 — T1195.002 | FAIL | Sub-technique training data gap |

**Score: 2/10 pass, 1/10 partial, 7/10 fail**

---

## 4. Results — With RAG (Entity Router + ChromaDB)

### Q1 — What is T1003?

> "T1003 is a technique in the MITRE ATT&CK framework where adversaries attempt to dump credentials to obtain account login and credential material, typically in the form of a hash or a clear text password."

**Assessment: PASS.** Entity router fired correctly (`[Router] Technique ID lookup`). Direct metadata lookup returned the correct object. Response is factually accurate.

---

### Q2 — Explain T1055

> "T1055, also known as Process Injection, is a technique used by adversaries to inject code into processes in order to evade process-based defenses and potentially elevate privileges."

**Assessment: PASS.** Technique ID and name correct. Description accurate and grounded in retrieved context. Concise.

---

### Q3 — What techniques does APT29 use?

> "APT29 uses: Compromise Software Supply Chain (T1195.002), Vulnerability Scanning (T1595.002), Code Repositories (T1213.003), Tool (T1588.002), External Proxy (T1090.002)"

**Assessment: PARTIAL PASS.** Technique IDs are real and attributed to APT29. However the result is skewed toward reconnaissance and resource development techniques; APT29 is known for a much broader TTP profile. Top-5 retrieval limit is constraining the response. No tactic mapping or narrative context is provided. Factually correct but analytically incomplete.

---

### Q4 — What credential access techniques does APT29 use?

> "APT29 uses the following credential access techniques: Credentials from Password Stores (T1555), LSA Secrets (T1003.004)"

**Assessment: PARTIAL PASS.** Tactic-filtered re-ranking is working — the response is scoped to credential access correctly. T1555 and T1003.004 are legitimate APT29 attributions. Response is incomplete; APT29 has additional credential access techniques not surfaced here. Format is a list with no analyst framing.

---

### Q5 — What is APT33?

> "Unavailability: The provided ATT&CK context does not contain information about APT33. The context only lists APT3 as associated with specific techniques."

**Assessment: FAIL — Gap in ChromaDB.** The router fired correctly but the retriever could not find APT33 in the database. The model correctly reported the absence rather than hallucinating, which is appropriate behaviour. Root cause is either an ingestion gap or a group name matching failure..

---

### Q6 — How can T1003 be mitigated?

> "Mitigation for T1003 (OS Credential Dumping): Disable unnecessary services... Implement strong passwords... Use MFA... Employ Credential Guard... Limit administrative privileges... Monitor system logs..."

**Assessment: PASS.** Technique correctly identified as OS Credential Dumping. Mitigation advice is relevant and grounded. No ATT&CK mitigation IDs (M-numbers) cited — this is a gap fine-tuning should address.

---

### Q7 — Which groups use T1003?

> "Suckfly, Ember Bear, APT28, APT39, APT32, Leviathan, Mustang Panda, Storm-0501, BlackByte, Tonto Team, Axiom, Sowbug, Poseidon Group"

**Assessment: PASS.** Router correctly executed technique → group reverse lookup. Response is a flat list of group names with no framing, confidence weighting, or tactic context, but the attribution data is accurate.

---

### Q8 — What is Process Injection?

> "Process Injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges."

**Assessment: PASS.** Semantic search path worked correctly. Response is accurate and grounded in the retrieved STIX description.

---

### Q9 — What platforms are affected by T1003?

> "Linux, macOS, Windows"

**Assessment: PASS.** Direct metadata lookup returned the correct platform field. Concise and accurate.

---

### Q10 — What is T1195.002?

> "T1195.002 is a technique in the MITRE ATT&CK framework related to the tactic of initial-access. It describes adversaries manipulating application software before it reaches the end consumer..."

**Assessment: PASS.** Sub-technique lookup worked correctly. The retriever found the object that the plain model claimed did not exist. Factually accurate.

---

### With-RAG Summary

| Query | Result | Notes |
|-------|--------|-------|
| Q1 — T1003 identification | PASS | Direct lookup correct |
| Q2 — T1055 explanation | PASS | Semantic path correct |
| Q3 — APT29 techniques | PARTIAL PASS | Real IDs, top-5 too narrow for full profile |
| Q4 — APT29 credential access | PARTIAL PASS | Tactic filtering works, incomplete coverage |
| Q5 — APT33 identification | FAIL | APT33 missing from ChromaDB |
| Q6 — T1003 mitigation | PASS | Correct technique, no M-numbers cited |
| Q7 — Groups using T1003 | PASS | Reverse lookup correct |
| Q8 — Process Injection | PASS | Semantic path correct |
| Q9 — T1003 platforms | PASS | Metadata field returned correctly |
| Q10 — T1195.002 | PASS | Sub-technique lookup correct |

**Score: 7/10 pass, 2/10 partial, 1/10 fail**

---

## 5. Comparative Summary

| Query | Plain | RAG | Delta |
|-------|-------|-----|-------|
| Q1 — T1003 identification | FAIL | PASS | +1 |
| Q2 — T1055 explanation | PASS | PASS | 0 |
| Q3 — APT29 techniques | PARTIAL FAIL | PARTIAL PASS | +1 |
| Q4 — APT29 credential access | FAIL | PARTIAL PASS | +1 |
| Q5 — APT33 identification | FAIL | FAIL | 0 |
| Q6 — T1003 mitigation | FAIL | PASS | +1 |
| Q7 — Groups using T1003 | FAIL | PASS | +2 |
| Q8 — Process Injection | PASS | PASS | 0 |
| Q9 — T1003 platforms | FAIL | PASS | +1 |
| Q10 — T1195.002 | FAIL | PASS | +1 |
| **Score** | **2/10** | **7/10** | **+5** |

RAG grounding produces a measurable and consistent improvement across all query categories. The delta is largest on identifier-based queries (T1003, T1195.002, platform lookup) where the plain model's training data is imprecise or absent.

---

## 6. Key Findings

**Finding 1 — Plain 7B ATT&CK knowledge is unreliable.**
The model recognises ATT&CK identifier formats but maps them incorrectly under ambiguity (T1003 → Network Service Scanning, T1003 → Exfiltration Over Alternative Protocol). Sub-technique granularity is largely absent from training data. Actor attribution contains errors (APT33 conflated with OilRig/APT34). This confirms that fine-tuning on ATT&CK-specific data is necessary even for a 7B model.

**Finding 2 — RAG resolves factual failures but not structural ones.**
RAG responses are factually correct but analytically thin. They read as database lookups rather than intelligence assessments — no tactic framing, no confidence reasoning, no detection context, no narrative synthesis. A real analyst response to "What techniques does APT29 use?" would include tactic grouping, campaign context, and prioritisation. This structural gap is what fine-tuning is expected to address.

**Finding 3 — The entity router is functioning correctly across all three paths.**
Technique ID lookup, group relationship lookup, tactic-filtered re-ranking, and reverse technique-to-group lookup all fired correctly. The APT33 failure is a data gap, not a routing failure — the router executed correctly and the model reported the absence honestly.

**Finding 4 — APT33 is missing from the knowledge base.**
The retriever returned APT3 context when queried for APT33, suggesting either an ingestion gap or a prefix-matching collision in the group name resolver. This is a pipeline data issue.

**Finding 5 — Top-5 retrieval is insufficient for broad group TTP queries.**
APT29 has over 100 attributed techniques. Top-5 retrieval surfaces a narrow, skewed subset. Tactic-filtered queries (Q4) partially mitigate this by scoping the candidate set before re-ranking, but unscoped group queries (Q3) will remain analytically incomplete at top-5. Consider increasing k for group queries or implementing tactic-aware query expansion.

---

## 7. Gap Analysis — What Fine-Tuning Should Fix

| Gap | Observed In | Expected Post-Fine-Tune |
|-----|-------------|------------------------|
| No ATT&CK IDs in plain responses | Q2, Q3, Q8 | Model cites technique IDs by default |
| No tactic framing in responses | Q3, Q4, Q6 | Responses include tactic context |
| No mitigation IDs (M-numbers) | Q6 | Model cites M-numbers from retrieved context |
| No analyst narrative structure | Q3, Q4, Q7 | Responses follow analyst output format |
| Actor attribution errors (plain) | Q5 | Correct attribution from fine-tuned domain knowledge |

---

## 8. Open Issues

| Issue | Severity | Owner |
|-------|----------|-------|
| APT33 missing from ChromaDB or group name collision | Medium | — |
| Top-5 too narrow for unscoped group TTP queries | Medium | — |
| No M-numbers in mitigation responses | Low | Addressable via fine-tuning |
| Clean dataset at 914 pairs, below 3k–5k target | Medium | — |

---

## 9. Next Steps

- [ ] Resolve APT33 ingestion gap before fine-tuning run
- [ ] Expand dataset size — 914 pairs is the current floor; more data needed before cloud training run
- [ ] Activate AMD Developer Cloud credits — pipeline validated, baseline recorded, activation is unblocked
- [ ] Begin LoRA fine-tuning on MI300X with clean dataset
- [ ] Re-run identical 10 queries post fine-tuning for direct comparison

---

## 10. Appendix — Environment

```
Compute:      Kaggle (NVIDIA 2xT4 GPUs)
Model:        Qwen/Qwen2.5-7B-Instruct (HuggingFace transformers)
RAG DB:       ChromaDB persistent (pre-populated)
Embedder:     sentence-transformers/all-MiniLM-L6-v2
ATT&CK data:  enterprise-attack.json (STIX v2.1, MITRE CTI, bundled)
Framework:    Python 3.x
```
