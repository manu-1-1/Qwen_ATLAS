# Qwen 2.5 7B + ATT&CK RAG Evaluation Results

## Overview

This evaluation measures the performance of **Qwen 2.5 7B Instruct augmented with the Qwen-ATLAS ATT&CK Retrieval System**.

Unlike the baseline model, responses were generated using retrieved context from:

* MITRE ATT&CK Enterprise ATT&CK dataset
* ATT&CK techniques
* ATT&CK groups
* ATT&CK mitigations
* ATT&CK relationship mappings
* Custom routing and retrieval logic

The same 40-query benchmark used for baseline evaluation was executed to enable direct comparison.

---

## Evaluation Configuration

| Parameter        | Value                           |
| ---------------- | ------------------------------- |
| Model            | Qwen 2.5 7B Instruct            |
| Retrieval        | Enabled                         |
| Fine-Tuning      | Disabled                        |
| Vector Database  | ChromaDB                        |
| Embedding Model  | all-MiniLM-L6-v2                |
| Knowledge Source | MITRE ATT&CK Enterprise Dataset |
| Total Queries    | 40                              |
| Scoring Rubric   | v2                              |
| Maximum Score    | 80                              |

---

## Overall Results

| Metric      | Value   |
| ----------- | ------- |
| Total Score | 67 / 80 |
| Accuracy    | 83.75%  |

---

## Category Breakdown

| Category                 | Score   |
| ------------------------ | ------- |
| Technique ID Lookup      | 10 / 10 |
| Technique Name Lookup    | 10 / 10 |
| Group Information        | 10 / 10 |
| Group → Techniques       | 8 / 8   |
| Technique → Groups       | 2 / 10  |
| Mitigation Lookup        | 6 / 10  |
| Tactic-Filtered Queries  | 10 / 10 |
| Analyst Semantic Queries | 11 / 12 |

---

## Improvements Over Baseline

### ATT&CK Identifier Resolution

The largest improvement occurred in ATT&CK identifier lookups.

Examples successfully resolved:

* T1003 → OS Credential Dumping
* T1055 → Process Injection
* T1195.002 → Compromise Software Supply Chain
* T1110.003 → Password Spraying
* T1021.001 → Remote Desktop Protocol

These queries frequently failed in the baseline model.

---

### Threat Group Attribution

The RAG system eliminated major attribution errors.

Examples corrected:

* APT33 → Iranian threat actor
* Lazarus Group → North Korean threat actor
* APT29 → Russian SVR-linked actor
* Kimsuky → North Korean espionage actor

The baseline model frequently hallucinated nation-state affiliations.

---

### ATT&CK Relationship Knowledge

The retrieval layer enabled successful resolution of:

* Group → Technique mappings
* Alias → Group mappings
* Technique → Mitigation mappings
* Tactic-filtered technique enumeration

Examples:

* Cozy Bear → APT29
* The Dukes → APT29
* Credential-access techniques used by APT29
* Discovery techniques used by Lazarus Group

These relationships are not explicitly stored within the base model's parameters and were successfully supplied through retrieval.

---

### ATT&CK Sub-Techniques

The RAG system resolved ATT&CK sub-techniques reliably.

Examples:

* T1110.003
* T1195.002
* T1021.001

The baseline model frequently failed to recognize these identifiers.

---

## Remaining Failure Modes

Although retrieval significantly improved performance, several failures remained.

### Generation-Level Hallucinations

In multiple cases the retriever supplied the correct ATT&CK object, but the model generated an incorrect explanation afterward.

Examples:

#### T1055

Retrieved correctly.

Model later described:

> PowerShell command-and-control activity

Correct answer:

> Process Injection

---

#### T1195.002

Retrieved correctly.

Model later described:

> Stolen credentials

Correct answer:

> Compromise Software Supply Chain

---

### Reverse ATT&CK Queries

Technique → Group queries remain the weakest category.

Examples:

* Which groups use T1055?
* Which groups use T1195.002?

The retriever frequently returned correct group mappings, but generation drift occasionally corrupted the final answer.

---

### Mitigation Generation

Mitigation retrieval generally worked correctly.

However, the model sometimes:

* Confused technique identities
* Mixed mitigation contexts
* Introduced unsupported ATT&CK mappings

These errors reduced the mitigation score despite successful retrieval.

---

## Key Finding

The majority of baseline failures were knowledge failures.

RAG successfully corrected:

* ATT&CK identifier hallucinations
* Threat actor attribution errors
* ATT&CK relationship queries
* ATT&CK sub-technique resolution
* ATT&CK mitigation retrieval

The remaining failures are primarily generation failures rather than retrieval failures.

This distinction is important because it suggests that future improvements should focus on:

* Prompt engineering
* Response formatting
* Instruction tuning
* QLoRA fine-tuning

rather than expanding the ATT&CK knowledge base itself.

---

## Comparative Results

| Model                    | Score            |
| ------------------------ | ---------------- |
| Base Qwen 2.5 7B         | 35 / 80 (43.75%) |
| Qwen 2.5 7B + ATT&CK RAG | 67 / 80 (83.75%) |

### Improvement

| Metric               | Value                   |
| -------------------- | ----------------------- |
| Absolute Gain        | +32 points              |
| Accuracy Gain        | +40.0 percentage points |
| Relative Improvement | +91.4%                  |

---

## Conclusion

The ATT&CK retrieval system substantially improves the model's ability to perform structured threat intelligence tasks.

Performance increased from:

**43.75% → 83.75%**

without any model fine-tuning.

These results demonstrate that retrieval augmentation contributes more to ATT&CK knowledge acquisition than parameter-only knowledge stored in the base model.

The remaining error profile suggests that future gains are most likely to come from fine-tuning and output-control mechanisms rather than further expansion of the ATT&CK knowledge base.
