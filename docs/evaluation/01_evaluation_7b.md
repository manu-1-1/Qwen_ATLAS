# Base Qwen 2.5 7B Evaluation Results

## Overview

This evaluation measures the performance of the baseline **Qwen 2.5 7B Instruct** model on MITRE ATT&CK threat intelligence tasks before the introduction of retrieval-augmented generation (RAG) or fine-tuning.

The benchmark consists of 40 queries covering:

* ATT&CK Technique ID lookups
* Technique name lookups
* Threat group attribution
* Group-to-technique mapping
* Technique-to-group mapping
* Mitigation recommendations
* Tactic-filtered threat intelligence queries
* Analyst-oriented semantic reasoning

All responses were generated using the base model without external knowledge retrieval.

---

## Evaluation Configuration

| Parameter        | Value                       |
| ---------------- | --------------------------- |
| Model            | Qwen 2.5 7B Instruct        |
| Retrieval        | Disabled                    |
| Fine-Tuning      | Disabled                    |
| Knowledge Source | Internal model weights only |
| Total Queries    | 40                          |
| Scoring Rubric   | v2                          |
| Maximum Score    | 80                          |

---

## Overall Results

| Metric      | Value   |
| ----------- | ------- |
| Total Score | 35 / 80 |
| Accuracy    | 43.75%  |

---

## Category Breakdown

| Category                 | Score   |
| ------------------------ | ------- |
| Technique ID Lookup      | 2 / 10  |
| Technique Name Lookup    | 5 / 10  |
| Group Information        | 6 / 10  |
| Group → Techniques       | 2 / 8   |
| Technique → Groups       | 1 / 10  |
| Mitigation Lookup        | 2 / 10  |
| Tactic-Filtered Queries  | 5 / 10  |
| Analyst Semantic Queries | 12 / 12 |

---

## Observations

### Strengths

The base model demonstrated reasonable general cybersecurity knowledge and analyst-oriented reasoning.

Notable strengths included:

* Credential dumping explanations
* Password spraying concepts
* Process injection concepts
* PowerShell abuse indicators
* SOC-oriented defensive reasoning
* General threat actor descriptions

The model achieved a perfect score on analyst semantic queries, indicating strong natural-language cybersecurity understanding.

---

### Weaknesses

The model struggled significantly with structured MITRE ATT&CK knowledge.

Observed failure modes included:

#### ATT&CK Identifier Hallucination

Examples:

* T1003 incorrectly identified as Remote Services
* T1021.001 incorrectly identified as Query Registry
* T1195.002 not recognized
* T1110.003 not recognized

#### Threat Group Attribution Errors

Examples:

* APT33 incorrectly attributed to China
* Lazarus Group incorrectly attributed to China
* Multiple nation-state attribution errors

#### Reverse ATT&CK Queries

The model performed poorly on:

* "Which groups use T1003?"
* "Who uses T1055?"
* "Which groups use T1195.002?"

These queries frequently resulted in hallucinated interpretations unrelated to ATT&CK.

Examples included:

* ACH transaction codes
* Telecommunications standards
* Generic cybersecurity concepts

#### ATT&CK Relationship Knowledge

The model lacked explicit knowledge of:

* Technique ↔ Group relationships
* Group ↔ Technique mappings
* ATT&CK mitigations
* ATT&CK sub-techniques

---

## Key Finding

The base Qwen 2.5 7B model possesses strong general cybersecurity reasoning capabilities but lacks reliable structured ATT&CK knowledge.

Performance deteriorates rapidly when queries require:

* Exact ATT&CK identifiers
* Threat actor attribution
* ATT&CK relationship traversal
* ATT&CK-specific mitigations
* Sub-technique resolution

This establishes a clear baseline for evaluating the impact of retrieval-augmented generation (RAG) and later QLoRA fine-tuning experiments.

---

## Conclusion

The baseline model achieved:

**35 / 80 (43.75%)**

While capable of producing useful cybersecurity explanations, it is not sufficiently reliable for ATT&CK-centric threat intelligence workflows without external knowledge augmentation.

The results justify the introduction of a dedicated ATT&CK retrieval system as the next stage of the Qwen-ATLAS architecture.
