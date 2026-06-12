# Qwen-ATLAS RAFT Adapter + ATT&CK RAG Evaluation

## Overview

This evaluation measures the performance of the **Qwen-ATLAS RAFT Adapter**, fine-tuned using 1,743 Retrieval-Augmented Fine-Tuning (RAFT) samples and integrated with the Qwen-ATLAS ATT&CK retrieval pipeline.

The objective of this benchmark is to evaluate the model's ability to consume retrieved ATT&CK context, perform structured analysis, and generate grounded cybersecurity responses while minimizing unsupported completions.

Unlike the baseline RAG evaluation, this model was additionally trained to:

* Process retrieved ATT&CK context explicitly.
* Produce structured reasoning traces.
* Perform multi-hop ATT&CK relationship analysis.
* Recognize insufficient context and avoid unsupported conclusions.

---

## Evaluation Configuration

| Parameter        | Value                               |
| ---------------- | ----------------------------------- |
| Model            | Qwen 2.5 7B Instruct + RAFT Adapter |
| Retrieval        | Enabled                             |
| Fine-Tuning      | QLoRA (2 Epochs)                    |
| Vector Database  | ChromaDB                            |
| Embedding Model  | all-MiniLM-L6-v2                    |
| Knowledge Source | MITRE ATT&CK Enterprise Dataset     |
| Total Queries    | 40                                  |
| Scoring Rubric   | v2                                  |
| Maximum Score    | 80                                  |

---

## Overall Results

| Metric      | Value   |
| ----------- | ------- |
| Total Score | 59 / 80 |
| Accuracy    | 73.75%  |

---

## Category Breakdown

| Category                 | Score   |
| ------------------------ | ------- |
| Technique ID Lookup      | 6 / 10  |
| Technique Name Lookup    | 5 / 10  |
| Group Information        | 10 / 10 |
| Group → Techniques       | 8 / 8   |
| Technique → Groups       | 8 / 10  |
| Mitigation Lookup        | 4 / 10  |
| Tactic-Filtered Queries  | 10 / 10 |
| Analyst Semantic Queries | 8 / 12  |

---

## Strengths

### 1. Strong ATT&CK Relationship Reasoning

The model demonstrated excellent performance when reasoning across ATT&CK relationships rather than simply retrieving isolated facts.

Notable examples include:

* Threat Group → Technique attribution
* Technique → Threat Group mapping
* Tactic-filtered technique extraction
* Multi-hop ATT&CK analysis

The model achieved perfect scores in:

| Category                | Score   |
| ----------------------- | ------- |
| Group Information       | 10 / 10 |
| Group → Techniques      | 8 / 8   |
| Tactic-Filtered Queries | 10 / 10 |

These tasks require selective extraction from multiple retrieved documents and represent more realistic analyst workflows than simple technique lookups.

---

### 2. Improved Retrieval Grounding

The fine-tuned model showed a strong tendency to rely on retrieved ATT&CK context rather than generating unsupported ATT&CK information from parametric memory.

When relevant context was present, the model generally extracted information directly from retrieved documents instead of producing speculative responses.

This behavior is consistent with the primary objective of Retrieval-Augmented Fine-Tuning.

---

### 3. Structured Analytical Responses

The model frequently produced explicit reasoning traces before generating final answers.

This behavior improved transparency and made it easier to trace how conclusions were derived from retrieved ATT&CK evidence.

In multi-document scenarios, the reasoning structure often reflected the retrieval path used to arrive at the final answer.

---

## Observed Failure Modes

### 1. Repetition Loops During Generation

Several responses exhibited repetitive token generation near the end of otherwise correct answers.

Examples included:

* Repetition of threat group names
* Repetition of ATT&CK identifiers
* Repetition of mitigation references

Importantly, these loops generally occurred after the model had already generated the correct analytical content.

This behavior is consistent with known inference-time artifacts in quantized language models and does not necessarily indicate incorrect reasoning.

---

### 2. Output Structure Variability

The model occasionally substituted alternative XML-style tags such as:

* `<response>`
* `<heading>`

instead of the expected:

* `<reasoning>`

Although the underlying cybersecurity content was often correct, these formatting deviations resulted in reduced benchmark scores.

---

### 3. Mitigation Retrieval Challenges

Mitigation-focused queries produced the weakest category performance.

When multiple mitigation documents were retrieved simultaneously, the model occasionally:

* Confused mitigation identifiers.
* Repeated mitigation IDs.
* Misclassified ATT&CK objects.

This suggests that mitigation retrieval and ranking remain a weaker area of the current retrieval pipeline.

---

## Comparative Results

| Model Configuration           | Score   | Accuracy |
| ----------------------------- | ------- | -------- |
| Base Qwen 2.5 7B (No RAG)     | 35 / 80 | 43.75%   |
| Qwen 2.5 7B RAFT (No RAG)     | 12 / 80 | 15.00%   |
| Base Qwen 2.5 7B + ATT&CK RAG | 67 / 80 | 83.75%   |
| Qwen 2.5 7B RAFT + RAG        | 59 / 80 | 73.75%   |

---

## Interpretation

The RAFT-enhanced model did not outperform the baseline RAG system on this benchmark.

The baseline RAG configuration achieved:

**67 / 80 (83.75%)**

compared to:

**59 / 80 (73.75%)**

for the RAFT-enhanced model.

However, the nature of the errors differs substantially.

The baseline system primarily benefited from the strong retrieval pipeline and the general capabilities of the underlying Qwen model.

The RAFT model exhibited:

* Stronger retrieval dependence.
* More structured reasoning behavior.
* Better handling of ATT&CK relationship analysis.
* Greater tendency to ground responses in retrieved evidence.

The performance reduction appears largely attributable to generation-format inconsistencies and repetition artifacts rather than widespread analytical failures.

---

## Implications for Adversarial Security Research

From a security research perspective, the RAFT model remains highly valuable despite the lower benchmark score.

Because the model is strongly conditioned to trust and reason over retrieved context, it provides an effective platform for studying:

* Retrieval poisoning attacks
* Context injection attacks
* ATT&CK knowledge corruption
* RAG-specific adversarial behaviors
* Trust calibration failures in retrieval systems

These characteristics align closely with the objectives of the Qwen-ATLAS project, which focuses on the security properties of retrieval-augmented threat intelligence systems rather than maximizing standalone benchmark performance.

---

## Conclusion

The Qwen-ATLAS RAFT Adapter with ATT&CK RAG achieved:

**59 / 80 (73.75%)**

on the evaluation benchmark.

Although the model did not surpass the baseline RAG configuration in overall accuracy, it demonstrated strong retrieval grounding, structured analytical reasoning, and excellent performance on ATT&CK relationship-analysis tasks.

The evaluation suggests that the fine-tuning process successfully shifted the model toward retrieval-dependent reasoning, making it a suitable platform for the next phase of the project: adversarial evaluation, retrieval poisoning research, and red-team security testing of RAG systems.
