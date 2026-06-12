# Qwen-ATLAS RAFT Adapter Evaluation (Without RAG)

## Overview

This evaluation measures the performance of the fine-tuned **Qwen-ATLAS RAFT Adapter** on the MITRE ATT&CK benchmark when **Retrieval-Augmented Generation (RAG) is disabled**.

The objective of this experiment is to evaluate how the model behaves when deprived of the retrieval context it was trained to consume. Because the RAFT training process conditioned the model on structured ATT&CK context blocks and retrieval-driven reasoning patterns, this benchmark serves as a control experiment to measure the model's dependence on the retrieval pipeline.

---

## Evaluation Configuration

| Parameter        | Value                               |
| ---------------- | ----------------------------------- |
| Model            | Qwen 2.5 7B Instruct + RAFT Adapter |
| Retrieval        | Disabled                            |
| Fine-Tuning      | QLoRA (RAFT)                        |
| Knowledge Source | None (No Retrieved Context)         |
| Total Queries    | 40                                  |
| Scoring Rubric   | v2                                  |
| Maximum Score    | 80                                  |

---

## Overall Results

| Metric      | Value   |
| ----------- | ------- |
| Total Score | 12 / 80 |
| Accuracy    | 15.00%  |

**Note:** The score of 12 reflects partial credit awarded for generic cybersecurity concepts generated before the model entered repetitive generation patterns or produced ATT&CK-specific hallucinations.

---

## Category Breakdown

| Category                 | Score  |
| ------------------------ | ------ |
| Technique ID Lookup      | 1 / 10 |
| Technique Name Lookup    | 5 / 10 |
| Group Information        | 2 / 10 |
| Group → Techniques       | 0 / 8  |
| Technique → Groups       | 0 / 10 |
| Mitigation Lookup        | 0 / 10 |
| Tactic-Filtered Queries  | 0 / 10 |
| Analyst Semantic Queries | 4 / 12 |

---

## Observations

### Strengths

A small number of analyst-oriented queries still produced partially correct cybersecurity concepts. These responses demonstrate that the underlying base model retains general cybersecurity knowledge.

However, ATT&CK-specific performance was severely degraded in the absence of retrieval context.

---

### Weaknesses

#### 1. Severe Distribution Shift

The model was trained using retrieval-augmented prompts containing structured ATT&CK context. When that context was removed during evaluation, performance degraded substantially.

This indicates that the fine-tuned model has become highly dependent on the retrieval format it was trained to consume.

---

#### 2. Repetitive Generation Loops

Many responses entered repetitive generation patterns and continued producing the same phrase until reaching the maximum token limit.

Examples included:

* Repeated Windows Command Shell descriptions.
* Repeated registry-related citations.
* Repeated ATT&CK identifiers and mitigation references.

These behaviors are consistent with known generation stability issues in low-rank, low-bit quantized fine-tuning environments.

---

#### 3. ATT&CK Identifier Hallucinations

Without retrieved context, the model frequently failed to correctly map ATT&CK identifiers to their associated techniques.

Examples observed:

| Query     | Expected                         | Generated                         |
| --------- | -------------------------------- | --------------------------------- |
| T1003     | OS Credential Dumping            | Environment Variable Modification |
| T1055     | Process Injection                | Credential-Related Activity       |
| T1195.002 | Compromise Software Supply Chain | Encrypt/Obfuscate Data            |

These failures demonstrate that the fine-tuned model no longer performs reliable ATT&CK retrieval from internal memory alone.

---

#### 4. Failure to Produce Retrieval-Oriented Reasoning Structure

The model rarely produced the structured reasoning behavior observed during retrieval-enabled evaluation.

This suggests that the reasoning patterns learned during RAFT training are strongly tied to the presence of retrieved ATT&CK context.

---

## Key Finding

The most significant result of this experiment is the model's strong dependence on retrieval.

Unlike the baseline Qwen 2.5 7B model, which could still generate moderately accurate ATT&CK-related answers from internal knowledge alone, the RAFT-adapted model performed poorly without contextual grounding.

This behavior suggests that the fine-tuning process successfully conditioned the model to rely on external ATT&CK evidence rather than attempting unsupported ATT&CK-specific completions from latent memory.

---

## Comparative Results

| Model                         | Score   | Accuracy |
| ----------------------------- | ------- | -------- |
| Base Qwen 2.5 7B (No RAG)     | 35 / 80 | 43.75%   |
| Qwen-ATLAS RAFT (No RAG)      | 12 / 80 | 15.00%   |
| Base Qwen 2.5 7B + ATT&CK RAG | 67 / 80 | 83.75%   |

---

## Interpretation

The results indicate that the RAFT adapter did not create a stronger standalone ATT&CK model.

Instead, it transformed the model into a retrieval-conditioned reasoning system whose performance depends heavily on access to relevant ATT&CK context.

This behavior is consistent with the goals of Retrieval-Augmented Fine-Tuning (RAFT), where the objective is not necessarily to improve closed-book performance, but to improve the model's ability to consume, reason over, and respond using retrieved evidence.

---

## Conclusion

The Qwen-ATLAS RAFT Adapter achieved:

**12 / 80 (15.00%)**

when evaluated without retrieval support.

The evaluation demonstrates that the model is highly dependent on the retrieval pipeline and suffers significant performance degradation when ATT&CK context is unavailable. While standalone ATT&CK recall decreased substantially compared to the base model, the experiment confirms that the fine-tuned model has become retrieval-oriented rather than memory-oriented.

This establishes the necessity of evaluating the model within its intended deployment configuration: **RAFT + Retrieval-Augmented Generation (RAG)**.
