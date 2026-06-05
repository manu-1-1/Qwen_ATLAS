# Qwen-ATLAS Model Pipeline

## Overview

Qwen-ATLAS is an AI-powered threat intelligence assistant designed to answer cybersecurity and MITRE ATT&CK-related questions using Retrieval-Augmented Generation (RAG).

The Model Pipeline is responsible for:

* Query routing
* ATT&CK knowledge retrieval
* Context construction
* Large Language Model (LLM) inference
* Fine-tuning infrastructure
* Evaluation and benchmarking

The objective is to combine a general-purpose language model with structured ATT&CK knowledge to produce grounded and explainable threat intelligence responses.

---

# Architecture

```text
User Query
     │
     ▼
Query Router
     │
     ├── Technique ID Lookup
     ├── Group Lookup
     └── Semantic Search
     │
     ▼
ChromaDB Retriever
     │
     ▼
Context Builder
     │
     ▼
Qwen Model
     │
     ▼
Threat Intelligence Response
```

---

# Retrieval Layer

The retrieval layer provides ATT&CK knowledge to the language model.

## Data Source

The knowledge base originates from:

* MITRE ATT&CK Enterprise Dataset
* STIX 2.1 ATT&CK objects

Processed ATT&CK entities include:

* Techniques
* Groups
* Mitigations

---

## ChromaDB

ATT&CK entities are embedded and stored in ChromaDB.

Embedding model:

```text
sentence-transformers/all-MiniLM-L6-v2
```

Stored collections contain:

* ATT&CK technique descriptions
* ATT&CK group descriptions
* ATT&CK mitigation descriptions

The vector database serves as the primary retrieval backend for RAG operations.

---

# Query Routing

One of the major improvements introduced during baseline development was ATT&CK-aware routing.

Instead of treating every query as a semantic search request, the system first attempts to identify the query type.

---

## Technique ID Lookup

Examples:

```text
What is T1003?
Explain T1055
```

Router action:

```text
Technique ID detected
        ↓
Direct ATT&CK lookup
```

This avoids semantic-search failures for ATT&CK identifiers.

---

## Group Lookup

Examples:

```text
What is APT29?
What techniques does APT29 use?
```

Router action:

```text
Threat Group detected
        ↓
Relationship traversal
```

The system retrieves techniques associated with the specified ATT&CK group.

---

## Semantic Search

Examples:

```text
Explain Process Injection
How can defenders mitigate credential dumping?
```

Router action:

```text
Embedding search
        ↓
Top-k retrieval
```

Used when no explicit ATT&CK identifier is detected.

---

# Group Technique Re-Ranking

A group such as APT29 may have hundreds of associated ATT&CK techniques.

Returning the first N techniques produces low-quality results.

To improve retrieval quality:

```text
Group
   ↓
Retrieve candidate techniques
   ↓
Embed query
   ↓
Similarity ranking
   ↓
Top-k techniques
```

This produces context more relevant to the user's specific question.

Example:

```text
What credential access techniques does APT29 use?
```

will prioritize credential-related techniques over unrelated APT29 techniques.

---

# Context Construction

Retrieved ATT&CK objects are converted into a textual context block.

Example:

```text
Technique: OS Credential Dumping (T1003)

Tactics: credential-access

Description:
Adversaries may attempt to dump credentials...
```

Multiple retrieved documents are concatenated into a context window supplied to the language model.

---

# Language Model

Current validation model:

```text
Qwen/Qwen2.5-0.5B-Instruct
```

Planned baseline model:

```text
Qwen/Qwen2.5-7B-Instruct
```

The language model receives:

1. System instructions
2. Retrieved ATT&CK context
3. User query

The model generates a grounded response using the supplied context.

---

# Prompt Format

The system uses Qwen's chat template.

Conceptually:

```text
System:
You are a cybersecurity threat intelligence assistant.

User:
ATT&CK Context:
...

Question:
...

A:
```

Using the native chat template reduces prompt echoing and improves instruction-following behavior.

---

# Baseline Evaluation

The initial validation phase used Qwen 2.5 0.5B Instruct.

Purpose:

* Verify end-to-end pipeline functionality
* Validate retrieval quality
* Establish a baseline before 7B evaluation

Evaluation categories include:

* ATT&CK identifier recognition
* Threat group knowledge
* Technique explanation
* Mitigation guidance
* ATT&CK reasoning tasks

Results are documented separately in:

```text
docs/evaluation_0.5B.md
```

---

# Planned Fine-Tuning

After the 7B baseline is established, the project will proceed to LoRA fine-tuning.

Objectives:

* Improve ATT&CK terminology usage
* Improve threat-intelligence style responses
* Improve response structure
* Improve context utilization

Fine-tuning is not intended to replace RAG.

The ATT&CK knowledge base remains external and is retrieved dynamically through ChromaDB.

---

# Planned Adversarial Evaluation

After baseline and fine-tuning evaluation, the Security Architect phase will begin.

Areas of investigation include:

* Data poisoning
* Retrieval poisoning
* Prompt injection
* Hallucination analysis
* Adversarial prompting
* Robustness testing

The objective is to evaluate how resilient the RAG pipeline remains under malicious inputs and manipulated knowledge sources.

---

# Current Status

Completed:

* ATT&CK ingestion
* ChromaDB integration
* Semantic retrieval
* ATT&CK-aware query routing
* Group relationship lookup
* Embedding re-ranking
* End-to-end RAG inference
* Initial 0.5B evaluation

In Progress:

* 7B baseline evaluation

Planned:

* LoRA fine-tuning
* Adversarial evaluation
* Poisoning experiments
* Final benchmarking
