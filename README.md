# Qwen-ATLAS

**AI-Powered Threat Intelligence Agent**

Qwen-ATLAS is a specialized Threat Intelligence Q&A agent currently designed to interact with the MITRE ATT&CK framework. *Note: Although the model has thus far been trained primarily on ATT&CK data, the project is named **ATLAS** because integrating the MITRE ATLAS (Adversarial Threat Landscape for AI Systems) framework is a core upcoming goal.*

It demonstrates how to build a highly optimized, resource-light threat intelligence agent by replacing heavy vector databases with deterministic graph-traversal logic for structured queries, falling back to a local LLM for complex semantic reasoning.

## Architecture

The project explores two primary architectures:
1. **Vector RAG (ChromaDB)**: The traditional approach using dense embeddings to retrieve threat intelligence data.
2. **Vectorless RAG v2**: A highly resource-efficient in-memory traversal tree that uses direct deterministic routing for structured queries (e.g., specific Technique IDs or Threat Actors) and falls back to dynamic node selection using a local LLM (`llama3.1:8b` via Ollama) for unstructured queries. This approach yields a 70x faster initialization time and saves over 500MB of RAM without sacrificing retrieval accuracy.

## Evaluation & RAFT

The agent leverages **Retrieval-Augmented Fine-Tuning (RAFT)** on the **Qwen 2.5 7B Instruct** model. Through rigorous evaluation, the RAFT-adapted model was successfully conditioned to rely almost entirely on retrieved ATT&CK context rather than internal parametric memory. This creates an agent with strong multi-hop relationship reasoning and excellent retrieval grounding.

## Next Goals

With the agent now successfully conditioned to trust and reason over retrieved context, the next phase of the Qwen-ATLAS project focuses on expanding its threat intelligence scope and conducting **Adversarial Security Research**, specifically:

- **MITRE ATLAS Integration**: Expanding the retrieval systems and datasets to include the MITRE ATLAS framework, allowing the agent to reason over adversarial attacks targeting AI and machine learning systems.

- **Model / Retrieval Poisoning Attacks**: Investigating how malicious or manipulated threat intelligence documents injected into the RAG pipeline can compromise the model's output.
- **Context Injection**: Studying RAG-specific adversarial behaviors and trust calibration failures.
- **Red-Team Security Testing**: Evaluating the resilience of retrieval-augmented threat intelligence systems against active exploitation.
