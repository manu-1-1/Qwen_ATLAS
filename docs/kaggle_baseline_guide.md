# Kaggle Baseline Setup Guide

## Overview

This document describes how to run the Qwen-ATLAS baseline evaluation notebook on Kaggle using GPU acceleration.

The baseline consists of:

* Qwen 2.5 7B Instruct
* ATT&CK knowledge retrieval using ChromaDB
* Baseline evaluation queries comparing:

  * Plain model responses
  * RAG-enhanced responses

---

## Prerequisites

### Kaggle Account

Create a Kaggle account and verify the account if GPU access is unavailable.

### GPU Selection

Recommended:

* 2 × Tesla T4

Alternative:

* Tesla P100

The notebook was developed and tested using dual T4 GPUs.

---

## Dataset Preparation

Upload the project dataset to Kaggle.

Required files include:

```text
enterprise-attack.json
index_mappings.json
chroma_rag.py
```

Additional project files may be included as needed.

After upload, attach the dataset to the notebook through:

```text
Add Input
→ Select Dataset
→ Attach Dataset
```

---

## Environment Setup

Install required dependencies:

```bash
pip install chromadb==1.5.9
pip install sentence-transformers
pip install mitreattack-python
pip install transformers
pip install accelerate
```

If the Kaggle environment is restarted, dependencies must be reinstalled.

---

## Running the Notebook

Execute notebook cells sequentially:

### 1. Environment Setup

Installs dependencies and copies required ATT&CK data files into the working directory.

### 2. Retriever Initialization

Loads:

* ATT&CK data
* ChromaDB
* Retrieval mappings

### 3. ChromaDB Ingestion

Builds the local ATT&CK retrieval database.

Expected output:

```text
Collection Count: 900+
```

### 4. Model Loading

Loads:

```text
Qwen/Qwen2.5-7B-Instruct
```

Expected output:

```text
Model Loaded
```

### 5. Inference Functions

Creates:

```python
plain_inference()
rag_inference()
```

These functions are used throughout evaluation.

---

## Evaluation Queries

The notebook contains a predefined evaluation set covering:

* ATT&CK techniques
* ATT&CK groups
* ATT&CK relationships
* Platform information
* Credential access techniques

Examples:

```text
What is T1003?
What techniques does APT29 use?
Which groups use T1003?
What credential access techniques does APT29 use?
```

---

## Running Evaluation

The notebook executes each query twice:

### Plain Mode

```text
User Query
↓
Qwen 7B
↓
Answer
```

### RAG Mode

```text
User Query
↓
Retriever
↓
ATT&CK Context
↓
Qwen 7B
↓
Answer
```

Results are stored for comparison and documentation.

---

## Common Issues

### Session Restart

Symptoms:

```text
ModuleNotFoundError
NameError
```

Resolution:

Re-run all notebook cells from the beginning.

---

### Missing ChromaDB

Symptoms:

```text
No module named 'chromadb'
```

Resolution:

Reinstall dependencies and restart execution from the setup section.

---

### Missing ATT&CK Files

Symptoms:

```text
FileNotFoundError:
enterprise-attack.json
```

Resolution:

Verify that ATT&CK files are present in the attached Kaggle dataset and copied into the notebook working directory.

---

### GPU Not Available

Check:

```python
import torch
print(torch.cuda.is_available())
print(torch.cuda.device_count())
```

Expected:

```text
True
2
```

for dual T4 execution.

---

## Expected Outcomes

The baseline evaluation should demonstrate:

* Improved ATT&CK factual accuracy using RAG
* Improved ATT&CK relationship retrieval
* Reduced ATT&CK-specific hallucinations
* Stronger grounding compared to plain model responses

The resulting outputs are documented in:

```text
docs/evaluation_7B.md
```

and serve as the baseline for future LoRA fine-tuning and security evaluation efforts.
