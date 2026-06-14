# Technical Documentation: Vectorless RAG v3 & Local Ollama Benchmarking

This document provides a highly detailed explanation of the architecture, engineering decisions, and implementation details of **Vectorless RAG v3** and the **Ollama-based Vector RAG** (`chroma_rag_ollama.py`) comparison system.

---

## 1. The Problems Addressed

### Problem A: Decoupled Intent-Entity Routing (Vectorless RAG v2 Limitation)
In Vectorless RAG v2, query intent detection and entity resolution were decoupled. When a query passed the intent detection check (Check 3: Mitigation/Prevent), it expected a technique ID or name to be present in the query text. If it failed to resolve the entity inside the handler, the system returned nothing or incorrectly fell through to subsequent checks.

Furthermore, **Check 1: Group/Actor Name Resolution** was placed at the very top of the routing pipeline. Because of this, any query containing a threat group name was prematurely hijacked by the Group router, even if the primary intent was different.
*   **Example Query:** *"How do I prevent that credential theft technique used by APT29?"*
*   **V2 Behavior:** The query contained the word `"APT29"`, matching Check 1. The system immediately bypassed Check 3 (Mitigation) and returned the techniques associated with APT29, completely failing to answer the user's question about **preventing** the technique.

### Problem B: Unfair Vector RAG Baseline (SentenceTransformers Bias)
In previous reports, **Vector RAG** (ChromaDB) loaded the SentenceTransformers model in Python, which forced imports of `torch` (PyTorch) and `sentence_transformers`. This inflated the Vector RAG metrics:
*   **Initialization Time:** ~46.0 seconds (very heavy Python process load).
*   **Memory Growth on Load:** ~480 MB.

To make the comparison valid, we needed a Vector RAG client that offloaded the embedding compilation step to the same local Ollama server used by the Vectorless RAG.

---

## 2. The Solutions Implemented

### Solution 1: Coupled Intent-Entity Routing (Vectorless RAG v3)
In **Vectorless RAG v3**, the routing pipeline in [vectorless_rag/v3/mitre_tree.py](file:///d:/Projects/Qwen_ATLAS/vectorless_rag/v3/mitre_tree.py) was completely restructured:
1.  **Reordered Routing Pipeline:** The Group name matching check was moved down below specific intent-based queries (Mitigations and Technique-to-Groups).
2.  **Intent-Coupled Fallback Routing:** If a query matches the mitigation intent (e.g. contains `"prevent"`, `"mitigate"`), but no technique name/ID can be extracted deterministically, the system invokes **Tier 2 LLM Node Selection**. Llama 3.1 8B semantically identifies the technique ID (e.g., `T1003` or `T1552.002`), and then the router fetches the associated mitigations for that resolved technique, returning them as context.

### Solution 2: Ollama-based Vector RAG (`chroma_rag_ollama.py`)
We built a clean Vector RAG implementation ([chroma_rag_ollama.py](file:///d:/Projects/Qwen_ATLAS/chroma_rag_ollama.py)) that:
1.  Replaces local `SentenceTransformer` imports with native `urllib` queries to Ollama's `/api/embed` endpoint using the `nomic-embed-text` model.
2.  Offloads all vector math and embedding compiling to the local Ollama service.
3.  Performs automatic database ingestion of 768-dimensional embeddings into a new ChromaDB collection `attck_objects_ollama` if it is empty.

---

## 3. Codes Written and Detailed Explanations

Below are the complete implementations of the three key components developed for v3.

### 1. Vectorless RAG v3 Traversal Engine (`mitre_tree.py`)
This file constructs the ATT&CK tree in memory and implements the new coupled intent-fallback routing structure.

*   **File Path:** [vectorless_rag/v3/mitre_tree.py](file:///d:/Projects/Qwen_ATLAS/vectorless_rag/v3/mitre_tree.py)
*   **How it works:**
    *   `_build()` loads tactics, techniques, aliases, and mitigations from `enterprise-attack.json` and `index_mappings.json` into nested dictionary indices.
    *   `resolve_tech_id()` checks queries for exact technique IDs (using regex `T\d{4}`) or exact technique names.
    *   `context_for_query()` executes the new coupled intent router:
        1.  **Technique to Groups Lookup:** Checked first. If `"which groups|who uses"` matches but no technique ID is found in the query, it triggers LLM Node Selection to find the technique, then returns the groups associated with it.
        2.  **Mitigation Lookup:** Checked second. If `"prevent|mitigate"` matches but no technique ID is found in the query, it triggers LLM Node Selection to find the technique, then returns the mitigations associated with it.
        3.  **Exact ID/Name Lookup:** Checked third to retrieve technique details directly.
        4.  **Group Lookup:** Checked fourth. If a threat group matches, it returns group info or relationships.
        5.  **Semantic Search Fallback:** If none of the routing checks match, it falls back to a full semantic search.

```python
# Unified context_for_query from vectorless_rag/v3/mitre_tree.py
def context_for_query(self, query: str, top_k: int = 5) -> str:
    query_lower = query.lower()

    # Helper to resolve technique ID/Name deterministically
    def resolve_tech_id(q: str) -> Optional[str]:
        match = re.search(r"T\d{4}(?:\.\d{3})?", q)
        if match:
            return match.group().upper()
        for name, tech_id in sorted(self.technique_name_to_id.items(), key=lambda x: len(x[0]), reverse=True):
            if re.search(rf"\b{re.escape(name)}\b", q.lower()):
                return tech_id
        return None

    # ── 1. Technique to Groups Lookup ────────────
    is_tech_to_groups = bool(re.search(r"(which groups|who uses|actors using|groups associated)", query_lower))
    if is_tech_to_groups:
        tid = resolve_tech_id(query)
        if tid:
            groups = self.tech_to_groups.get(tid, [])
            if groups:
                group_lines = [f"- {g}" for g in groups]
                return f"Technique: {tid}\n\nATT&CK groups associated with {tid}:\n" + "\n".join(group_lines)
        else:
            print(f"[Router] Fallback to Tier 2 for group relationship resolving: {query}")
            candidates = self.get_candidate_nodes(query, top_n=25)
            selected_scores = self.select_nodes(query, candidates)
            resolved_tids = [item.get("id") for item in selected_scores if item.get("score", 0) >= 4]
            if not resolved_tids and candidates:
                resolved_tids = [candidates[0]["id"]]
            if resolved_tids:
                tid = resolved_tids[0]
                groups = self.tech_to_groups.get(tid, [])
                if groups:
                    group_lines = [f"- {g}" for g in groups]
                    return f"Technique: {tid}\n\nATT&CK groups associated with {tid}:\n" + "\n".join(group_lines)

    # ── 2. Mitigation Lookup ────────────────────
    is_mitigation = bool(re.search(r"(mitigate|mitigation|prevent|defend|protect)", query_lower))
    if is_mitigation:
        tid = resolve_tech_id(query)
        if tid:
            mit_ids = self.tech_to_mitigations.get(tid, [])
            if mit_ids:
                mitigation_lines = []
                for mid in mit_ids:
                    mit_info = self.mitigations.get(mid)
                    if mit_info:
                        mitigation_lines.append(f"- {mit_info['name']} ({mid}): {mit_info['description'][:200]}...")
                return f"Technique: {tid}\n\nAssociated mitigations:\n" + "\n".join(sorted(mitigation_lines))
        else:
            print(f"[Router] Fallback to Tier 2 for mitigation resolving: {query}")
            candidates = self.get_candidate_nodes(query, top_n=25)
            selected_scores = self.select_nodes(query, candidates)
            resolved_tids = [item.get("id") for item in selected_scores if item.get("score", 0) >= 4]
            if not resolved_tids and candidates:
                resolved_tids = [candidates[0]["id"]]
            if resolved_tids:
                tid = resolved_tids[0]
                mit_ids = self.tech_to_mitigations.get(tid, [])
                if mit_ids:
                    mitigation_lines = []
                    for mid in mit_ids:
                        mit_info = self.mitigations.get(mid)
                        if mit_info:
                            mitigation_lines.append(f"- {mit_info['name']} ({mid}): {mit_info['description'][:200]}...")
                    return f"Technique: {tid}\n\nAssociated mitigations:\n" + "\n".join(sorted(mitigation_lines))

    # ── 3. Exact ID / Name Lookup ────────────────
    tid = resolve_tech_id(query)
    if tid:
        node = self.get_by_id(tid)
        if node:
            return f"[{node.id}] {node.name}\n\nDescription: {node.description}\n\nDetection: {node.detection}"

    # ── 4. Resolve Group / Actor Name ────────
    matched_group = None
    for group_name in self.groups.keys():
        if re.search(rf"\b{re.escape(group_name)}\b", query_lower):
            matched_group = self.alias_to_group[group_name]
            break
    if not matched_group:
        for alias in sorted(self.alias_to_group.keys(), key=len, reverse=True):
            if re.search(rf"\b{re.escape(alias)}\b", query_lower):
                matched_group = self.alias_to_group[alias]
                break

    if matched_group:
        is_info_query = re.search(r"(what is|who is|explain)", query_lower) or query_lower.strip() in [matched_group.lower(), group_name.lower()]
        group_info = self.groups.get(matched_group.lower(), {})
        desc = group_info.get("description", "No description available.")
        if is_info_query:
            aliases_str = ", ".join(group_info.get("aliases", []))
            return f"Group: {group_info.get('name')} ({group_info.get('id', 'N/A')})\nAliases: {aliases_str}\nDescription: {desc}"
        else:
            tech_ids = self.group_to_techs.get(matched_group, [])
            tech_names = [f"- {self.get_by_id(tid).name} ({tid})" for tid in tech_ids[:15] if self.get_by_id(tid)]
            relationship_text = f"Group: {matched_group}\n\nTechniques associated with {matched_group}:\n" + "\n".join(tech_names)
            detail_blocks = [relationship_text]
            for tid in tech_ids[:5]:
                tnode = self.get_by_id(tid)
                if tnode:
                    detail_blocks.append(f"[{tnode.id}] {tnode.name}\nDescription: {tnode.description[:1000]}...\nDetection: {tnode.detection[:400]}")
            return "\n\n---\n\n".join(detail_blocks)

    # ── 5. Semantic LLM-Based Retrieval ──────────
    candidates = self.get_candidate_nodes(query, top_n=25)
    selected_scores = self.select_nodes(query, candidates)
    ...
```

---

### 2. Ollama-based Vector RAG (`chroma_rag_ollama.py`)
This file is the new database client that integrates with local Ollama embeddings for comparison.

*   **File Path:** [chroma_rag_ollama.py](file:///d:/Projects/Qwen_ATLAS/chroma_rag_ollama.py)
*   **How it works:**
    *   Queries `http://localhost:11434/api/embed` with model `"nomic-embed-text"` to construct document and query embedding vectors.
    *   Initializes a connection to ChromaDB collection `attck_objects_ollama`.
    *   If the database is unpopulated (`count() == 0`), it automatically calls `ingest_techniques()`, `ingest_groups()`, and `ingest_mitigations()` to compile and populate the index.
    *   Exposes identical retrieval interfaces (`retrieve` and `smart_retrieve`) to the main application for hot-swappability.

```python
# API Ingestion & Retrieval from chroma_rag_ollama.py
def get_ollama_embeddings(texts: list) -> list:
    if not texts:
        return []
    data = {
        "model": EMBED_MODEL_NAME,
        "input": texts
    }
    req = urllib.request.Request(
        "http://localhost:11434/api/embed",
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            return res_data.get("embeddings", [])
    except Exception as e:
        print(f"Error querying Ollama embeddings: {e}")
        return [[0.0] * 768 for _ in texts]

def _batch_upsert(docs, metas, ids, batch=50):
    for i in range(0, len(docs), batch):
        b_docs = docs[i:i+batch]
        b_metas = metas[i:i+batch]
        b_ids = ids[i:i+batch]
        embeddings = get_ollama_embeddings(b_docs)
        col.upsert(
            documents=b_docs,
            embeddings=embeddings,
            metadatas=b_metas,
            ids=b_ids,
        )
```

---

### 3. Comparison Benchmarking Suite (`benchmark_rag.py`)
Executes the standardized suite of 41 queries across all 4 RAG setups.

*   **File Path:** [vectorless_rag/v3/benchmark_rag.py](file:///d:/Projects/Qwen_ATLAS/vectorless_rag/v3/benchmark_rag.py)
*   **How it works:**
    *   Loads all 4 engines: `vector_st` (SentenceTransformers), `vector_ollama` (Ollama), `vectorless_v2`, and `vectorless_v3`.
    *   Executes 41 benchmark queries.
    *   Tracks retrieval success (recall) based on expected keywords, latency (in ms), process memory growth (in MB), and context lengths.
    *   Writes a final comparative markdown report to `vectorless_rag/v3/rag_comparison_results.md`.

---

## 4. Benchmark Findings & Analysis

The generated benchmark report ([rag_comparison_results.md](file:///d:/Projects/Qwen_ATLAS/vectorless_rag/v3/rag_comparison_results.md)) shows:

### 1. Coupled Fallback Routing Success
In Vectorless RAG v3, the decoupled routing limitation was successfully resolved. For query **I1** (*'How do I prevent that credential theft technique used by APT29?'*):
*   **Vectorless RAG v2** matched the group `APT29` and returned techniques used by APT29, failing to return mitigations.
*   **Vectorless RAG v3** matched the mitigation intent (`prevent`), fell back to Tier 2 LLM selection, successfully resolved the technique to `T1552.002` (Credentials in Registry), and retrieved its associated mitigations:
    ```
    [Router] Fallback to Tier 2 for mitigation resolving: How do I prevent that credential theft technique used by APT29?
    Technique: T1552.002
    Associated mitigations:
    - Audit (M1047): ...
    - Password Policies (M1027): ...
    ```
This allows Vectorless RAG v3 to achieve a near-perfect recall rate of **97.6% (40/41)**.

### 2. Startup & Memory Efficiency (Apples-to-Apples Vector RAG comparison)
By running Vector RAG via local Ollama embeddings (`nomic-embed-text`), we stripped out the heavyweight PyTorch client loading costs. This resulted in:
*   **Initialization Time:** Chroma (Ollama) initializes in **6.6s** (instead of **46s** for ST).
*   **Memory Growth on Load:** Chroma (Ollama) consumes **244.4 MB** (instead of **477.7 MB** for ST).
*   **Vectorless Advantage:** Vectorless RAG v3 is still significantly faster to load (**0.20s**) and uses virtually no RAM (**8.4 MB**), proving the architecture remains highly superior for resource-constrained edge deployments.

### 3. Recall Drop in Ollama Embeddings
Interestingly, the retrieval accuracy of Vector RAG (Ollama) dropped to **78.0% (32/41)** because `nomic-embed-text` failed to recall complex group relationship queries (e.g. `D1`, `D4`, `G1-G5`). In contrast, Vectorless RAG v3 maintains **97.6%** accuracy by relying on its deterministic, tree-traversed hierarchy.
