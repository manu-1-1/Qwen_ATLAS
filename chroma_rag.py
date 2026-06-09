import chromadb
import numpy as np
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
from mitreattack.stix20 import MitreAttackData
import json, re
from collections import defaultdict

attack  = MitreAttackData("enterprise-attack.json")
embedder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

client = chromadb.PersistentClient(path="./chroma_attackdb")
col    = client.get_or_create_collection("attck_objects",
             metadata={"hnsw:space": "cosine"})

with open("index_mappings.json") as f:
    mappings = json.load(f)

tech_to_groups  = mappings["tech_to_groups"]
tactic_to_techs = mappings["tactic_to_techs"]
mit_to_techs    = mappings["mit_to_techs"]

group_to_techs = defaultdict(list)

for tech, groups in tech_to_groups.items():
    for group in groups:
        group_to_techs[group].append(tech)

def safe_text(val):
    return val if isinstance(val, str) else ""

def get_ext_id(obj):
    try: return obj.external_references[0].external_id
    except: return obj.id

# --- Startup indexes ---------------------------------------------------

# Fix 1: Technique name → ID (for "What is Process Injection?" style queries)
technique_name_to_id = {}
for _t in attack.get_techniques(remove_revoked_deprecated=True):
    technique_name_to_id[_t.name.lower()] = get_ext_id(_t)

# Fix 2: Alias → canonical group name (for "Cozy Bear", "The Dukes" etc.)
alias_to_group = {}
for _g in attack.get_groups(remove_revoked_deprecated=True):
    alias_to_group[_g.name.lower()] = _g.name
    for _alias in (_g.aliases or []):
        alias_to_group[_alias.lower()] = _g.name

group_name_to_id = {}
for g in attack.get_groups(remove_revoked_deprecated=True):
    gid = get_ext_id(g)

    group_name_to_id[g.name.lower()] = gid

    for alias in (g.aliases or []):
        group_name_to_id[alias.lower()] = gid

# Fix 3: Reverse mitigation index (tid → [mid, ...]) built once at startup
tech_to_mitigations = defaultdict(list)
for _mid, _techs in mit_to_techs.items():
    for _tid in _techs:
        tech_to_mitigations[_tid].append(_mid)

# -----------------------------------------------------------------------

TACTIC_KEYWORDS = {
    "credential access": "credential-access",
    "persistence": "persistence",
    "execution": "execution",
    "collection": "collection",
    "lateral movement": "lateral-movement",
    "defense evasion": "defense-evasion",
    "privilege escalation": "privilege-escalation",
    "discovery": "discovery",
}

def ingest_techniques():
    docs, metas, ids = [], [], []
    for t in attack.get_techniques(remove_revoked_deprecated=True):
        tid = get_ext_id(t)
        tactics   = [p.phase_name for p in (t.kill_chain_phases or [])]
        platforms = list(t.x_mitre_platforms or [])
        text = (f"Technique: {t.name} ({tid})\n"
                f"Tactics: {', '.join(tactics)}\n"
                f"Platforms: {', '.join(platforms)}\n"
                f"Description: {safe_text(t.description)[:800]}\n"
                f"Detection: {safe_text(getattr(t,'x_mitre_detection',''))[:400]}")
        docs.append(text);  ids.append(tid)
        metas.append({
            "object_type": "technique",
            "technique_id": tid,
            "name": t.name,
            "tactic": tactics[0] if tactics else "unknown",
            "tactics_all": json.dumps(tactics),
            "platform": platforms[0] if platforms else "unknown",
            "platforms_all": json.dumps(platforms),
        })
    _batch_upsert(docs, metas, ids)
    print(f"Ingested {len(docs)} techniques")

def ingest_groups():
    docs, metas, ids = [], [], []
    for g in attack.get_groups(remove_revoked_deprecated=True):
        gid = get_ext_id(g)
        aliases = list(g.aliases or [])
        used    = [t["object"].name for t in attack.get_techniques_used_by_group(g.id)]
        text = (f"Group: {g.name} ({gid})\n"
                f"Aliases: {', '.join(aliases)}\n"
                f"Description: {safe_text(g.description)[:600]}\n"
                f"Associated techniques: {', '.join(used[:20])}")
        docs.append(text);  ids.append(gid)
        metas.append({
            "object_type": "group",
            "technique_id": gid,
            "name": g.name,
            "tactic": "n/a",
            "platform": "n/a",
        })
    _batch_upsert(docs, metas, ids)
    print(f"Ingested {len(docs)} groups")

def ingest_mitigations():
    docs, metas, ids = [], [], []
    for m in attack.get_mitigations(remove_revoked_deprecated=True):
        mid = get_ext_id(m)
        text = (f"Mitigation: {m.name} ({mid})\n"
                f"Description: {safe_text(m.description)[:800]}")
        docs.append(text);  ids.append(mid)
        metas.append({
            "object_type": "mitigation",
            "technique_id": mid,
            "name": m.name,
            "tactic": "n/a",
            "platform": "n/a",
        })
    _batch_upsert(docs, metas, ids)
    print(f"Ingested {len(docs)} mitigations")

def _batch_upsert(docs, metas, ids, batch=200):
    embeddings = embedder.encode(docs, show_progress_bar=True).tolist()
    for i in range(0, len(docs), batch):
        col.upsert(
            documents=docs[i:i+batch],
            embeddings=embeddings[i:i+batch],
            metadatas=metas[i:i+batch],
            ids=ids[i:i+batch],
        )

if __name__ == "__main__":
    ingest_techniques()
    ingest_groups()
    ingest_mitigations()
    print("ChromaDB fully populated.")

def format_chroma_get(result):
    out = []
    for i, meta in enumerate(result["metadatas"]):
        out.append({
            **meta,
            "text": result["documents"][i],
            "score": 1.0
        })
    return out

def lookup_technique_id(query):
    match = re.search(r"T\d{4}(?:\.\d{3})?", query)
    if not match:
        return None
    tid = match.group()
    result = col.get(ids=[tid], include=["documents", "metadatas"])
    if not result["ids"]:
        return None
    return format_chroma_get(result)

def lookup_technique_name(query):
    """Match technique by name string (e.g. 'Process Injection', 'OS Credential Dumping')."""
    q = query.lower()
    # Sort by length descending so longer/more specific names match first
    for name in sorted(technique_name_to_id.keys(), key=len, reverse=True):
        if re.search(rf"\b{re.escape(name)}\b", q):
            tid = technique_name_to_id[name]
            result = col.get(ids=[tid], include=["documents", "metadatas"])
            if result["ids"]:
                return format_chroma_get(result)
    return None

def lookup_group(query, top_k=5):
    query_lower = query.lower()
    matched_group = None

    # Primary: exact canonical name match against index_mappings keys
    for group in group_to_techs.keys():
        if re.search(rf"\b{re.escape(group.lower())}\b", query_lower):
            matched_group = group
            break

    # Secondary: alias resolution (e.g. "Cozy Bear" → "APT29")
    if not matched_group:
        for alias in sorted(alias_to_group.keys(), key=len, reverse=True):
            if re.search(rf"\b{re.escape(alias)}\b", query_lower):
                matched_group = alias_to_group[alias]
                break

    # Tertiary fallback: ChromaDB group object search
    if not matched_group:
        q_vec = embedder.encode([query])[0].tolist()
        fallback = col.query(
            query_embeddings=[q_vec],
            n_results=top_k,
            where={"object_type": "group"},
            include=["documents", "metadatas", "distances"],
        )
        if fallback["ids"][0]:
            # Verify the top result is actually the queried group, not a
            # near-miss like APT3 when APT33 was requested
            top_name = fallback["metadatas"][0][0].get("name", "").lower()
            # Extract group name tokens from query for sanity check
            group_token = re.search(
                r"apt\d+|[a-z]+\s?bear|[a-z]+\s?panda|[a-z]+\s?tiger|"
                r"lazarus|kimsuky|sandworm|cozy\s?bear|fancy\s?bear",
                query_lower
            )
            if group_token and group_token.group().replace(" ", "") not in top_name.replace(" ", ""):
                # Top result name doesn't match query token — likely a near-miss
                print("[Router] Group semantic fallback (no confident match)")
                return None
            print("[Router] Group semantic fallback")
            out = []
            for i, meta in enumerate(fallback["metadatas"][0]):
                out.append({
                    **meta,
                    "text": fallback["documents"][0][i],
                    "score": 1 - fallback["distances"][0][i],
                })
            return out
        return None

    # Normal path: group found in index_mappings
    technique_ids = group_to_techs[matched_group]

    requested_tactic = None
    for phrase, tactic in TACTIC_KEYWORDS.items():
        if phrase in query_lower:
            requested_tactic = tactic
            break

    result = col.get(ids=technique_ids, include=["documents", "metadatas"])

    if requested_tactic:
        filtered_docs = []
        filtered_meta = []
        for doc, meta in zip(result["documents"], result["metadatas"]):
            tactics = json.loads(meta.get("tactics_all", "[]"))
            if requested_tactic in tactics:
                filtered_docs.append(doc)
                filtered_meta.append(meta)
        result = {
            "documents": filtered_docs,
            "metadatas": filtered_meta,
        }

    if not result["documents"]:
        return None

    # Detect pure enumeration queries
    is_enumeration = re.search(
        r"(what techniques|which techniques|ttp|uses|techniques used)",
        query_lower
    )
    if is_enumeration and requested_tactic is None:

        top_indices = list(
            range(min(15, len(result["documents"])))
        )
    else:

        query_vec = embedder.encode(query)

        doc_vecs = embedder.encode(
            result["documents"],
            show_progress_bar=False
        )

        scores = np.dot(doc_vecs, query_vec)

        top_indices = np.argsort(scores)[::-1][:top_k]

    reranked = {
        "documents": [result["documents"][i] for i in top_indices],
        "metadatas": [result["metadatas"][i] for i in top_indices],
    }

    technique_names = [
        f"- {meta['name']} ({meta['technique_id']})"
        for meta in reranked["metadatas"]
    ]

    group_summary = {
        "name": matched_group,
        "technique_id": matched_group,
        "object_type": "group_relationship",
        "text": (
            f"Group: {matched_group}\n\n"
            f"The following ATT&CK techniques are associated "
            f"with {matched_group}:\n\n"
            + "\n".join(technique_names)
        ),
        "score": 1.0,
    }

    return [group_summary] + format_chroma_get(reranked)

def lookup_groups_for_technique(query):
    match = re.search(r"T\d{4}(?:\.\d{3})?", query)
    if not match:
        return None
    tid = match.group()
    if tid not in tech_to_groups:
        return None
    groups = tech_to_groups[tid]
    group_lines = [f"- {g}" for g in groups]
    summary = {
        "name": tid,
        "technique_id": tid,
        "object_type": "technique_relationship",
        "score": 1.0,
        "text": (
            f"Technique: {tid}\n\n"
            f"The following ATT&CK groups are associated "
            f"with {tid}:\n\n"
            + "\n".join(group_lines)
        ),
    }
    return [summary]

def lookup_mitigation(query):
    match = re.search(r"T\d{4}(?:\.\d{3})?", query)

    if not match:
        return None

    tid = match.group()

    mitigation_ids = tech_to_mitigations.get(tid)

    if not mitigation_ids:
        return None

    result = col.get(
        ids=mitigation_ids,
        include=["documents", "metadatas"]
    )

    if not result["documents"]:
        return None

    mitigation_lines = []

    for meta in result["metadatas"]:
        mitigation_lines.append(
            f"- {meta['name']} ({meta['technique_id']})"
        )

    summary = {
        "name": tid,
        "technique_id": tid,
        "object_type": "mitigation_relationship",
        "score": 1.0,
        "text": (
            f"Technique: {tid}\n\n"
            f"Associated mitigations:\n\n"
            + "\n".join(sorted(mitigation_lines))
        )
    }

    return [summary]

def lookup_technique_semantic_name(query, top_k=1):
    q_vec = embedder.encode([query])[0].tolist()

    result = col.query(
        query_embeddings=[q_vec],
        n_results=top_k,
        where={"object_type": "technique"},
        include=["documents", "metadatas", "distances"],
    )

    if not result["ids"][0]:
        return None

    score = 1 - result["distances"][0][0]

    if score < 0.60:
        return None

    return [{
        **result["metadatas"][0][0],
        "text": result["documents"][0][0],
        "score": score,
    }]

def lookup_group_info(query):
    query_lower = query.lower()
    matched_group = None

    # Canonical group name match
    for group in group_to_techs.keys():
        if re.search(rf"\b{re.escape(group.lower())}\b", query_lower):
            matched_group = group
            break

    # Alias match
    if not matched_group:
        for alias in sorted(alias_to_group.keys(), key=len, reverse=True):
            if re.search(rf"\b{re.escape(alias)}\b", query_lower):
                matched_group = alias_to_group[alias]
                break

    if not matched_group:
        return None

    # Exact group ID lookup
    gid = group_name_to_id.get(matched_group.lower())

    if not gid:
        return None

    result = col.get(
        ids=[gid],
        include=["documents", "metadatas"]
    )

    if not result["ids"]:
        return None

    return format_chroma_get(result)


def smart_retrieve(query, top_k=5):
    if re.search(r"(which groups|what groups|who uses)", query.lower()):
        group_usage = lookup_groups_for_technique(query)
        if group_usage:
            print("[Router] Technique -> Group lookup")
            return group_usage

    if re.search(r"(mitigate|mitigation|prevent|defend|protect)", query.lower()):
        mitigation_result = lookup_mitigation(query)
        if mitigation_result:
            print("[Router] Mitigation lookup")
            return mitigation_result

    tech_result = lookup_technique_id(query)
    if tech_result:
        print("[Router] Technique ID lookup")
        return tech_result

    tech_name_result = lookup_technique_name(query)
    if tech_name_result:
        print("[Router] Technique name lookup")
        return tech_name_result

    tech_semantic = lookup_technique_semantic_name(query)
    if tech_semantic:
        print("[Router] Technique semantic lookup")
        return tech_semantic
    
    if re.search(
        r"(what is|who is|explain)",
        query.lower()
    ):
        group_info = lookup_group_info(query)
        if group_info:
            print("[Router] Group info lookup")
            return group_info

    group_result = lookup_group(query, top_k)
    if group_result:
        print("[Router] Group relationship lookup")
        return group_result

    print("[Router] Semantic search")
    return hybrid_retrieve(query, top_k=top_k)

def retrieve(query: str, n_results: int = 5) -> tuple[str, str]:
    """
    Public interface for notebook use.
    Returns (context_str, router_label) where context_str is
    ready to inject into the prompt and router_label is the
    routing path taken (for logging).
    """
    results = smart_retrieve(query, top_k=n_results)
    if not results:
        return "", "no results"
    router_label = _last_router_label(results)
    context_str = "\n\n".join(
        r["text"] for r in results
    )
    return context_str, router_label

def _last_router_label(results: list[dict]) -> str:
    if not results:
        return "no results"
    obj_type = results[0].get("object_type", "unknown")
    label_map = {
        "technique_relationship": "Technique -> Group lookup",
        "group_relationship":     "Group relationship lookup",
        "group":                  "Group semantic fallback",
        "technique":              "Technique ID lookup / Name lookup",
        "mitigation":             "Mitigation lookup",
        "mitigation_relationship": "Mitigation lookup",
    }
    return label_map.get(obj_type, "Semantic search")

def hybrid_retrieve(query: str, tactic: str = None,
                    platform: str = None, top_k: int = 5) -> list[dict]:
    """Semantic similarity + optional metadata filters."""
    q_vec = embedder.encode([query])[0].tolist()
    where = {}
    if tactic and platform:
        where = {"$and": [{"tactic": tactic}, {"platform": platform}]}
    elif tactic:
        where = {"tactic": tactic}
    elif platform:
        where = {"platform": platform}

    results = col.query(
        query_embeddings=[q_vec],
        n_results=top_k,
        where=where or None,
        include=["documents", "metadatas", "distances"],
    )
    out = []
    for i, meta in enumerate(results["metadatas"][0]):
        out.append({
            **meta,
            "text": results["documents"][0][i],
            "score": 1 - results["distances"][0][i],
        })
    return out