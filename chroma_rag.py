import chromadb
import numpy as np
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
from mitreattack.stix20 import MitreAttackData
import json, re

attack  = MitreAttackData("enterprise-attack.json")
embedder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

client = chromadb.PersistentClient(path="./chroma_attackdb")
col    = client.get_or_create_collection("attck_objects",
             metadata={"hnsw:space": "cosine"})

with open("index_mappings.json") as f:
    mappings = json.load(f)

tech_to_groups = mappings["tech_to_groups"]
tactic_to_techs = mappings["tactic_to_techs"]
mit_to_techs = mappings["mit_to_techs"]

from collections import defaultdict

group_to_techs = defaultdict(list)

for tech, groups in tech_to_groups.items():
    for group in groups:
        group_to_techs[group].append(tech)

def safe_text(val):
    return val if isinstance(val, str) else ""

def get_ext_id(obj):
    try: return obj.external_references[0].external_id
    except: return obj.id

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
            documents=docs[i:i+batch],           # ✅ plain text strings
            embeddings=embeddings[i:i+batch],     # ✅ vectors separately
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

    result = col.get(
        ids=[tid],
        include=["documents", "metadatas"]
    )

    if not result["ids"]:
        return None

    return format_chroma_get(result)

def lookup_group(query, top_k=5):
    query_lower = query.lower()

    matched_group = None

    for group in group_to_techs.keys():
        if group.lower() in query_lower:
            matched_group = group
            break

    if not matched_group:
        return None

    technique_ids = group_to_techs[matched_group]

    result = col.get(
        ids=technique_ids,
        include=["documents", "metadatas"]
    )

    if not result["documents"]:
        return None

    query_vec = embedder.encode(query)

    doc_vecs = embedder.encode(
        result["documents"],
        show_progress_bar=False
    )

    scores = np.dot(doc_vecs, query_vec)

    top_indices = np.argsort(scores)[::-1][:top_k]

    reranked = {
        "documents": [result["documents"][i] for i in top_indices],
        "metadatas": [result["metadatas"][i] for i in top_indices]
    }

    return format_chroma_get(reranked)

def smart_retrieve(query, top_k=5):

    tech_result = lookup_technique_id(query)

    if tech_result:
        print("[Router] Technique ID lookup")
        return tech_result

    group_result = lookup_group(query, top_k)

    if group_result:
        print("[Router] Group relationship lookup")
        return group_result

    print("[Router] Semantic search")

    return hybrid_retrieve(query, top_k=top_k)

# ── Hybrid retrieval function ────────────────────────────────────────────────
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
        out.append({**meta,
                    "text": results["documents"][0][i],
                    "score": 1 - results["distances"][0][i]})
    return out