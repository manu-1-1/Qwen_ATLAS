# raft_dataset_gen.py
import json, random, re
from collections import defaultdict
from mitreattack.stix20 import MitreAttackData
from chroma_rag import hybrid_retrieve, col  # col needed for oracle-absent sampling

# ── Setup ────────────────────────────────────────────────────────────────────

attack = MitreAttackData("enterprise-attack.json")
with open("index_mappings.json") as f:
    idx = json.load(f)

techniques  = {t.external_references[0].external_id: t
               for t in attack.get_techniques(remove_revoked_deprecated=True)}
groups      = attack.get_groups(remove_revoked_deprecated=True)
mitigations = {m.external_references[0].external_id: m
               for m in attack.get_mitigations(remove_revoked_deprecated=True)}

SYSTEM = (
    "You are Qwen-ATLAS, an expert threat intelligence analyst specializing in "
    "MITRE ATT&CK. You will be given retrieved ATT&CK context documents. "
    "Answer using the provided context as your primary source. "
    "Cite technique IDs and group names explicitly. "
    "If the context is insufficient to answer fully, state what is missing."
)

def safe(v): return v if isinstance(v, str) else ""

def get_ext_id(obj):
    try: return obj.external_references[0].external_id
    except: return obj.id

def fmt_docs(docs: list[dict]) -> str:
    return "\n\n---\n\n".join(d["text"] for d in docs)

def make_example(question: str, docs: list[dict], cot: str, answer: str) -> dict:
    docs_block = fmt_docs(docs)
    return {"messages": [
        {"role": "system",    "content": SYSTEM},
        {"role": "user",      "content": f"ATT&CK Context:\n\n{docs_block}\n\nQuestion: {question}"},
        {"role": "assistant", "content": f"<reasoning>\n{cot}\n</reasoning>\n\n{answer}"},
    ]}

# ── Distractor retrieval ──────────────────────────────────────────────────────

def get_distractors(oracle_id: str, query: str, n: int = 3) -> list[dict]:
    """Query ChromaDB, exclude oracle, return n distractors."""
    results = hybrid_retrieve(query, top_k=n + 3)
    return [r for r in results if r.get("technique_id") != oracle_id][:n]

def get_oracle_doc(obj_id: str) -> dict | None:
    """Fetch a single object from ChromaDB by ID."""
    result = col.get(ids=[obj_id], include=["documents", "metadatas"])
    if not result["ids"]:
        return None
    return {"text": result["documents"][0], **result["metadatas"][0]}

# ── Type 1: Technique detection questions (oracle present) ────────────────────

def build_technique_detection_examples(limit=400) -> list[dict]:
    examples = []
    tids = list(techniques.keys())
    random.shuffle(tids)
    for tid in tids[:limit]:
        t = techniques[tid]
        platforms = list(t.x_mitre_platforms or [])
        tactics = [p.phase_name for p in (t.kill_chain_phases or [])]
        detection = safe(getattr(t, "x_mitre_detection", ""))
        if not detection:
            detection = (
                f"ATT&CK does not document explicit detection guidance for {tid}. "
                f"This technique operates on {', '.join(platforms)} platforms under the "
                f"{', '.join(tactics)} tactic(s). Detection should focus on platform-appropriate "
                f"telemetry for anomalous {t.name.lower()} activity."
            )

        monitoring_lines = (
            "- Monitor platform-appropriate telemetry for anomalous behavior\n"
            f"- Correlate with known {tid} indicators in threat intel feeds\n"
            f"- Review ATT&CK data sources for {tid} when available"
        )
        if any(p in ["Windows", "Linux", "macOS"] for p in platforms):
            monitoring_lines = (
                "- Enable command-line and process creation logging\n"
                "- Monitor for anomalous parent-child process relationships\n"
                f"- Correlate with known {tid} indicators in threat intel feeds\n"
                f"- Review data sources: {', '.join(_extract_datasources(detection))}"
            )

        oracle_doc = get_oracle_doc(tid)
        if not oracle_doc:
            continue

        question = f"How should a SOC analyst detect {t.name} ({tid})?"
        distractors = get_distractors(tid, question, n=3)
        docs = [oracle_doc] + distractors
        random.shuffle(docs)

        cot = (
            f"The retrieved context includes the ATT&CK entry for {tid} ({t.name}), "
            f"which contains an explicit Detection field. "
            f"The other documents are related techniques or groups that may use {tid} "
            f"but do not provide detection guidance directly. "
            f"I will extract detection data sources and recommended monitoring from the {tid} entry."
        )
        answer = (
            f"**Detecting {t.name} ({tid})**\n\n"
            f"**ATT&CK Detection Guidance:**\n{detection[:600]}\n\n"
            f"**Recommended monitoring:**\n{monitoring_lines}"
        )
        examples.append(make_example(question, docs, cot, answer))
    return examples

def _extract_datasources(detection_text: str) -> list[str]:
    """Extract DS#### references from detection text."""
    return list(set(re.findall(r'DS\d{4}', detection_text))) or ["process monitoring", "network traffic"]

# ── Type 2: Technique deep-dive (oracle present) ──────────────────────────────

def build_technique_deepdive_examples(limit=350) -> list[dict]:
    examples = []
    tids = list(techniques.keys())
    random.shuffle(tids)
    for tid in tids[:limit]:
        t = techniques[tid]
        tactics   = [p.phase_name for p in (t.kill_chain_phases or [])]
        platforms = list(t.x_mitre_platforms or [])
        desc = safe(t.description)
        if len(desc) < 100:
            continue

        oracle_doc = get_oracle_doc(tid)
        if not oracle_doc:
            continue

        question = f"Explain MITRE ATT&CK technique {tid}: {t.name}"
        distractors = get_distractors(tid, question, n=2)
        docs = [oracle_doc] + distractors
        random.shuffle(docs)

        cot = (
            f"The context contains the ATT&CK entry for {tid}. "
            f"I will summarize its tactic placement, platform scope, description, "
            f"and detection guidance from that entry."
        )
        answer = (
            f"**Technique ID:** {tid}\n"
            f"**Name:** {t.name}\n"
            f"**Tactic(s):** {', '.join(tactics)}\n"
            f"**Platforms:** {', '.join(platforms)}\n"
            f"**Description:** {desc[:700]}\n"
            f"**Detection:** {safe(getattr(t, 'x_mitre_detection', ''))[:400]}\n"
            f"**Used by:** {', '.join(idx['tech_to_groups'].get(tid, [])[:5]) or 'No attributed groups'}"
        )
        examples.append(make_example(question, docs, cot, answer))
    return examples

# ── Type 3: Group attribution (oracle present) ────────────────────────────────

def build_group_ttp_examples(limit=174) -> list[dict]:
    examples = []
    tactic_choices = ["persistence", "lateral-movement", "execution",
                      "collection", "credential-access", "defense-evasion"]

    for g in groups[:limit]:
        gid = get_ext_id(g)
        oracle_doc = get_oracle_doc(gid)
        if not oracle_doc:
            continue

        used = attack.get_techniques_used_by_group(g.id)
        techs = [(get_ext_id(t["object"]), t["object"].name) for t in used]
        if len(techs) < 3:
            continue

        tactic = random.choice(tactic_choices)
        filtered = [
            (tid, name) for tid, name in techs
            if tid in techniques and any(
                p.phase_name == tactic
                for p in (techniques[tid].kill_chain_phases or [])
            )
        ][:6]

        question = f"What {tactic.replace('-', ' ')} techniques does {g.name} use?"
        distractors = get_distractors(gid, question, n=3)
        docs = [oracle_doc] + distractors
        random.shuffle(docs)

        if filtered:
            ttp_lines = "\n".join(f"  - {tid}: {name}" for tid, name in filtered)
            cot = (
                f"The context contains the ATT&CK group entry for {g.name} ({gid}), "
                f"which lists associated techniques. I will filter those to {tactic} "
                f"phase techniques only."
            )
            answer = (
                f"**{g.name} ({gid}) — {tactic.replace('-', ' ').title()} TTPs**\n\n"
                f"**Overview:** {safe(g.description)[:400]}\n\n"
                f"**{tactic.replace('-', ' ').title()} techniques:**\n{ttp_lines}"
            )
        else:
            cot = (
                f"The ATT&CK entry for {g.name} is in the context but no techniques "
                f"are attributed specifically to the {tactic} tactic for this group. "
                f"I will note this gap explicitly."
            )
            answer = (
                f"**{g.name} ({gid})**\n\n"
                f"The ATT&CK context for {g.name} does not attribute specific "
                f"{tactic.replace('-', ' ')} techniques to this group. "
                f"Known associated techniques include: "
                f"{', '.join(t[0] for t in techs[:8])}."
            )
        examples.append(make_example(question, docs, cot, answer))
    return examples

def _detection_focus_for_tactic(tactic: str) -> str:
    return {
        "lateral-movement": "Internal SMB/RDP traffic, credential reuse across hosts, unusual service creation.",
        "persistence":      "Registry run key modifications, scheduled task creation, startup folder changes, new services.",
        "execution":        "Unusual process spawning, script interpreter invocations, LOLBin usage.",
        "collection":       "Unusual file access patterns, staging directories, archive creation.",
        "credential-access":"LSASS access, SAM database reads, unusual authentication failures.",
    }.get(tactic, "Platform telemetry relevant to the technique's operating environment.")

# ── Type 4: Multi-hop — group + technique cross-reference ────────────────────

def build_multihop_examples(limit=250) -> list[dict]:
    examples = []
    for g in random.sample(groups, min(limit, len(groups))):
        gid = get_ext_id(g)
        used = attack.get_techniques_used_by_group(g.id)
        for tactic_name in ["lateral-movement", "persistence", "execution"]:
            lm_techs = [
                t["object"] for t in used
                if any(p.phase_name == tactic_name
                    for p in (t["object"].kill_chain_phases or []))
                and get_ext_id(t["object"]) in techniques
            ][:3]
            if lm_techs:
                break  # use first tactic that has results

        group_doc = get_oracle_doc(gid)
        tech_docs = [get_oracle_doc(get_ext_id(t)) for t in lm_techs[:2]]
        tech_docs = [d for d in tech_docs if d]
        if not group_doc or not tech_docs:
            continue

        docs = [group_doc] + tech_docs
        # add 1 distractor
        question = f"{g.name} has achieved initial access. What {tactic_name.replace('-', ' ')} techniques should we prioritize monitoring?"
        distractor = get_distractors(gid, question, n=1)
        docs += distractor
        random.shuffle(docs)

        tech_summary = "\n".join(
            f"  - {get_ext_id(t)}: {t.name} — {safe(t.description)[:120]}"
            for t in lm_techs
        )
        cot = (
            f"This requires two hops: first identify {g.name}'s attributed TTPs from "
            f"the group document ({gid}), then cross-reference the {tactic_name.replace('-', ' ')} "
            f"technique entries present in the context to get detection-relevant detail."
        )
        answer = (
            f"**{tactic_name.replace('-', ' ').title()} Monitoring for {g.name}**\n\n"
            f"Based on ATT&CK attribution, prioritize:\n{tech_summary}\n\n"
            f"**Detection focus:** "
            + _detection_focus_for_tactic(tactic_name)
            + f" Correlate {g.name} IOCs with {tactic_name.replace('-', ' ')} artifacts within a 24-hour window."
        )
        examples.append(make_example(question, docs, cot, answer))
    return examples

# ── Type 5: Oracle absent — context insufficient (30% target) ────────────────

def build_oracle_absent_examples(limit=700) -> list[dict]:
    """
    Ask about a group/technique but retrieve only distractors.
    Model must recognize context is insufficient.
    """
    examples = []
    all_groups = list(groups)
    random.shuffle(all_groups)

    for g in all_groups[:limit]:
        gid = get_ext_id(g)
        used = attack.get_techniques_used_by_group(g.id)
        if not used:
            continue

        # Pick a tactic the group actually uses — but don't retrieve their doc
        tactic = random.choice(["exfiltration", "command-and-control", "collection"])
        question = f"What {tactic} techniques has {g.name} used in documented campaigns?"

        # Deliberately retrieve distractors only — exclude the group's own doc
        distractors = get_distractors(gid, question, n=4)
        if len(distractors) < 2:
            continue

        cot = (
            f"The retrieved context does not include the ATT&CK group entry for "
            f"{g.name} ({gid}). The documents present are technique or other group "
            f"entries that do not contain {g.name} attribution data. "
            f"I cannot answer from the context alone."
        )
        answer = (
            f"The retrieved ATT&CK context does not contain the group entry for "
            f"{g.name}. Without the attribution data from the {gid} STIX object, "
            f"I cannot confirm which specific {tactic} techniques this group has used. "
            f"Recommend querying the ATT&CK database directly for {gid} or "
            f"refining the retrieval query to include group objects."
        )
        examples.append(make_example(question, distractors, cot, answer))
    return examples

def build_technique_oracle_absent_examples(limit=400) -> list[dict]:
    """Ask about a technique but retrieve only unrelated docs."""
    examples = []
    tids = list(techniques.keys())
    random.shuffle(tids)
    
    for tid in tids[:limit]:
        t = techniques[tid]
        tactics = [p.phase_name for p in (t.kill_chain_phases or [])]
        if not tactics:
            continue
        
        # Ask about a tactic this technique does NOT belong to
        all_tactics = ["persistence", "lateral-movement", "execution",
                       "collection", "exfiltration", "command-and-control"]
        off_tactic = random.choice([x for x in all_tactics if x not in tactics])
        
        question = f"What {off_tactic.replace('-', ' ')} capability does {t.name} provide?"
        distractors = get_distractors(tid, question, n=4)
        if len(distractors) < 2:
            continue
        
        cot = (
            f"{t.name} ({tid}) is a {'/'.join(tactics)} technique, not a "
            f"{off_tactic} technique. The retrieved context reflects this mismatch — "
            f"the documents present do not address {off_tactic} capabilities of {tid}."
        )
        answer = (
            f"{t.name} ({tid}) is classified under {', '.join(tactics)} in ATT&CK, "
            f"not {off_tactic.replace('-', ' ')}. "
            f"The retrieved context does not contain {off_tactic} attribution for this technique. "
            f"If you are investigating {off_tactic.replace('-', ' ')} activity, "
            f"query ATT&CK for techniques under the TA"
            + ("0008" if off_tactic == "lateral-movement" else "0010" if off_tactic == "exfiltration" else "0011")
            + f" tactic."
        )
        examples.append(make_example(question, distractors, cot, answer))
    return examples

# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    random.seed(42)

    print("Building technique detection examples...")
    det   = build_technique_detection_examples(limit=450)
    print(f"  → {len(det)}")

    print("Building technique deep-dive examples...")
    dive  = build_technique_deepdive_examples(limit=400)
    print(f"  → {len(dive)}")

    print("Building group TTP examples...")
    grp   = build_group_ttp_examples(limit=174)
    print(f"  → {len(grp)}")

    print("Building multi-hop examples...")
    multi = build_multihop_examples(limit=174)
    print(f"  → {len(multi)}")

    print("Building oracle-absent (group) examples...")
    absent_g = build_oracle_absent_examples(limit=174)
    print(f"  → {len(absent_g)}")

    print("Building oracle-absent (technique) examples...")
    absent_t = build_technique_oracle_absent_examples(limit=400)
    print(f"  → {len(absent_t)}")

    dataset = det + dive + grp + multi + absent_g + absent_t
    random.shuffle(dataset)

    out = "raft_dataset.jsonl"
    with open(out, "w") as f:
        for ex in dataset:
            f.write(json.dumps(ex) + "\n")

    print(f"\nTotal: {len(dataset)} examples → {out}")