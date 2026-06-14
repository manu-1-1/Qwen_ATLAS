"""
mitre_tree.py
=============
Upgraded Vectorless RAG (v4) using MITRE ATT&CK structured tree traversal
relying SOLELY on LLM-based node selection, bypassing all deterministic routers.
"""

import os
import json
import re
import urllib.request
import urllib.error
from collections import defaultdict
from typing import Optional, List, Dict, Any

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.1:8b"


# ─────────────────────────────────────────────
#  HELPERS & OLLAMA INTEGRATION
# ─────────────────────────────────────────────

def query_ollama(prompt: str, system_prompt: Optional[str] = None) -> str:
    """Helper to query the local Ollama instance with Llama 3.1 8b."""
    data = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.0  # Keep selection deterministic
        }
    }
    if system_prompt:
        data["system"] = system_prompt

    req = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            return res_data.get("response", "").strip()
    except Exception as e:
        return ""


def get_fallback_summary(name: str, description: str) -> str:
    """Fallback summary: extracts the first two sentences from the description."""
    if not description:
        return f"Technique {name}."
    sentences = re.split(r'(?<=[.!?]) +', description.strip())
    fallback = " ".join(sentences[:2])
    return fallback if fallback else f"Technique {name}."


# ─────────────────────────────────────────────
#  NODE
# ─────────────────────────────────────────────

class MITRENode:
    """A single node in the ATT&CK tree representing Tactic, Technique, or Sub-technique."""

    def __init__(
        self,
        id: str,
        name: str,
        node_type: str,           # "tactic" | "technique" | "sub-technique"
        description: str = "",
        summary: str = "",
        parent_id: Optional[str] = None,
        platforms: list = None,
        detection: str = "",
    ):
        self.id = id
        self.name = name
        self.node_type = node_type
        self.description = description
        self.summary = summary
        self.parent_id = parent_id
        self.platforms = platforms or []
        self.detection = detection
        self.children: List[MITRENode] = []

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.node_type,
            "description": self.description,
            "summary": self.summary,
            "platforms": self.platforms,
            "detection": self.detection,
            "children": [c.to_dict() for c in self.children],
        }

    def __repr__(self):
        return f"<MITRENode [{self.id}] {self.name} ({self.node_type})>"


# ─────────────────────────────────────────────
#  TREE
# ─────────────────────────────────────────────

class MITRETree:
    """
    Builds a MITRE ATT&CK Tactic -> Technique -> Sub-technique tree,
    caches summaries, resolves actor groups & mitigations, and uses pure LLM-based selection.
    """

    def __init__(self, json_path: str):
        self.tactics: Dict[str, MITRENode] = {}        # phase_name  → MITRENode
        self.techniques: Dict[str, MITRENode] = {}     # T1059       → MITRENode
        self.all_nodes: Dict[str, MITRENode] = {}      # flat lookup for any ID
        
        # Metadata / Relationships from index_mappings
        self.group_to_techs: Dict[str, List[str]] = defaultdict(list)
        self.tech_to_groups: Dict[str, List[str]] = {}
        self.tech_to_mitigations: Dict[str, List[str]] = defaultdict(list)
        
        # Raw entity lookups for routing
        self.groups: Dict[str, Dict[str, Any]] = {}       # name_lower -> info
        self.alias_to_group: Dict[str, str] = {}         # alias_lower -> canonical_name
        self.mitigations: Dict[str, Dict[str, Any]] = {}   # ID -> info
        self.technique_name_to_id: Dict[str, str] = {}   # name_lower -> ID

        # Build structure
        self._build(json_path)

    def _build(self, json_path: str):
        # 1. Load mappings if available
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        mappings_path = os.path.join(base_dir, "index_mappings.json")
        if os.path.exists(mappings_path):
            with open(mappings_path, "r", encoding="utf-8") as f:
                mappings = json.load(f)
            self.tech_to_groups = mappings.get("tech_to_groups", {})
            for tech, grps in self.tech_to_groups.items():
                for grp in grps:
                    self.group_to_techs[grp].append(tech)
            
            mit_to_techs = mappings.get("mit_to_techs", {})
            for mit, techs in mit_to_techs.items():
                for tech in techs:
                    self.tech_to_mitigations[tech].append(mit)

        # 2. Load summaries cache (fallback to sibling v2 if needed)
        cache_path = os.path.join(os.path.dirname(__file__), "mitre_summaries.json")
        if not os.path.exists(cache_path):
            cache_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "v2", "mitre_summaries.json")
            
        summaries = {}
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    summaries = json.load(f)
            except Exception:
                pass

        # 3. Read STIX data
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        objects = data.get("objects", [])

        # Pass 1 — Tactics
        for obj in objects:
            if obj.get("type") == "x-mitre-tactic":
                shortname = obj.get("x_mitre_shortname", obj["id"])
                node = MITRENode(
                    id=shortname,
                    name=obj.get("name", ""),
                    node_type="tactic",
                    description=obj.get("description", ""),
                    summary=obj.get("description", "")[:150] + "...",
                )
                self.tactics[shortname] = node
                self.all_nodes[shortname] = node

        # Pass 2 — Techniques + Sub-techniques
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue

            ext_refs = obj.get("external_references", [])
            mitre_id = next(
                (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
                obj["id"],
            )

            is_sub = obj.get("x_mitre_is_subtechnique", False)
            phases = [
                p["phase_name"]
                for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ]

            # Summary loading (from cache or fallback description sentences)
            summary = summaries.get(mitre_id)
            if not summary:
                summary = get_fallback_summary(obj.get("name", ""), obj.get("description", ""))

            node = MITRENode(
                id=mitre_id,
                name=obj.get("name", ""),
                node_type="sub-technique" if is_sub else "technique",
                description=obj.get("description", ""),
                summary=summary,
                parent_id=mitre_id.split(".")[0] if is_sub else None,
                platforms=obj.get("x_mitre_platforms", []),
                detection=obj.get("x_mitre_detection", ""),
            )

            self.techniques[mitre_id] = node
            self.all_nodes[mitre_id] = node
            self.technique_name_to_id[node.name.lower()] = mitre_id

            # Attach technique → tactic
            if not is_sub:
                for phase in phases:
                    if phase in self.tactics:
                        self.tactics[phase].children.append(node)

        # Pass 3 — Attach sub-techniques → parent technique
        for node in self.techniques.values():
            if node.node_type == "sub-technique" and node.parent_id:
                parent = self.techniques.get(node.parent_id)
                if parent:
                    parent.children.append(node)

        # Pass 4 — Load Groups & Mitigations from STIX
        for obj in objects:
            # Intrusion Set (Threat Actor / Group)
            if obj.get("type") == "intrusion-set":
                ext_refs = obj.get("external_references", [])
                group_id = next(
                    (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
                    obj["id"],
                )
                aliases = obj.get("aliases", [])
                group_info = {
                    "id": group_id,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "aliases": aliases
                }
                name_lower = group_info["name"].lower()
                self.groups[name_lower] = group_info
                self.alias_to_group[name_lower] = group_info["name"]
                for alias in aliases:
                    self.alias_to_group[alias.lower()] = group_info["name"]

            # Course of Action (Mitigation)
            elif obj.get("type") == "course-of-action":
                ext_refs = obj.get("external_references", [])
                mit_id = next(
                    (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
                    obj["id"],
                )
                self.mitigations[mit_id] = {
                    "id": mit_id,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", "")
                }

    # ── Traversal Helpers ────────────────────────

    def get_by_id(self, mitre_id: str) -> Optional[MITRENode]:
        return self.all_nodes.get(mitre_id)

    def get_siblings(self, mitre_id: str) -> List[MITRENode]:
        node = self.all_nodes.get(mitre_id)
        if not node:
            return []
        if node.node_type == "sub-technique" and node.parent_id:
            parent = self.all_nodes.get(node.parent_id)
            return [c for c in parent.children if c.id != mitre_id] if parent else []
        elif node.node_type == "technique":
            siblings = []
            for tactic in self.tactics.values():
                if node in tactic.children:
                    siblings.extend([c for c in tactic.children if c.id != mitre_id])
            return list(set(siblings))
        return []

    # ── Unified Candidate Filtering (Pre-LLM) ─────

    def get_candidate_nodes(self, query: str, top_n: int = 30) -> List[Dict[str, Any]]:
        """Filters down techniques, groups, and mitigations based on term overlap."""
        query_lower = query.lower()
        tokens = [t for t in re.split(r'\W+', query_lower) if len(t) > 2]
        
        if not tokens:
            # Return subset of tree index as fallback candidates
            index = []
            for node in list(self.techniques.values())[:top_n]:
                index.append({
                    "id": node.id,
                    "title": node.name,
                    "type": "technique",
                    "summary": node.summary
                })
            return index

        scored_nodes = []
        
        # 1. Score Techniques
        for node in self.techniques.values():
            score = 0
            if node.id.lower() in query_lower:
                score += 500
            name_lower = node.name.lower()
            if name_lower in query_lower:
                score += 300
            for token in tokens:
                if token in name_lower:
                    score += 50
                if token in node.summary.lower():
                    score += 10
                if token in node.description.lower():
                    score += 2
            if score > 0:
                scored_nodes.append((score, {
                    "id": node.id,
                    "title": node.name,
                    "type": "technique",
                    "summary": node.summary
                }))
                
        # 2. Score Groups
        for name_lower, group in self.groups.items():
            score = 0
            if group["id"].lower() in query_lower:
                score += 500
            if name_lower in query_lower:
                score += 300
            for alias in group.get("aliases", []):
                if alias.lower() in query_lower:
                    score += 300
            for token in tokens:
                if token in name_lower:
                    score += 50
                if token in group.get("description", "").lower():
                    score += 5
            if score > 0:
                scored_nodes.append((score, {
                    "id": group["id"],
                    "title": group["name"],
                    "type": "group",
                    "summary": group.get("description", "")[:150] + "..."
                }))
                
        # 3. Score Mitigations
        for mid, mit in self.mitigations.items():
            score = 0
            if mid.lower() in query_lower:
                score += 500
            name_lower = mit["name"].lower()
            if name_lower in query_lower:
                score += 300
            for token in tokens:
                if token in name_lower:
                    score += 50
                if token in mit.get("description", "").lower():
                    score += 5
            if score > 0:
                scored_nodes.append((score, {
                    "id": mid,
                    "title": mit["name"],
                    "type": "mitigation",
                    "summary": mit.get("description", "")[:150] + "..."
                }))
                
        # Sort candidates and return top N
        scored_nodes.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in scored_nodes[:top_n]]

    # ── LLM Retrieval Selection ─────────────────

    def select_nodes(self, query: str, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Asks Ollama to select relevant nodes from candidates."""
        if not candidates:
            return []

        prompt = f"""
You are a MITRE ATT&CK retrieval system.

User Query:
{query}

Available Candidate Nodes (techniques, groups, mitigations):
{json.dumps(candidates, indent=2)}

Analyze the query and select the most relevant candidate nodes. For each selected node, assign a relevance score from 0 to 10 (10 being most relevant).
Return ONLY a valid JSON array of objects, each containing "id" and "score", ordered by score descending.

Example:
[
  {{
    "id": "T1059.001",
    "score": 10
  }}
]
"""
        response = query_ollama(prompt, "You are a precise JSON generator. Do not include markdown blocks, notes, or conversational text. Return only raw JSON.")
        return self._parse_selected_nodes(response)

    def _parse_selected_nodes(self, text: str) -> List[Dict[str, Any]]:
        text_clean = text.strip()
        if text_clean.startswith("```json"):
            text_clean = text_clean[7:]
        if text_clean.startswith("```"):
            text_clean = text_clean[3:]
        if text_clean.endswith("```"):
            text_clean = text_clean[:-3]
        text_clean = text_clean.strip()

        try:
            data = json.loads(text_clean)
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass

        match = re.search(r'\[\s*\{.*\}\s*\]', text_clean, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
                if isinstance(data, list):
                    return data
            except json.JSONDecodeError:
                pass

        # Regex fallback
        items = []
        matches = re.findall(r'\{\s*["\']id["\']\s*:\s*["\'](T\d{4}(?:\.\d{3})?|G\d{4}|M\d{4})["\']\s*,\s*["\']score["\']\s*:\s*(\d+)\s*\}', text_clean)
        for tid, score_str in matches:
            items.append({"id": tid, "score": int(score_str)})
        
        if not items:
            ids = re.findall(r'(?:T\d{4}(?:\.\d{3})?|G\d{4}|M\d{4})', text_clean)
            for tid in set(ids):
                items.append({"id": tid, "score": 8})

        return items

    def check_completeness(self, query: str, context_str: str) -> bool:
        """Asks LLM if the retrieved context is sufficient for the query."""
        prompt = f"""
Question:
{query}

Retrieved Context:
{context_str}

Is this retrieved context sufficient to answer the question about the MITRE ATT&CK techniques, actors, or mitigations?
Answer ONLY YES or NO.
"""
        response = query_ollama(prompt).strip().upper()
        return "YES" in response or "NO" not in response

    # ── Context Generation (Pure LLM Selector) ─────

    def context_for_query(self, query: str, top_k: int = 5) -> str:
        """
        Retrieves context relying purely on LLM Node Selection.
        Bypasses the direct routing highways completely.
        """
        query_lower = query.lower()

        # 1. Fetch Candidates and run LLM Selector
        candidates = self.get_candidate_nodes(query, top_n=30)
        selected_scores = self.select_nodes(query, candidates)

        # 2. Filter Selected Nodes
        selected_items = []
        for item in selected_scores:
            node_id = item.get("id")
            score = item.get("score", 0)
            if node_id and score >= 4:
                # Find node type from candidate list
                node_type = "technique"
                for cand in candidates:
                    if cand["id"] == node_id:
                        node_type = cand["type"]
                        break
                selected_items.append((score, node_id, node_type))

        # Fallback to top keyword candidate if LLM didn't select anything
        if not selected_items and candidates:
            selected_items.append((8, candidates[0]["id"], candidates[0]["type"]))

        if not selected_items:
            return "No relevant MITRE ATT&CK techniques found for the query."

        # Sort selected items by score descending
        selected_items.sort(key=lambda x: x[0], reverse=True)

        # 3. Detect Intent using Keyword Overlap
        has_mitigation_intent = bool(re.search(r"(mitigate|mitigation|prevent|defend|protect)", query_lower))
        has_tech_to_groups_intent = bool(re.search(r"(which groups|who uses|actors using|groups associated)", query_lower))
        has_group_relationship_intent = bool(re.search(r"(what techniques|which techniques|ttp|uses|techniques used)", query_lower))

        context_blocks = []
        for _, node_id, node_type in selected_items[:top_k]:
            if node_type == "group":
                # Resolve group from canonical name/alias dict
                group_info = None
                for g in self.groups.values():
                    if g["id"].lower() == node_id.lower():
                        group_info = g
                        break
                if group_info:
                    if has_group_relationship_intent:
                        tech_ids = self.group_to_techs.get(group_info["name"], [])
                        tech_names = [f"- {self.get_by_id(tid).name} ({tid})" for tid in tech_ids[:15] if self.get_by_id(tid)]
                        relationship_text = (
                            f"Group: {group_info['name']}\n\n"
                            f"The following ATT&CK techniques are associated with {group_info['name']}:\n\n"
                            + "\n".join(tech_names)
                        )
                        context_blocks.append(relationship_text)
                        for tid in tech_ids[:3]:
                            tnode = self.get_by_id(tid)
                            if tnode:
                                context_blocks.append(
                                    f"[{tnode.id}] {tnode.name}\n"
                                    f"Description: {tnode.description[:1000]}...\n"
                                    f"Detection: {tnode.detection[:400]}"
                                )
                    else:
                        aliases_str = ", ".join(group_info.get("aliases", []))
                        context_blocks.append(
                            f"Group: {group_info['name']} ({group_info['id']})\n"
                            f"Aliases: {aliases_str}\n"
                            f"Description: {group_info['description']}"
                        )

            elif node_type == "technique":
                tnode = self.techniques.get(node_id)
                if tnode:
                    if has_mitigation_intent:
                        mit_ids = self.tech_to_mitigations.get(node_id, [])
                        if mit_ids:
                            mitigation_lines = []
                            for mid in mit_ids:
                                mit_info = self.mitigations.get(mid)
                                if mit_info:
                                    mitigation_lines.append(f"- {mit_info['name']} ({mid}): {mit_info['description'][:200]}...")
                            context_blocks.append(
                                f"Technique: {node_id}\n\n"
                                f"Associated mitigations:\n\n"
                                + "\n".join(sorted(mitigation_lines))
                            )
                    elif has_tech_to_groups_intent:
                        groups = self.tech_to_groups.get(node_id, [])
                        if groups:
                            group_lines = [f"- {g}" for g in groups]
                            context_blocks.append(
                                f"Technique: {node_id}\n\n"
                                f"The following ATT&CK groups are associated with {node_id}:\n\n"
                                + "\n".join(group_lines)
                            )
                    else:
                        context_blocks.append(
                            f"[{tnode.id}] {tnode.name}\n\n"
                            f"Description: {tnode.description}\n\n"
                            f"Detection: {tnode.detection}"
                        )

            elif node_type == "mitigation":
                mit_info = self.mitigations.get(node_id)
                if mit_info:
                    context_blocks.append(
                        f"Mitigation: {mit_info['name']} ({node_id})\n"
                        f"Description: {mit_info['description']}"
                    )

        context_str = "\n\n---\n\n".join(context_blocks)

        # 4. Completeness Check & Context Expansion (Only for Techniques)
        # Check if the generated context matches a technique info query and runs expansion
        if len(context_blocks) > 0 and "Description:" in context_str:
            is_sufficient = self.check_completeness(query, context_str)
            if not is_sufficient:
                expanded_nodes = []
                for _, node_id, node_type in selected_items[:top_k]:
                    if node_type == "technique":
                        node = self.techniques.get(node_id)
                        if node:
                            if node.parent_id:
                                parent = self.get_by_id(node.parent_id)
                                if parent and parent not in expanded_nodes:
                                    expanded_nodes.append(parent)
                            for child in node.children[:3]:
                                if child not in expanded_nodes:
                                    expanded_nodes.append(child)
                            siblings = self.get_siblings(node.id)
                            for sib in siblings[:3]:
                                if sib not in expanded_nodes:
                                    expanded_nodes.append(sib)

                if expanded_nodes:
                    context_blocks.append("\n\n=== Expanded Context (Sufficient Info Check Fallback) ===")
                    for node in expanded_nodes:
                        context_blocks.append(
                            f"[{node.id}] {node.name} (Related)\n"
                            f"Description: {node.description[:800]}...\n"
                            f"Detection: {node.detection[:300]}"
                        )
                    context_str = "\n\n---\n\n".join(context_blocks)

        return context_str

    def stats(self) -> dict:
        return {
            "tactics": len(self.tactics),
            "techniques": sum(1 for n in self.techniques.values() if n.node_type == "technique"),
            "sub_techniques": sum(1 for n in self.techniques.values() if n.node_type == "sub-technique"),
            "total_nodes": len(self.all_nodes),
        }
