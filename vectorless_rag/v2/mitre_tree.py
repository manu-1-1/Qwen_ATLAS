"""
mitre_tree.py
=============
Upgraded Vectorless RAG (v2) using MITRE ATT&CK structured tree traversal
with LLM-generated summaries, Ollama llama3.1:8b selection, and completeness checks.
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
        # Silently log error, fallback code handles empty response
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
    caches summaries, resolves actor groups & mitigations, and uses LLM-based selection.
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

        # 2. Load summaries cache
        cache_path = os.path.join(os.path.dirname(__file__), "mitre_summaries.json")
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

        # Pass 4 — Load Groups & Mitigations from STIX to enable complete routing
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
            # Techniques sharing the same tactic
            siblings = []
            for tactic in self.tactics.values():
                if node in tactic.children:
                    siblings.extend([c for c in tactic.children if c.id != mitre_id])
            return list(set(siblings))
        return []

    # ── LLM Retrieval Selection ─────────────────

    def build_tree_index(self) -> List[Dict[str, str]]:
        """Creates a lightweight index of all techniques and sub-techniques."""
        index = []
        for node in self.techniques.values():
            index.append({
                "id": node.id,
                "title": node.name,
                "type": node.node_type,
                "summary": node.summary
            })
        return index

    def select_nodes(self, query: str, candidates: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Asks Ollama to score and select the best nodes from the candidate list."""
        if not candidates:
            return []

        prompt = f"""
You are a MITRE ATT&CK retrieval system.

User Query:
{query}

Available Nodes:
{json.dumps(candidates, indent=2)}

Analyze the query and select the most relevant ATT&CK nodes. For each selected node, assign a relevance score from 0 to 10 (10 being most relevant).
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
        
        # Robust parsing
        return self._parse_selected_nodes(response)

    def _parse_selected_nodes(self, text: str) -> List[Dict[str, Any]]:
        text_clean = text.strip()
        # Clean up code blocks if present
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

        # Regex fallback
        match = re.search(r'\[\s*\{.*\}\s*\]', text_clean, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
                if isinstance(data, list):
                    return data
            except json.JSONDecodeError:
                pass

        # Direct token regex parsing
        items = []
        matches = re.findall(r'\{\s*["\']id["\']\s*:\s*["\'](T\d{4}(?:\.\d{3})?)["\']\s*,\s*["\']score["\']\s*:\s*(\d+)\s*\}', text_clean)
        for tid, score_str in matches:
            items.append({"id": tid, "score": int(score_str)})
        
        if not items:
            # Look for general IDs in the text
            ids = re.findall(r'T\d{4}(?:\.\d{3})?', text_clean)
            for tid in set(ids):
                items.append({"id": tid, "score": 8})  # Default relevance score

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
        return "YES" in response or "NO" not in response  # Safe fallback to True if ambiguous

    # ── Candidate Filtering (Pre-LLM) ────────────

    def get_candidate_nodes(self, query: str, top_n: int = 25) -> List[Dict[str, str]]:
        """Filters nodes down using a fast keyword matching score before sending to LLM."""
        query_lower = query.lower()
        # Tokenize query, remove short words (stopwords-like)
        tokens = [t for t in re.split(r'\W+', query_lower) if len(t) > 2]
        
        if not tokens:
            # If no keywords remain, return top top_n techniques based on name length
            return self.build_tree_index()[:top_n]

        scored_nodes = []
        for node in self.techniques.values():
            score = 0
            # Matches in ID (exact match = huge boost)
            if node.id.lower() in query_lower:
                score += 500
            
            # Matches in name
            name_lower = node.name.lower()
            if name_lower in query_lower:
                score += 300
            for token in tokens:
                if token in name_lower:
                    score += 50
            
            # Matches in summary / description
            desc_lower = node.description.lower()
            summary_lower = node.summary.lower()
            for token in tokens:
                if token in summary_lower:
                    score += 10
                if token in desc_lower:
                    score += 2

            if score > 0:
                scored_nodes.append((score, node))

        # Sort and take top N
        scored_nodes.sort(key=lambda x: x[0], reverse=True)
        candidates = []
        for _, node in scored_nodes[:top_n]:
            candidates.append({
                "id": node.id,
                "title": node.name,
                "type": node.node_type,
                "summary": node.summary
            })
        
        # If no candidates found via token matching, return a slice of the index
        if not candidates:
            return self.build_tree_index()[:top_n]

        return candidates

    # ── Context Generation & Query Router ────────

    def context_for_query(self, query: str, top_k: int = 5) -> str:
        """
        Main query interface. Matches the routing logic of Chroma RAG:
        1. Technique ID / Name Lookups
        2. Threat Group Aliases and Relationships
        3. Mitigation Mappings (both ID and Name resolved)
        4. Semantic query selection via LLM node selection + Completeness expansion.
        """
        query_lower = query.lower()

        # ── 1. Resolve Group / Actor Name first ────────
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
            # Check if it's a Group Info query ("what is", "who is", "explain" or just the name)
            is_info_query = re.search(r"(what is|who is|explain)", query_lower) or query_lower.strip() in [matched_group.lower(), group_name.lower()]
            
            group_info = self.groups.get(matched_group.lower(), {})
            desc = group_info.get("description", "No description available.")
            
            if is_info_query:
                aliases_str = ", ".join(group_info.get("aliases", []))
                return (
                    f"Group: {group_info.get('name')} ({group_info.get('id', 'N/A')})\n"
                    f"Aliases: {aliases_str}\n"
                    f"Description: {desc}"
                )
            else:
                # Group Relationship query (techniques used by group)
                tech_ids = self.group_to_techs.get(matched_group, [])
                tech_names = []
                for tid in tech_ids[:15]:
                    tnode = self.get_by_id(tid)
                    if tnode:
                        tech_names.append(f"- {tnode.name} ({tid})")
                
                relationship_text = (
                    f"Group: {matched_group}\n\n"
                    f"The following ATT&CK techniques are associated with {matched_group}:\n\n"
                    + "\n".join(tech_names)
                )
                
                # Fetch raw details of top 5 associated techniques (same as Chroma RAG)
                detail_blocks = [relationship_text]
                for tid in tech_ids[:5]:
                    tnode = self.get_by_id(tid)
                    if tnode:
                        detail_blocks.append(
                            f"[{tnode.id}] {tnode.name}\n"
                            f"Description: {tnode.description[:1000]}...\n"
                            f"Detection: {tnode.detection[:400]}"
                        )
                return "\n\n---\n\n".join(detail_blocks)

        # ── 2. Technique to Groups Lookup ────────────
        if re.search(r"(which groups|who uses|actors using|groups associated)", query_lower):
            tid = None
            match = re.search(r"T\d{4}(?:\.\d{3})?", query_lower)
            if match:
                tid = match.group().upper()
            else:
                for name, tech_id in sorted(self.technique_name_to_id.items(), key=lambda x: len(x[0]), reverse=True):
                    if re.search(rf"\b{re.escape(name)}\b", query_lower):
                        tid = tech_id
                        break
            if tid:
                groups = self.tech_to_groups.get(tid, [])
                if groups:
                    group_lines = [f"- {g}" for g in groups]
                    return (
                        f"Technique: {tid}\n\n"
                        f"The following ATT&CK groups are associated with {tid}:\n\n"
                        + "\n".join(group_lines)
                    )

        # ── 3. Mitigation Lookup ────────────────────
        if re.search(r"(mitigate|mitigation|prevent|defend|protect)", query_lower):
            tid = None
            match = re.search(r"T\d{4}(?:\.\d{3})?", query_lower)
            if match:
                tid = match.group().upper()
            else:
                for name, tech_id in sorted(self.technique_name_to_id.items(), key=lambda x: len(x[0]), reverse=True):
                    if re.search(rf"\b{re.escape(name)}\b", query_lower):
                        tid = tech_id
                        break
            
            if tid:
                mit_ids = self.tech_to_mitigations.get(tid, [])
                if mit_ids:
                    mitigation_lines = []
                    for mid in mit_ids:
                        mit_info = self.mitigations.get(mid)
                        if mit_info:
                            mitigation_lines.append(f"- {mit_info['name']} ({mid}): {mit_info['description'][:200]}...")
                    return (
                        f"Technique: {tid}\n\n"
                        f"Associated mitigations:\n\n"
                        + "\n".join(sorted(mitigation_lines))
                    )

        # ── 4. Exact ID Lookup ──────────────────────
        match = re.search(r"T\d{4}(?:\.\d{3})?", query)
        if match:
            tid = match.group()
            node = self.get_by_id(tid)
            if node:
                return (
                    f"[{node.id}] {node.name}\n\n"
                    f"Description: {node.description}\n\n"
                    f"Detection: {node.detection}"
                )

        # Match by specific technique name in query
        for name, tid in sorted(self.technique_name_to_id.items(), key=lambda x: len(x[0]), reverse=True):
            if re.search(rf"\b{re.escape(name)}\b", query_lower):
                node = self.get_by_id(tid)
                if node:
                    return (
                        f"[{node.id}] {node.name}\n\n"
                        f"Description: {node.description}\n\n"
                        f"Detection: {node.detection}"
                    )

        # ── 5. Semantic LLM-Based Retrieval ──────────
        candidates = self.get_candidate_nodes(query, top_n=25)
        selected_scores = self.select_nodes(query, candidates)

        # Filter and sort selected nodes
        selected_nodes = []
        for item in selected_scores:
            node_id = item.get("id")
            score = item.get("score", 0)
            if node_id and score >= 4:  # Cutoff threshold
                node = self.get_by_id(node_id)
                if node:
                    selected_nodes.append((score, node))

        # Sort by score descending
        selected_nodes.sort(key=lambda x: x[0], reverse=True)
        selected_nodes = [node for _, node in selected_nodes[:top_k]]

        # If LLM didn't select anything relevant, fall back to top candidate nodes
        if not selected_nodes and candidates:
            for cand in candidates[:top_k]:
                node = self.get_by_id(cand["id"])
                if node:
                    selected_nodes.append(node)

        if not selected_nodes:
            return "No relevant MITRE ATT&CK techniques found for the query."

        # Format retrieved context
        context_blocks = []
        for node in selected_nodes:
            context_blocks.append(
                f"[{node.id}] {node.name}\n"
                f"Description: {node.description[:1000]}...\n"
                f"Detection: {node.detection[:400]}"
            )
        
        context_str = "\n\n---\n\n".join(context_blocks)

        # ── 6. Completeness Check & Context Expansion ──
        is_sufficient = self.check_completeness(query, context_str)
        if not is_sufficient:
            # Expand context!
            expanded_nodes = []
            for node in selected_nodes:
                # Add parent
                if node.parent_id:
                    parent = self.get_by_id(node.parent_id)
                    if parent and parent not in selected_nodes and parent not in expanded_nodes:
                        expanded_nodes.append(parent)
                
                # Add children (limit to 3 to avoid overflow)
                for child in node.children[:3]:
                    if child not in selected_nodes and child not in expanded_nodes:
                        expanded_nodes.append(child)
                
                # Add siblings (limit to 3)
                siblings = self.get_siblings(node.id)
                for sib in siblings[:3]:
                    if sib not in selected_nodes and sib not in expanded_nodes:
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
