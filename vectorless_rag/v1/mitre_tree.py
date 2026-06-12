"""
mitre_tree.py
=============
Standalone vector-less RAG replacement using MITRE ATT&CK structured tree traversal.
No ChromaDB. No embeddings. No sentence-transformers.

Usage:
    from mitre_tree import MITRETree
    tree = MITRETree("enterprise-attack.json")
    context = tree.context_for_query("powershell execution")
"""

import json
from collections import defaultdict
from typing import Optional


# ─────────────────────────────────────────────
#  NODE
# ─────────────────────────────────────────────

class MITRENode:
    """A single node in the ATT&CK tree: Tactic, Technique, or Sub-technique."""

    def __init__(
        self,
        id: str,
        name: str,
        node_type: str,           # "tactic" | "technique" | "sub-technique"
        description: str = "",
        parent_id: Optional[str] = None,
        platforms: list = None,
        detection: str = "",
    ):
        self.id = id
        self.name = name
        self.node_type = node_type
        self.description = description
        self.parent_id = parent_id
        self.platforms = platforms or []
        self.detection = detection
        self.children: list["MITRENode"] = []

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.node_type,
            "description": self.description,
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
    Builds a Tactic → Technique → Sub-technique tree from enterprise-attack.json.

    Replaces ChromaDB by traversing the hierarchy and matching via keyword search.
    """

    def __init__(self, json_path: str):
        self.tactics: dict[str, MITRENode] = {}        # phase_name  → MITRENode
        self.techniques: dict[str, MITRENode] = {}     # T1059       → MITRENode
        self.all_nodes: dict[str, MITRENode] = {}      # flat lookup for any id
        self._build(json_path)

    # ── Build ──────────────────────────────────

    def _build(self, json_path: str):
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

            node = MITRENode(
                id=mitre_id,
                name=obj.get("name", ""),
                node_type="sub-technique" if is_sub else "technique",
                description=obj.get("description", ""),
                parent_id=mitre_id.split(".")[0] if is_sub else None,
                platforms=obj.get("x_mitre_platforms", []),
                detection=obj.get("x_mitre_detection", ""),
            )

            self.techniques[mitre_id] = node
            self.all_nodes[mitre_id] = node

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

    # ── Query API ──────────────────────────────

    def get_by_id(self, mitre_id: str) -> Optional[MITRENode]:
        """
        Exact ID lookup.
        Examples: get_by_id("T1059"), get_by_id("T1059.001"), get_by_id("initial-access")
        """
        return self.all_nodes.get(mitre_id)

    def search(self, keyword: str, node_type: str = None) -> list[MITRENode]:
        """
        Keyword search across name + description.
        Optionally filter by node_type: "tactic" | "technique" | "sub-technique"
        """
        kw = keyword.lower()
        results = []
        for node in self.all_nodes.values():
            if node_type and node.node_type != node_type:
                continue
            if kw in node.name.lower() or kw in node.description.lower():
                results.append(node)
        return results

    def get_subtree(self, node_id: str) -> Optional[dict]:
        """Returns the full subtree under any node as a nested dict."""
        node = self.all_nodes.get(node_id)
        return node.to_dict() if node else None

    def get_siblings(self, mitre_id: str) -> list[MITRENode]:
        """Returns all techniques/sub-techniques under the same parent."""
        node = self.all_nodes.get(mitre_id)
        if not node or not node.parent_id:
            return []
        parent = self.all_nodes.get(node.parent_id)
        return parent.children if parent else []

    def context_for_query(self, query: str, top_k: int = 5) -> str:
        """
        Takes a user query string, returns a formatted context string
        ready to inject into your LLM prompt.

        OLD (ChromaDB):
            results = collection.query(query_texts=[query], n_results=5)
            context = results['documents'][0]

        NEW (Tree):
            context = tree.context_for_query(query, top_k=5)
        ─────────────────────────────────────────────────────────────
        """
        results = self.search(query)[:top_k]

        if not results:
            return "No relevant MITRE ATT&CK techniques found for the query."

        lines = [f"MITRE ATT&CK Context — query: '{query}'\n{'─'*50}"]
        for node in results:
            lines.append(
                f"\n[{node.id}] {node.name}  |  Type: {node.node_type}"
                f"\nPlatforms: {', '.join(node.platforms) or 'N/A'}"
                f"\nDescription: {node.description[:400].strip()}..."
                f"\n{'─'*50}"
            )
        return "\n".join(lines)

    # ── Stats ──────────────────────────────────

    def stats(self) -> dict:
        """Quick summary of the loaded tree."""
        return {
            "tactics": len(self.tactics),
            "techniques": sum(1 for n in self.techniques.values() if n.node_type == "technique"),
            "sub_techniques": sum(1 for n in self.techniques.values() if n.node_type == "sub-technique"),
            "total_nodes": len(self.all_nodes),
        }