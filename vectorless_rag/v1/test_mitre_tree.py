"""
test_mitre_tree.py
==================
Standalone test runner — run this to verify mitre_tree.py works
before touching your existing RAG code.

Run:
    python test_mitre_tree.py path/to/enterprise-attack.json
"""

import sys
from mitre_tree import MITRETree


def run_tests(json_path: str):
    print("=" * 60)
    print("  MITRE Tree — Standalone Test Runner")
    print("=" * 60)

    # ── Load ──────────────────────────────
    print("\n[1] Loading tree...")
    tree = MITRETree(json_path)
    stats = tree.stats()
    print(f"    ✓ Tactics        : {stats['tactics']}")
    print(f"    ✓ Techniques     : {stats['techniques']}")
    print(f"    ✓ Sub-techniques : {stats['sub_techniques']}")
    print(f"    ✓ Total nodes    : {stats['total_nodes']}")

    # ── Exact ID lookup ───────────────────
    print("\n[2] Exact ID lookup — T1059")
    node = tree.get_by_id("T1059")
    if node:
        print(f"    ✓ Found : [{node.id}] {node.name}")
        print(f"      Sub-techniques: {len(node.children)}")
    else:
        print("    ✗ Not found")

    # ── Sub-technique lookup ───────────────
    print("\n[3] Sub-technique lookup — T1059.001")
    sub = tree.get_by_id("T1059.001")
    if sub:
        print(f"    ✓ Found : [{sub.id}] {sub.name}  (parent: {sub.parent_id})")
    else:
        print("    ✗ Not found")

    # ── Tactic lookup ─────────────────────
    print("\n[4] Tactic lookup — initial-access")
    tactic = tree.get_by_id("initial-access")
    if tactic:
        print(f"    ✓ Found : [{tactic.id}] {tactic.name}")
        print(f"      Techniques under this tactic: {len(tactic.children)}")
    else:
        print("    ✗ Not found")

    # ── Keyword search ────────────────────
    print("\n[5] Keyword search — 'powershell'")
    results = tree.search("powershell")
    print(f"    ✓ {len(results)} results found")
    for r in results[:3]:
        print(f"      [{r.id}] {r.name}  ({r.node_type})")

    # ── context_for_query (drop-in test) ──
    print("\n[6] context_for_query — 'credential dumping'  (your ChromaDB replacement)")
    context = tree.context_for_query("credential dumping", top_k=3)
    print(context)

    # ── Siblings ──────────────────────────
    print("\n[7] Siblings of T1059.001")
    siblings = tree.get_siblings("T1059.001")
    print(f"    ✓ {len(siblings)} siblings")
    for s in siblings[:4]:
        print(f"      [{s.id}] {s.name}")

    print("\n" + "=" * 60)
    print("  All tests passed ✓")
    print("=" * 60)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_mitre_tree.py path/to/enterprise-attack.json")
        sys.exit(1)
    run_tests(sys.argv[1])