"""
Integration module for Qwen-ATLAS testing framework
Connects to existing RAG pipeline and knowledge graph
"""

import sys
import os
import json
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

class QwenATLASTester:
    """Tester that integrates with Qwen-ATLAS's existing components"""
    
    def __init__(self, rag_client=None, kg_client=None):
        """
        Initialize with existing Qwen-ATLAS components
        """
        self.rag_client = rag_client
        self.kg_client = kg_client
        self.golden_baseline = self._load_golden_baseline()
        self.test_results = []
        
    def _load_golden_baseline(self):
        """
        Load golden baseline from enterprise-attack.json
        This is your source of truth for validation
        """
        golden_triples = []
        
        try:
            # Look for enterprise-attack.json in project root
            json_path = project_root / "enterprise-attack.json"
            
            if not json_path.exists():
                print(f"Warning: {json_path} not found")
                return set()
                
            with open(json_path, 'r', encoding='utf-8') as f:
                attack_data = json.load(f)
            
            id_to_name = {}
            id_to_aliases = {}
            id_to_tech = {}
            
            group_uses_tech = {}
            group_uses_software = {}
            software_uses_tech = {}
            
            if "objects" in attack_data:
                # First pass: map IDs
                for obj in attack_data["objects"]:
                    obj_type = obj.get("type")
                    obj_id = obj.get("id")
                    if obj_type == "intrusion-set":
                        id_to_name[obj_id] = obj.get("name")
                        aliases = [obj.get("name")] + obj.get("aliases", [])
                        id_to_aliases[obj_id] = aliases
                    elif obj_type == "attack-pattern":
                        refs = obj.get("external_references", [])
                        if refs:
                            id_to_tech[obj_id] = refs[0].get("external_id", "")
                            
                # Second pass: map relationships
                for obj in attack_data["objects"]:
                    if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses":
                        source = obj.get("source_ref", "")
                        target = obj.get("target_ref", "")
                        
                        if source.startswith("intrusion-set--") and target.startswith("attack-pattern--"):
                            group_uses_tech.setdefault(source, set()).add(target)
                        elif source.startswith("intrusion-set--") and target.startswith(("malware--", "tool--")):
                            group_uses_software.setdefault(source, set()).add(target)
                        elif source.startswith(("malware--", "tool--")) and target.startswith("attack-pattern--"):
                            software_uses_tech.setdefault(source, set()).add(target)
                            
                # Third pass: build golden triples (Direct)
                for group_id, tech_set in group_uses_tech.items():
                    for tech_target in tech_set:
                        tech_id = id_to_tech.get(tech_target)
                        if tech_id:
                            for alias in id_to_aliases.get(group_id, []):
                                golden_triples.append((alias, "uses", tech_id))
                                
                # Fourth pass: build golden triples (Indirect via Software)
                for group_id, sw_set in group_uses_software.items():
                    for sw_id in sw_set:
                        for tech_target in software_uses_tech.get(sw_id, []):
                            tech_id = id_to_tech.get(tech_target)
                            if tech_id:
                                for alias in id_to_aliases.get(group_id, []):
                                    golden_triples.append((alias, "uses", tech_id))
                    
            print(f"Loaded {len(golden_triples)} golden triples from MITRE data (including aliases & indirect paths)")
            
        except Exception as e:
            print(f"Warning: Could not load golden baseline: {e}")
            # Try loading from index_mappings.json
            golden_triples = self._load_baseline_from_index()
        
        return set(golden_triples)
    
    def _load_baseline_from_index(self):
        """Fallback: Load baseline from your index mappings"""
        triples = []
        try:
            index_path = project_root / "index_mappings.json"
            if index_path.exists():
                with open(index_path, 'r', encoding='utf-8') as f:
                    mappings = json.load(f)
                    
                    if "tech_to_groups" in mappings:
                        for tech, groups in mappings["tech_to_groups"].items():
                            for group in groups:
                                triples.append((group, "uses", tech))
        except Exception as e:
            print(f"Could not load index mappings: {e}")
        
        return triples
    
    def query_model(self, prompt: str) -> str:
        """
        Query Qwen-ATLAS using your existing inference pipeline
        """
        try:
            # Try to import your inference function
            sys.path.insert(0, str(project_root))
            
            # Try different possible import names
            try:
                from rag_inference import query_rag_pipeline
                response = query_rag_pipeline(prompt)
                return str(response)
            except Exception as e:
                print(f"[DEBUG] rag_inference import failed: {e}")
            
            # Try chroma_rag
            try:
                from chroma_rag import ChromaRAG
                # This assumes ChromaRAG has a query method
                rag = ChromaRAG(persist_directory="./chroma_attackdb")
                response = rag.query(prompt)
                return str(response)
            except Exception as e:
                print(f"[DEBUG] chroma_rag import failed: {e}")
            
            # Try chroma_rag_ollama
            try:
                from chroma_rag_ollama import OllamaRAG
                rag = OllamaRAG()
                response = rag.query(prompt)
                return str(response)
            except:
                pass
            
            # If nothing works, return a placeholder
            return "[INFO] Model query not implemented. Placeholder response."
            
        except Exception as e:
            return f"[ERROR] Could not query model: {str(e)}"
    
    def get_kg_triples(self) -> List[Tuple]:
        """Extract triples from your vectorless knowledge graph"""
        triples = []
        
        try:
            kg_path = project_root / "index_mappings.json"
            
            if kg_path.exists():
                with open(kg_path, 'r', encoding='utf-8') as f:
                    kg_data = json.load(f)
                
                if "tech_to_groups" in kg_data:
                    for tech, groups in kg_data["tech_to_groups"].items():
                        for group in groups:
                            triples.append((group, "uses", tech))
                                
        except Exception as e:
            print(f"Could not load KG: {e}")
        
        return triples