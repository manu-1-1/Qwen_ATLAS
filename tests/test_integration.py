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
            id_to_tech = {}
            
            if "objects" in attack_data:
                for obj in attack_data["objects"]:
                    if obj.get("type") == "intrusion-set":
                        id_to_name[obj.get("id")] = obj.get("name")
                    elif obj.get("type") == "attack-pattern":
                        refs = obj.get("external_references", [])
                        if refs:
                            id_to_tech[obj.get("id")] = refs[0].get("external_id", "")
                
                for obj in attack_data["objects"]:
                    if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses":
                        source = obj.get("source_ref", "")
                        target = obj.get("target_ref", "")
                        
                        actor_name = id_to_name.get(source)
                        tech_id = id_to_tech.get(target)
                        
                        if actor_name and tech_id:
                            golden_triples.append((actor_name, "uses", tech_id))
                    
            print(f"Loaded {len(golden_triples)} golden triples from MITRE data")
            
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