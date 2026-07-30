"""
Data Poisoning Simulation
"""

import json
from pathlib import Path
from typing import Dict, List, Tuple

class QwenATLASPoisonTester:
    """Test KG poisoning vulnerabilities"""
    
    def __init__(self, qwen_tester):
        self.qwen_tester = qwen_tester
        self.golden_baseline = qwen_tester.golden_baseline
    
    def verify_kg_consistency(self) -> Dict:
        """Scan your actual KG for potential poisoning"""
        kg_triples = self.qwen_tester.get_kg_triples()
        
        suspicious = []
        for triple in kg_triples:
            if triple not in self.golden_baseline:
                suspicious.append({
                    "triple": triple,
                    "reason": "Not found in MITRE ATT&CK baseline",
                    "severity": "HIGH"
                })
        
        return {
            "total_triples": len(kg_triples),
            "suspicious_count": len(suspicious),
            "suspicious_entries": suspicious[:10],  # Limit for display
            "trust_score": 1.0 - (len(suspicious) / len(kg_triples)) if kg_triples else 0.0
        }
