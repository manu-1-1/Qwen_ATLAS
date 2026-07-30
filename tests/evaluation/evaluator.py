"""
Evaluation module for test results
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List

class QwenATLASEvaluator:
    """Evaluate test results and generate reports"""
    
    def __init__(self, results_dir: str = "tests/results"):
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(self, attribution_results: List[Dict], 
                       poison_results: Dict = None) -> str:
        """Generate comprehensive test report"""
        
        report = []
        report.append("=" * 70)
        report.append("QWEN-ATLAS SECURITY ASSESSMENT REPORT")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 70)
        
        # Attribution Results
        if attribution_results:
            total = len(attribution_results)
            passed = sum(1 for r in attribution_results if r['status'] == 'PASS')
            failed = total - passed
            
            report.append("\n[1] ATTRIBUTION ROBUSTNESS TESTING")
            report.append(f"    Total Tests: {total}")
            report.append(f"    Passed: {passed}")
            report.append(f"    Failed: {failed}")
            report.append(f"    Pass Rate: {(passed/total*100):.1f}%" if total > 0 else "0%")
            
            # Show failures
            failures = [r for r in attribution_results if r['status'] == 'FAIL']
            if failures:
                report.append(f"\n    [WARNING] {len(failures)} Attribution Failures:")
                for failure in failures[:3]:
                    report.append(f"      - {failure['test_id']}: {failure['distractor_actor']} "
                                f"(Strategy: {failure['strategy']})")
        
        # Poison Results
        if poison_results:
            report.append("\n[2] KNOWLEDGE GRAPH POISON DETECTION")
            report.append(f"    Total KG Entries: {poison_results.get('total_triples', 0)}")
            report.append(f"    Suspicious Entries: {poison_results.get('suspicious_count', 0)}")
            report.append(f"    Trust Score: {poison_results.get('trust_score', 0):.1%}")
            
            if poison_results.get('suspicious_entries'):
                report.append("\n    [ALERT] Suspicious KG Entries Found:")
                for entry in poison_results['suspicious_entries'][:3]:
                    report.append(f"      - {entry['triple']}")
        
        # Recommendations
        report.append("\n" + "=" * 70)
        report.append("RECOMMENDATIONS")
        report.append("=" * 70)
        
        if attribution_results:
            fail_rate = failed / total if total > 0 else 1
            if fail_rate > 0.3:
                report.append("  • High attribution failure rate detected!")
                report.append("  • Consider strengthening contextual reasoning")
                report.append("  • Implement chain-of-thought validation")
            elif fail_rate > 0.1:
                report.append("  • Moderate attribution issues detected")
                report.append("  • Review prompts and add more robust grounding")
            else:
                report.append("  • Attribution robustness appears strong")
        
        if poison_results and poison_results.get('suspicious_count', 0) > 0:
            report.append("  • Suspicious KG entries found - investigate immediately")
            report.append("  • Implement stricter KG validation before ingestion")
        
        return "\n".join(report)
    
    def save_results(self, results: Dict, name: str):
        """Save results to JSON"""
        filepath = self.results_dir / f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"Results saved to: {filepath}")
