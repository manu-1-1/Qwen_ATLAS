#!/usr/bin/env python3
"""
Main test runner for Qwen-ATLAS
"""

import sys
import json
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from tests.test_integration import QwenATLASTester
from tests.red_team.attribution_tests import QwenATLASAttributionTester
from tests.poison_simulation.kg_poison_tester import QwenATLASPoisonTester
from tests.evaluation.evaluator import QwenATLASEvaluator

def main():
    """Run the complete test suite"""
    print("=" * 60)
    print("QWEN-ATLAS SECURITY ASSESSMENT")
    print("=" * 60)
    
    # Initialize tester
    print("\n[1] Initializing Qwen-ATLAS Tester...")
    qwen_tester = QwenATLASTester()
    print(f"    Loaded {len(qwen_tester.golden_baseline)} golden baseline entries")
    
    # Run attribution tests
    print("\n[2] Running Attribution Robustness Tests...")
    attribution_tester = QwenATLASAttributionTester(qwen_tester)
    attribution_results = attribution_tester.run_test_suite(num_tests=5)
    print(f"    Completed {len(attribution_results)} tests")
    
    # Run KG poison detection
    print("\n[3] Checking Knowledge Graph for Poisoning...")
    poison_tester = QwenATLASPoisonTester(qwen_tester)
    poison_results = poison_tester.verify_kg_consistency()
    print(f"    Found {poison_results.get('suspicious_count', 0)} suspicious entries")
    
    # Generate report
    print("\n[4] Generating Security Report...")
    evaluator = QwenATLASEvaluator()
    report = evaluator.generate_report(attribution_results, poison_results)
    
    # Save results
    evaluator.save_results(
        {"attribution": attribution_results, "poison": poison_results},
        "security_assessment"
    )
    
    # Print report
    print("\n" + report)
    
    # Save report to file
    report_path = Path("tests/results/security_report.txt")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"\nReport saved to: {report_path}")
    
    print("\n" + "=" * 60)
    print("ASSESSMENT COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    main()
