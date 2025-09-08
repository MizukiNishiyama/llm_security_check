#!/usr/bin/env python3
"""
Batch validation of anonymization quality across multiple files
"""

from pathlib import Path
from anonymize_juliet import JulietAnonymizer
import random
import re

def batch_validate_anonymization():
    """Test anonymization across diverse CWE files"""
    
    anonymizer = JulietAnonymizer()
    
    # Get comprehensive sample across different CWE types
    cwe_dirs = list(Path("data/juliet/testcases").glob("CWE*"))
    random.shuffle(cwe_dirs)
    
    sample_files = []
    for cwe_dir in cwe_dirs[:15]:  # Test 15 different CWE types
        c_files = list(cwe_dir.rglob("*.c"))
        if c_files:
            sample_files.append(random.choice(c_files))
    
    print(f"Batch testing {len(sample_files)} files from different CWE categories...")
    print("=" * 80)
    
    results = {
        'total_files': len(sample_files),
        'successful_anonymizations': 0,
        'remaining_hints': {},
        'anonymization_quality': []
    }
    
    # Test patterns that should be anonymized
    hint_patterns = {
        'api_functions': r'\\b(malloc|free|strcpy|LoadLibrary|CreateProcess|socket|recv)\\b',
        'windows_types': r'\\b(HMODULE|HANDLE|DWORD|SOCKET|WSADATA)\\b', 
        'constants': r'\\b(INVALID_SOCKET|NO_ERROR|FILENAME|IP_ADDRESS)\\b',
        'status_strings': r'"[^"]*(?:success|fail|error|login)[^"]*"',
        'debug_strings': r'"(?:Hello|Inside|Calling|Finished)[^"]*"',
        'tech_terms': r'\\b(?:overflow|buffer|payload|encoded)\\b'
    }
    
    for i, file_path in enumerate(sample_files, 1):
        print(f"\\n[{i:2}/{len(sample_files)}] {file_path.name[:60]}")
        print("-" * 70)
        
        try:
            result = anonymizer.process_file(file_path)
            if not result:
                print("  ❌ Failed to process file")
                continue
                
            vulnerable = result['functions'].get('vulnerable', '')
            secure = result['functions'].get('secure', '')
            combined = vulnerable + secure
            
            if not combined.strip():
                print("  ⚠️  No functions extracted")
                continue
            
            results['successful_anonymizations'] += 1
            
            # Quality assessment
            quality_score = assess_anonymization_quality(combined, hint_patterns)
            results['anonymization_quality'].append(quality_score)
            
            print(f"  📊 Anonymization quality: {quality_score:.1%}")
            
            # Show sample of anonymized code
            print(f"  📝 Sample: {combined[:100].replace(chr(10), ' ')[:80]}...")
            
            # Track remaining hints
            for category, pattern in hint_patterns.items():
                matches = re.findall(pattern, combined, re.IGNORECASE)
                if matches:
                    if category not in results['remaining_hints']:
                        results['remaining_hints'][category] = set()
                    results['remaining_hints'][category].update(matches[:3])  # Limit to avoid spam
                    print(f"  🔍 {category}: {len(matches)} matches")
            
        except Exception as e:
            print(f"  ❌ Error: {e}")
    
    return results

def assess_anonymization_quality(code, hint_patterns):
    """Assess anonymization quality (0.0 = many hints, 1.0 = no hints)"""
    
    total_hints = 0
    for pattern in hint_patterns.values():
        matches = re.findall(pattern, code, re.IGNORECASE)
        total_hints += len(matches)
    
    # Quality score based on hint density
    code_length = len(code.split())
    if code_length == 0:
        return 0.0
    
    hint_density = total_hints / code_length
    quality_score = max(0.0, 1.0 - (hint_density * 10))  # Scale factor
    
    return quality_score

def generate_summary_report(results):
    """Generate comprehensive summary"""
    
    print(f"\\n{'=' * 80}")
    print("BATCH ANONYMIZATION VALIDATION REPORT")
    print('=' * 80)
    
    print(f"Files processed: {results['total_files']}")
    print(f"Successful anonymizations: {results['successful_anonymizations']}")
    
    if results['anonymization_quality']:
        avg_quality = sum(results['anonymization_quality']) / len(results['anonymization_quality'])
        print(f"Average anonymization quality: {avg_quality:.1%}")
        
        # Quality distribution
        excellent = sum(1 for q in results['anonymization_quality'] if q >= 0.9)
        good = sum(1 for q in results['anonymization_quality'] if 0.7 <= q < 0.9)
        fair = sum(1 for q in results['anonymization_quality'] if 0.5 <= q < 0.7)
        poor = sum(1 for q in results['anonymization_quality'] if q < 0.5)
        
        print(f"\\nQuality distribution:")
        print(f"  Excellent (≥90%): {excellent} files")
        print(f"  Good (70-89%):    {good} files")
        print(f"  Fair (50-69%):    {fair} files")
        print(f"  Poor (<50%):      {poor} files")
    
    print(f"\\nRemaining hint categories:")
    for category, hints in results['remaining_hints'].items():
        print(f"  {category}: {len(hints)} unique patterns")
        for hint in sorted(hints)[:3]:  # Show first 3
            print(f"    - {hint}")
    
    # Recommendations
    print(f"\\n📋 RECOMMENDATIONS:")
    if avg_quality >= 0.9:
        print("  ✅ Excellent anonymization quality achieved!")
    elif avg_quality >= 0.7:
        print("  ✅ Good anonymization quality. Minor improvements possible.")
    elif avg_quality >= 0.5:
        print("  ⚠️  Fair anonymization. Consider additional patterns.")
    else:
        print("  ❌ Poor anonymization. Significant improvements needed.")
    
    if results['remaining_hints']:
        print(f"  📈 Focus on improving: {', '.join(results['remaining_hints'].keys())}")

if __name__ == "__main__":
    results = batch_validate_anonymization()
    generate_summary_report(results)