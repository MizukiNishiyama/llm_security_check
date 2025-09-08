#!/usr/bin/env python3
"""
Test script to identify anonymization gaps across different CWE types
"""

from pathlib import Path
from anonymize_juliet import JulietAnonymizer
import re

def analyze_anonymization_gaps():
    anonymizer = JulietAnonymizer()
    
    # Test files from different CWE categories
    test_files = [
        "data/juliet/testcases/CWE190_Integer_Overflow/s05/CWE190_Integer_Overflow__unsigned_int_rand_multiply_02.c",
        "data/juliet/testcases/CWE338_Weak_PRNG/CWE338_Weak_PRNG__w32_11.c",
        "data/juliet/testcases/CWE398_Poor_Code_Quality/CWE398_Poor_Code_Quality__empty_if_01.c",
        "data/juliet/testcases/CWE843_Type_Confusion/CWE843_Type_Confusion__char_01.c"
    ]
    
    gaps_found = []
    
    for filepath in test_files:
        print(f"\n{'='*60}")
        print(f"ANALYZING: {Path(filepath).name}")
        print('='*60)
        
        if not Path(filepath).exists():
            print(f"File not found: {filepath}")
            continue
            
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            original = f.read()
        
        # Apply current anonymization
        anonymized = anonymizer.anonymize_content(original)
        
        # Check for remaining hints
        print("REMAINING HINT PATTERNS:")
        
        # Check for various hint patterns that might remain
        hint_patterns = [
            (r'FLAW|FIX|POTENTIAL', 'FLAW/FIX comments'),
            (r'rand\(\)|RAND32\(\)', 'Random function calls'),
            (r'CryptGenRandom|globalReturns', 'Crypto/Test functions'),
            (r'UINT_MAX|INT_MAX', 'Integer limits'),
            (r'overflow|underflow', 'Overflow terminology'),
            (r'Benign.*fixed.*string', 'Test artifacts'),
            (r'INCIDENTAL.*CWE', 'Incidental CWE references'),
            (r'Dead Code', 'Code quality terms'),
            (r'empty if', 'Code quality patterns'),
            (r'Use of.*PRNG|Weak.*PRNG', 'PRNG terminology'),
            (r'multiply.*overflow', 'Specific vulnerability patterns'),
            (r'Ensure.*overflow', 'Prevention patterns'),
            (r'printLine\("Inside.*"\)', 'Descriptive debug strings'),
            (r'printLine\("Hello.*"\)', 'Greeting debug strings'),
            (r'printLine\("Calling.*"\)', 'Function call strings'),
        ]
        
        file_gaps = []
        for pattern, description in hint_patterns:
            matches = re.findall(pattern, anonymized, re.IGNORECASE)
            if matches:
                print(f"  ❌ {description}: {matches[:3]}")  # Show first 3 matches
                file_gaps.append((description, matches))
        
        if not file_gaps:
            print("  ✅ No obvious hints remaining")
        
        gaps_found.extend(file_gaps)
        
        # Show sample of anonymized function
        result = anonymizer.process_file(Path(filepath))
        if result and 'vulnerable' in result.get('functions', {}):
            print(f"\nANONYMIZED VULNERABLE FUNCTION (first 300 chars):")
            print(result['functions']['vulnerable'][:300] + "...")
    
    return gaps_found

def generate_improved_patterns(gaps_found):
    """Generate new anonymization patterns based on found gaps"""
    print(f"\n{'='*60}")
    print("PROPOSED ADDITIONAL PATTERNS")
    print('='*60)
    
    new_patterns = []
    
    # Analyze gaps and suggest patterns
    gap_types = set(gap[0] for gap in gaps_found)
    
    for gap_type in gap_types:
        print(f"\n{gap_type}:")
        
        if "Random function" in gap_type:
            new_patterns.extend([
                (r'\bRAND32\(\)', 'randomFunc()'),
                (r'\brand\(\)', 'randomFunc()'),
            ])
            print("  - r'\\bRAND32\\(\\)', 'randomFunc()'")
            print("  - r'\\brand\\(\\)', 'randomFunc()'")
            
        elif "Crypto/Test function" in gap_type:
            new_patterns.extend([
                (r'\bCryptGenRandom\b', 'secureRandom'),
                (r'\bglobalReturns\w+\b', 'testCondition'),
            ])
            print("  - r'\\bCryptGenRandom\\b', 'secureRandom'")
            print("  - r'\\bglobalReturns\\w+\\b', 'testCondition'")
            
        elif "Integer limits" in gap_type:
            new_patterns.extend([
                (r'\bUINT_MAX\b', 'MAX_VALUE'),
                (r'\bINT_MAX\b', 'MAX_VALUE'),
            ])
            print("  - r'\\bUINT_MAX\\b', 'MAX_VALUE'")
            print("  - r'\\bINT_MAX\\b', 'MAX_VALUE'")
            
        elif "Overflow terminology" in gap_type:
            new_patterns.extend([
                (r'\boverflow\b', 'exceed_limit'),
                (r'\bunderflow\b', 'below_limit'),
            ])
            print("  - r'\\boverflow\\b', 'exceed_limit'")
            print("  - r'\\bunderflow\\b', 'below_limit'")
            
        elif "Test artifacts" in gap_type or "Debug strings" in gap_type:
            new_patterns.extend([
                (r'printLine\(".*?"\)', 'printLine("output")'),
                (r'"Benign.*?"', '"test_string"'),
            ])
            print("  - r'printLine\\(\".*?\"\\)', 'printLine(\"output\")'")
            print("  - r'\"Benign.*?\"', '\"test_string\"'")
            
        elif "Code quality" in gap_type:
            new_patterns.extend([
                (r'\bempty if\b', 'conditional'),
                (r'\bDead Code\b', 'unreachable'),
            ])
            print("  - r'\\bempty if\\b', 'conditional'")
            print("  - r'\\bDead Code\\b', 'unreachable'")
    
    return new_patterns

if __name__ == "__main__":
    print("Testing current anonymization logic for gaps...")
    gaps = analyze_anonymization_gaps()
    
    print(f"\n{'='*60}")
    print(f"SUMMARY: Found {len(gaps)} gap categories")
    print('='*60)
    
    new_patterns = generate_improved_patterns(gaps)
    print(f"\nGenerated {len(new_patterns)} new anonymization patterns.")