#!/usr/bin/env python3
"""
More detailed gap analysis - looking at actual remaining content
"""

from pathlib import Path
from anonymize_juliet import JulietAnonymizer

def detailed_analysis():
    anonymizer = JulietAnonymizer()
    
    # Test files
    test_files = [
        "data/juliet/testcases/CWE190_Integer_Overflow/s05/CWE190_Integer_Overflow__unsigned_int_rand_multiply_02.c",
        "data/juliet/testcases/CWE338_Weak_PRNG/CWE338_Weak_PRNG__w32_11.c",
        "data/juliet/testcases/CWE398_Poor_Code_Quality/CWE398_Poor_Code_Quality__empty_if_01.c",
    ]
    
    problematic_patterns = []
    
    for filepath in test_files:
        print(f"\n{'='*60}")
        print(f"DETAILED ANALYSIS: {Path(filepath).name}")
        print('='*60)
        
        if not Path(filepath).exists():
            continue
            
        result = anonymizer.process_file(Path(filepath))
        if not result:
            continue
        
        vulnerable_func = result['functions'].get('vulnerable', '')
        secure_func = result['functions'].get('secure', '')
        
        print("VULNERABLE FUNCTION:")
        print(vulnerable_func[:500])
        print("\n" + "-"*40)
        print("SECURE FUNCTION:")
        print(secure_func[:500])
        
        # Analyze what might still give away the vulnerability type
        print(f"\nPOTENTIAL HINTS ANALYSIS:")
        
        # Check for function names that might hint at vulnerability
        if 'RAND32()' in vulnerable_func or 'rand()' in vulnerable_func:
            print("  ❌ Random function calls remain: RAND32(), rand()")
            problematic_patterns.append("Random function calls")
            
        if 'globalReturnsTrue()' in vulnerable_func or 'globalReturnsFalse()' in vulnerable_func:
            print("  ❌ Test utility functions remain: globalReturns*()")
            problematic_patterns.append("Test utility functions")
        
        if 'printLine("Inside' in vulnerable_func or 'printLine("Hello' in vulnerable_func:
            print("  ❌ Descriptive print statements remain")
            problematic_patterns.append("Descriptive print statements")
            
        if 'data * 2' in vulnerable_func:
            print("  ❌ Specific mathematical operations that hint at overflow")
            problematic_patterns.append("Specific mathematical operations")
            
        if 'if (x == 0)' in vulnerable_func and '{\n        }' in vulnerable_func:
            print("  ❌ Empty if block pattern visible")
            problematic_patterns.append("Empty if block pattern")
            
        if 'unsigned int' in vulnerable_func:
            print("  ❌ Specific type usage that hints at overflow")
            problematic_patterns.append("Specific type hints")
            
        if 'data > 0' in vulnerable_func:
            print("  ❌ Boundary checking patterns")
            problematic_patterns.append("Boundary checking patterns")
    
    return problematic_patterns

def generate_enhanced_patterns(issues):
    """Generate comprehensive anonymization patterns"""
    print(f"\n{'='*60}")
    print("ENHANCED ANONYMIZATION PATTERNS NEEDED")
    print('='*60)
    
    new_patterns = {
        'comment_patterns': [],
        'function_patterns': [],
        'variable_patterns': [],
        'string_patterns': []
    }
    
    if "Random function calls" in issues:
        print("\n1. RANDOM FUNCTION ANONYMIZATION:")
        new_patterns['function_patterns'].extend([
            (r'\bRAND32\(\)', 'getRandomValue()'),
            (r'\brand\(\)', 'getRandomValue()'),
        ])
        print("   - RAND32() -> getRandomValue()")
        print("   - rand() -> getRandomValue()")
    
    if "Test utility functions" in issues:
        print("\n2. TEST UTILITY FUNCTION ANONYMIZATION:")
        new_patterns['function_patterns'].extend([
            (r'\bglobalReturnsTrue\(\)', 'checkCondition()'),
            (r'\bglobalReturnsFalse\(\)', 'checkCondition()'),
        ])
        print("   - globalReturnsTrue() -> checkCondition()")
        print("   - globalReturnsFalse() -> checkCondition()")
    
    if "Descriptive print statements" in issues:
        print("\n3. DEBUG STRING ANONYMIZATION:")
        new_patterns['string_patterns'].extend([
            (r'"Inside the .*?"', '"debug_message"'),
            (r'"Hello from .*?"', '"status_message"'),
            (r'"Calling .*?"', '"action_message"'),
            (r'"Finished .*?"', '"completion_message"'),
        ])
        print("   - All descriptive strings -> generic messages")
    
    if "Specific mathematical operations" in issues:
        print("\n4. MATHEMATICAL OPERATION PATTERNS:")
        print("   - Consider anonymizing specific operations like 'data * 2'")
        print("   - But this might be too aggressive and break semantics")
    
    if "Empty if block pattern" in issues:
        print("\n5. CODE STRUCTURE PATTERNS:")
        print("   - Empty if blocks are structural, hard to anonymize")
        print("   - This might be acceptable as it shows code logic")
    
    if "Specific type hints" in issues:
        print("\n6. TYPE ANONYMIZATION:")
        new_patterns['variable_patterns'].extend([
            (r'\bunsigned int\b', 'uint_type'),
            (r'\bsigned int\b', 'int_type'),
        ])
        print("   - unsigned int -> uint_type")
        print("   - signed int -> int_type")
    
    if "Boundary checking patterns" in issues:
        print("\n7. BOUNDARY CHECK PATTERNS:")
        print("   - 'data > 0' type checks are semantic, consider preserving")
        print("   - These show algorithm logic, not necessarily vulnerability hints")
    
    return new_patterns

if __name__ == "__main__":
    print("Running detailed gap analysis...")
    issues = detailed_analysis()
    
    print(f"\n{'='*60}")
    print(f"ISSUES FOUND: {len(set(issues))}")
    for issue in set(issues):
        print(f"  - {issue}")
    print('='*60)
    
    enhanced_patterns = generate_enhanced_patterns(set(issues))
    
    total_new_patterns = sum(len(v) for v in enhanced_patterns.values())
    print(f"\nGenerated {total_new_patterns} new patterns across {len(enhanced_patterns)} categories.")