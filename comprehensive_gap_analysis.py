#!/usr/bin/env python3
"""
Comprehensive gap analysis across diverse CWE categories
"""

from pathlib import Path
from anonymize_juliet import JulietAnonymizer
import re
import random

def sample_diverse_files():
    """Sample files from different CWE categories"""
    
    # Different vulnerability categories for comprehensive testing
    cwe_dirs = [
        "CWE114_Process_Control",
        "CWE121_Stack_Based_Buffer_Overflow", 
        "CWE134_Uncontrolled_Format_String",
        "CWE176_Improper_Handling_of_Unicode_Encoding",
        "CWE188_Reliance_on_Data_Memory_Layout",
        "CWE194_Unexpected_Sign_Extension",
        "CWE222_Truncation_of_Security_Relevant_Information",
        "CWE506_Embedded_Malicious_Code",
        "CWE761_Free_Pointer_Not_at_Start_of_Buffer",
        "CWE364_Signal_Handler_Race_Condition"
    ]
    
    sample_files = []
    
    for cwe_dir in cwe_dirs:
        cwe_path = Path(f"data/juliet/testcases/{cwe_dir}")
        if cwe_path.exists():
            c_files = list(cwe_path.rglob("*.c"))
            if c_files:
                # Take first file from each category
                sample_files.append(c_files[0])
                print(f"Selected: {c_files[0]}")
    
    return sample_files

def analyze_comprehensive_gaps():
    """Analyze gaps across diverse vulnerability types"""
    
    anonymizer = JulietAnonymizer()
    sample_files = sample_diverse_files()
    
    all_gaps = {}
    hint_categories = {
        'function_calls': [],
        'variable_names': [],
        'string_literals': [],
        'type_names': [],
        'macro_constants': [],
        'api_names': [],
        'domain_terms': []
    }
    
    print(f"\n{'='*80}")
    print(f"COMPREHENSIVE ANONYMIZATION GAP ANALYSIS")
    print(f"Analyzing {len(sample_files)} files from different CWE categories")
    print('='*80)
    
    for i, filepath in enumerate(sample_files[:8], 1):  # Limit to 8 for readability
        print(f"\n[{i}/8] ANALYZING: {filepath.name}")
        print("-" * 60)
        
        if not filepath.exists():
            continue
        
        try:
            result = anonymizer.process_file(filepath)
            if not result:
                continue
            
            vulnerable_func = result['functions'].get('vulnerable', '')
            secure_func = result['functions'].get('secure', '')
            
            print(f"Vulnerable function preview:")
            print(vulnerable_func[:200] + "..." if len(vulnerable_func) > 200 else vulnerable_func)
            print()
            
            # Advanced pattern detection
            gaps_found = detect_advanced_patterns(vulnerable_func, secure_func, filepath.name)
            
            for category, patterns in gaps_found.items():
                if patterns:
                    hint_categories[category].extend(patterns)
                    print(f"  📍 {category}: {patterns[:3]}")  # Show first 3
            
        except Exception as e:
            print(f"  ❌ Error processing {filepath.name}: {e}")
    
    return hint_categories

def detect_advanced_patterns(vulnerable_func, secure_func, filename):
    """Detect advanced patterns that reveal vulnerability hints"""
    
    gaps = {
        'function_calls': [],
        'variable_names': [], 
        'string_literals': [],
        'type_names': [],
        'macro_constants': [],
        'api_names': [],
        'domain_terms': []
    }
    
    text = vulnerable_func + secure_func
    
    # Function calls that hint at vulnerability type
    function_patterns = [
        r'\\b(malloc|calloc|realloc|free)\\b',          # Memory management
        r'\\b(strcpy|strcat|sprintf|gets)\\b',          # Unsafe string functions  
        r'\\b(printf|fprintf|snprintf)\\b',             # Format string functions
        r'\\b(recv|send|socket|connect)\\b',            # Network functions
        r'\\b(CreateProcess|ShellExecute)\\b',          # Process control
        r'\\b(fopen|fread|fwrite)\\b',                  # File operations
        r'\\b(pthread_|CreateThread)\\b',               # Threading
        r'\\b(Signal|sigaction)\\b',                    # Signal handling
    ]
    
    for pattern in function_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            gaps['function_calls'].extend(matches)
    
    # Variable names that hint at purpose
    variable_patterns = [
        r'\\b(buffer|buf|data|input|output)\\d*\\b',    # Generic data containers
        r'\\b(size|len|length|count|num)\\w*\\b',       # Size-related variables
        r'\\b(ptr|pointer|addr|address)\\w*\\b',        # Pointer variables
        r'\\b(fd|file|handle|socket)\\w*\\b',           # Resource handles
        r'\\b(src|dest|source|destination)\\w*\\b',     # Source/destination
        r'\\b(cmd|command|arg|argv)\\w*\\b',            # Command-related
    ]
    
    for pattern in variable_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            gaps['variable_names'].extend(matches)
    
    # String literals that give away context
    string_patterns = [
        r'"[^"]*(?:error|fail|success|ok)[^"]*"',       # Status messages
        r'"[^"]*(?:buffer|memory|heap|stack)[^"]*"',    # Memory-related strings
        r'"[^"]*(?:file|path|directory)[^"]*"',         # File-related strings
        r'"[^"]*(?:user|admin|root)[^"]*"',             # User-related strings
        r'"[^"]*(?:password|key|secret)[^"]*"',         # Security-related strings
    ]
    
    for pattern in string_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            gaps['string_literals'].extend(matches)
    
    # Type names that hint at vulnerability
    type_patterns = [
        r'\\b(char|wchar_t|TCHAR)\\s*\\*',             # String types
        r'\\b(FILE|HANDLE|SOCKET)\\b',                  # Resource types
        r'\\b(DWORD|QWORD|size_t|ssize_t)\\b',        # Size types
        r'\\b(LPSTR|LPWSTR|LPTSTR)\\b',                # Windows string types
    ]
    
    for pattern in type_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            gaps['type_names'].extend(matches)
    
    # Macro constants
    macro_patterns = [
        r'\\b(MAX_PATH|BUFSIZ|_MAX_\\w+)\\b',          # Size constants
        r'\\b(NULL|TRUE|FALSE)\\b',                     # Common constants
        r'\\b(EOF|INVALID_\\w+)\\b',                    # Error constants
    ]
    
    for pattern in macro_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            gaps['macro_constants'].extend(matches)
    
    # API function names from different domains
    api_patterns = [
        r'\\b(GetLastError|SetLastError)\\b',          # Windows error APIs
        r'\\b(MessageBox|GetWindowText)\\b',           # Windows UI APIs  
        r'\\b(RegOpenKey|RegSetValue)\\b',             # Windows registry APIs
        r'\\b(bind|listen|accept)\\b',                 # Socket APIs
    ]
    
    for pattern in api_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            gaps['api_names'].extend(matches)
    
    return gaps

def generate_advanced_patterns(hint_categories):
    """Generate patterns based on comprehensive analysis"""
    
    print(f"\n{'='*80}")
    print("ADVANCED ANONYMIZATION PATTERNS NEEDED")
    print('='*80)
    
    new_patterns = {
        'function_patterns': [],
        'variable_patterns': [],
        'string_patterns': [],
        'type_patterns': [],
        'macro_patterns': []
    }
    
    # Function anonymization
    if hint_categories['function_calls']:
        unique_functions = list(set(hint_categories['function_calls']))
        print(f"\n🔧 FUNCTION ANONYMIZATION ({len(unique_functions)} unique):")
        for i, func in enumerate(unique_functions[:10], 1):  # Show first 10
            generic_name = f"apiCall{i}"
            new_patterns['function_patterns'].append((f'\\\\b{re.escape(func)}\\\\b', generic_name))
            print(f"   {func} -> {generic_name}")
    
    # Variable anonymization  
    if hint_categories['variable_names']:
        unique_vars = list(set(hint_categories['variable_names']))
        print(f"\n📝 VARIABLE ANONYMIZATION ({len(unique_vars)} unique):")
        for i, var in enumerate(unique_vars[:10], 1):
            generic_name = f"var{i}"
            new_patterns['variable_patterns'].append((f'\\\\b{re.escape(var)}\\\\b', generic_name))
            print(f"   {var} -> {generic_name}")
    
    # String anonymization
    if hint_categories['string_literals']:
        unique_strings = list(set(hint_categories['string_literals']))
        print(f"\n💬 STRING ANONYMIZATION ({len(unique_strings)} unique):")
        for i, string in enumerate(unique_strings[:5], 1):
            generic_string = f'"message_{i}"'
            escaped_string = re.escape(string)
            new_patterns['string_patterns'].append((escaped_string, generic_string))
            print(f"   {string[:30]}... -> {generic_string}")
    
    # Type anonymization
    if hint_categories['type_names']:
        unique_types = list(set(hint_categories['type_names']))
        print(f"\n🏷️  TYPE ANONYMIZATION ({len(unique_types)} unique):")
        for i, type_name in enumerate(unique_types[:8], 1):
            generic_type = f"type_{i}"
            new_patterns['type_patterns'].append((f'\\\\b{re.escape(type_name)}\\\\b', generic_type))
            print(f"   {type_name} -> {generic_type}")
    
    # Macro/constant anonymization
    if hint_categories['macro_constants']:
        unique_macros = list(set(hint_categories['macro_constants']))
        print(f"\n🔢 MACRO ANONYMIZATION ({len(unique_macros)} unique):")
        for i, macro in enumerate(unique_macros[:8], 1):
            generic_macro = f"CONST_{i}"
            new_patterns['macro_patterns'].append((f'\\\\b{re.escape(macro)}\\\\b', generic_macro))
            print(f"   {macro} -> {generic_macro}")
    
    return new_patterns

if __name__ == "__main__":
    print("Running comprehensive gap analysis across diverse CWE categories...")
    
    hint_categories = analyze_comprehensive_gaps()
    
    # Summary
    total_hints = sum(len(hints) for hints in hint_categories.values())
    print(f"\n{'='*80}")
    print(f"SUMMARY: Found {total_hints} total hint patterns")
    for category, hints in hint_categories.items():
        if hints:
            unique_count = len(set(hints))
            print(f"  {category}: {unique_count} unique patterns")
    print('='*80)
    
    # Generate patterns
    advanced_patterns = generate_advanced_patterns(hint_categories)
    
    total_new = sum(len(patterns) for patterns in advanced_patterns.values())
    print(f"\nGenerated {total_new} new advanced anonymization patterns.")