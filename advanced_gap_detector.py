#!/usr/bin/env python3
"""
Advanced gap detector focusing on Windows APIs, data types, and network patterns
"""

from pathlib import Path
from anonymize_juliet import JulietAnonymizer
import re

def detect_remaining_hints():
    """Detect specific remaining hints across sample files"""
    
    anonymizer = JulietAnonymizer()
    
    # Sample files with different vulnerability patterns
    sample_files = [
        "data/juliet/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_34.c",
        "data/juliet/testcases/CWE121_Stack_Based_Buffer_Overflow/s05/CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memmove_02.c",
        "data/juliet/testcases/CWE134_Uncontrolled_Format_String/s05/CWE134_Uncontrolled_Format_String__wchar_t_file_vprintf_05.c"
    ]
    
    all_hints = {
        'windows_apis': set(),
        'network_functions': set(), 
        'memory_functions': set(),
        'string_functions': set(),
        'file_operations': set(),
        'data_types': set(),
        'constants': set(),
        'status_strings': set(),
        'technical_terms': set()
    }
    
    for filepath in sample_files:
        file_path = Path(filepath)
        if not file_path.exists():
            continue
        
        print(f"\\nAnalyzing: {file_path.name}")
        print("-" * 50)
        
        result = anonymizer.process_file(file_path)
        if not result:
            continue
            
        vulnerable = result['functions'].get('vulnerable', '')
        secure = result['functions'].get('secure', '')
        combined = vulnerable + secure
        
        # Windows API detection
        windows_patterns = [
            r'\\b(LoadLibraryW?|FreeLibrary|GetProcAddress)\\b',
            r'\\b(CreateProcess[AW]?|ShellExecute[AW]?)\\b', 
            r'\\b(RegOpenKey[AW]?|RegSetValue[AW]?)\\b',
            r'\\b(WSAStartup|WSACleanup|WSADATA)\\b',
            r'\\b(HMODULE|HANDLE|DWORD|SOCKET)\\b',
            r'\\b(INVALID_SOCKET|SOCKET_ERROR)\\b'
        ]
        
        for pattern in windows_patterns:
            matches = re.findall(pattern, combined)
            if matches:
                all_hints['windows_apis'].update(matches)
                print(f"  Windows APIs: {matches}")
        
        # Network function detection
        network_patterns = [
            r'\\b(socket|bind|listen|accept|connect)\\b',
            r'\\b(recv|send|recvfrom|sendto)\\b',
            r'\\b(inet_addr|htons|ntohs)\\b',
            r'\\b(sockaddr_in|AF_INET|SOCK_STREAM)\\b'
        ]
        
        for pattern in network_patterns:
            matches = re.findall(pattern, combined)
            if matches:
                all_hints['network_functions'].update(matches)
                print(f"  Network functions: {matches}")
        
        # Memory function detection  
        memory_patterns = [
            r'\\b(malloc|calloc|realloc|free)\\b',
            r'\\b(memmove|memcpy|memset)\\b',
            r'\\b(VirtualAlloc|VirtualFree|HeapAlloc)\\b'
        ]
        
        for pattern in memory_patterns:
            matches = re.findall(pattern, combined)
            if matches:
                all_hints['memory_functions'].update(matches)
                print(f"  Memory functions: {matches}")
        
        # String function detection
        string_patterns = [
            r'\\b(wcscpy|wcscat|wcslen|wcschr)\\b',
            r'\\b(strcpy|strcat|strlen|strchr)\\b', 
            r'\\b(fgetws|fgets|gets)\\b',
            r'\\b(sprintf|snprintf|vprintf)\\b'
        ]
        
        for pattern in string_patterns:
            matches = re.findall(pattern, combined)
            if matches:
                all_hints['string_functions'].update(matches)
                print(f"  String functions: {matches}")
        
        # File operation detection
        file_patterns = [
            r'\\b(fopen|fclose|fread|fwrite)\\b',
            r'\\b(CreateFile[AW]?|ReadFile|WriteFile)\\b',
            r'\\b(FILE|HANDLE)\\b'
        ]
        
        for pattern in file_patterns:
            matches = re.findall(pattern, combined)
            if matches:
                all_hints['file_operations'].update(matches)
                print(f"  File operations: {matches}")
        
        # Data type detection
        type_patterns = [
            r'\\b(wchar_t|TCHAR|LPWSTR|LPSTR)\\b',
            r'\\b(twoIntsStruct|unionType)\\b',
            r'\\b(size_t|ssize_t|DWORD|BYTE)\\b'
        ]
        
        for pattern in type_patterns:
            matches = re.findall(pattern, combined)
            if matches:
                all_hints['data_types'].update(matches)
                print(f"  Data types: {matches}")
        
        # Constant detection
        constant_patterns = [
            r'\\b(FILENAME|IP_ADDRESS|TCP_PORT)\\b',
            r'\\b(MAKEWORD|NO_ERROR|IPPROTO_TCP)\\b',
            r'\\b(staticTrue|staticFalse)\\b',
            r'\\b(GLOBAL_CONST_TRUE|GLOBAL_CONST_FALSE)\\b'
        ]
        
        for pattern in constant_patterns:
            matches = re.findall(pattern, combined)
            if matches:
                all_hints['constants'].update(matches)
                print(f"  Constants: {matches}")
        
        # Status string detection
        status_patterns = [
            r'"[^"]*(?:success|fail|error|login|execution)[^"]*"'
        ]
        
        for pattern in status_patterns:
            matches = re.findall(pattern, combined, re.IGNORECASE)
            if matches:
                all_hints['status_strings'].update(matches)
                print(f"  Status strings: {matches}")
        
        # Technical term detection
        technical_patterns = [
            r'\\b(payload|encoded|decoded|base64)\\b',
            r'\\b(buffer|overflow|underflow)\\b',
            r'\\b(truncation|extension|conversion)\\b'
        ]
        
        for pattern in technical_patterns:
            matches = re.findall(pattern, combined, re.IGNORECASE)
            if matches:
                all_hints['technical_terms'].update(matches)
                print(f"  Technical terms: {matches}")
    
    return all_hints

def generate_comprehensive_patterns(hints):
    """Generate comprehensive patterns for all found hints"""
    
    print(f"\\n{'='*80}")
    print("COMPREHENSIVE PATTERN GENERATION")
    print('='*80)
    
    patterns = {
        'function_patterns': [],
        'variable_patterns': [],
        'string_patterns': [],
        'constant_patterns': []
    }
    
    # Windows API patterns
    if hints['windows_apis']:
        print(f"\\n🪟 WINDOWS API PATTERNS ({len(hints['windows_apis'])} unique):")
        for i, api in enumerate(sorted(hints['windows_apis']), 1):
            new_name = f"winAPI_{i}"
            patterns['function_patterns'].append((f'\\\\b{re.escape(api)}\\\\b', new_name))
            print(f"   {api} -> {new_name}")
    
    # Network function patterns  
    if hints['network_functions']:
        print(f"\\n🌐 NETWORK FUNCTION PATTERNS ({len(hints['network_functions'])} unique):")
        for i, func in enumerate(sorted(hints['network_functions']), 1):
            new_name = f"netFunc_{i}"
            patterns['function_patterns'].append((f'\\\\b{re.escape(func)}\\\\b', new_name))
            print(f"   {func} -> {new_name}")
    
    # Memory function patterns
    if hints['memory_functions']:
        print(f"\\n🧠 MEMORY FUNCTION PATTERNS ({len(hints['memory_functions'])} unique):")
        for i, func in enumerate(sorted(hints['memory_functions']), 1):
            new_name = f"memFunc_{i}"
            patterns['function_patterns'].append((f'\\\\b{re.escape(func)}\\\\b', new_name))
            print(f"   {func} -> {new_name}")
    
    # String function patterns
    if hints['string_functions']:
        print(f"\\n📝 STRING FUNCTION PATTERNS ({len(hints['string_functions'])} unique):")
        for i, func in enumerate(sorted(hints['string_functions']), 1):
            new_name = f"strFunc_{i}"
            patterns['function_patterns'].append((f'\\\\b{re.escape(func)}\\\\b', new_name))
            print(f"   {func} -> {new_name}")
    
    # Data type patterns
    if hints['data_types']:
        print(f"\\n🏷️  DATA TYPE PATTERNS ({len(hints['data_types'])} unique):")
        for i, dtype in enumerate(sorted(hints['data_types']), 1):
            new_name = f"DataType_{i}"
            patterns['variable_patterns'].append((f'\\\\b{re.escape(dtype)}\\\\b', new_name))
            print(f"   {dtype} -> {new_name}")
    
    # Constant patterns
    if hints['constants']:
        print(f"\\n🔢 CONSTANT PATTERNS ({len(hints['constants'])} unique):")
        for i, const in enumerate(sorted(hints['constants']), 1):
            new_name = f"CONST_{i}"
            patterns['constant_patterns'].append((f'\\\\b{re.escape(const)}\\\\b', new_name))
            print(f"   {const} -> {new_name}")
    
    # Status string patterns
    if hints['status_strings']:
        print(f"\\n💬 STATUS STRING PATTERNS ({len(hints['status_strings'])} unique):")
        for i, string in enumerate(sorted(hints['status_strings']), 1):
            new_name = f'"status_{i}"'
            patterns['string_patterns'].append((re.escape(string), new_name))
            print(f"   {string} -> {new_name}")
    
    return patterns

if __name__ == "__main__":
    print("Advanced gap detection for remaining hints...")
    
    hints = detect_remaining_hints()
    
    # Summary
    total_hints = sum(len(h) for h in hints.values())
    print(f"\\n{'='*80}")
    print(f"TOTAL UNIQUE HINTS FOUND: {total_hints}")
    for category, items in hints.items():
        if items:
            print(f"  {category}: {len(items)} items")
    print('='*80)
    
    # Generate patterns
    comprehensive_patterns = generate_comprehensive_patterns(hints)
    
    total_patterns = sum(len(p) for p in comprehensive_patterns.values())
    print(f"\\nGenerated {total_patterns} comprehensive anonymization patterns.")