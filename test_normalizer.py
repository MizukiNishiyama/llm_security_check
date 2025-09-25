#!/usr/bin/env python3
"""Test script to normalize a single file first"""
from code_normalizer import CodeNormalizer

def test_single_file():
    normalizer = CodeNormalizer()

    test_file = "data/juliet_modified/1_Ghidra_LLM_CWE78_renamed_v4/bad/CWE78_OS_Command_Injection__char_connect_socket_execl_41.c"
    output_dir = "data/juliet_modified/1_Ghidra_LLM_CWE78_renamed_v4/normalized/gpt5"

    print(f"Testing normalization with: {test_file}")

    normalized_code, processing_time = normalizer.normalize_c_file(test_file)

    if normalized_code:
        import os
        os.makedirs(output_dir, exist_ok=True)

        output_file = os.path.join(output_dir, "test_normalized.c")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(normalized_code)

        print(f"✓ Test successful! Normalized code saved to {output_file}")
        print(f"Processing time: {processing_time:.2f} seconds")
        print(f"Output length: {len(normalized_code)} characters")
    else:
        print("✗ Test failed!")

if __name__ == "__main__":
    test_single_file()