#!/usr/bin/env python3
"""Batch normalization with limited number of files option"""
import sys
from code_normalizer import CodeNormalizer

def main():
    if len(sys.argv) > 1:
        max_files = int(sys.argv[1])
    else:
        max_files = None

    normalizer = CodeNormalizer()

    input_dir = "data/juliet_modified/1_Ghidra_LLM_CWE78_renamed_v4/bad"
    output_dir = "data/juliet_modified/1_Ghidra_LLM_CWE78_renamed_v4/normalized/gpt5"

    print(f"Input directory: {input_dir}")
    print(f"Output directory: {output_dir}")
    print(f"Using GPT-5 with PROMPT_NORMALIZATION")
    if max_files:
        print(f"Processing only first {max_files} files")
    print("-" * 50)

    import os
    import glob

    # Get C files
    c_files = glob.glob(os.path.join(input_dir, "*.c"))

    if max_files:
        c_files = c_files[:max_files]

    print(f"Will process {len(c_files)} C files")

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Process files
    successful = 0
    total_time = 0.0

    for i, c_file in enumerate(c_files, 1):
        filename = os.path.basename(c_file)
        print(f"Processing {i}/{len(c_files)}: {filename}")

        normalized_code, processing_time = normalizer.normalize_c_file(c_file)

        if normalized_code:
            output_file = os.path.join(output_dir, filename)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(normalized_code)

            successful += 1
            total_time += processing_time
            print(f"  ✓ Success (took {processing_time:.2f}s)")
        else:
            print(f"  ✗ Failed")

    print(f"\nCompleted! {successful}/{len(c_files)} files normalized")
    print(f"Total time: {total_time:.2f}s")
    if successful > 0:
        print(f"Average: {total_time/successful:.2f}s per file")

if __name__ == "__main__":
    main()