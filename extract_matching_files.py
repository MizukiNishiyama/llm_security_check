#!/usr/bin/env python3
import os
import shutil
import glob
from pathlib import Path

def extract_matching_files():
    # Get all C files from juliet_modified directory
    c_files_pattern = "data/juliet_modified/1_Ghidra_LLM_CWE78_renamed_v4/bad/*.c"
    c_files = glob.glob(c_files_pattern)

    # Extract just the filenames (without extension and path)
    c_filenames = []
    for c_file in c_files:
        filename = os.path.basename(c_file)
        filename_without_ext = os.path.splitext(filename)[0]
        c_filenames.append(filename_without_ext)

    print(f"Found {len(c_filenames)} C files in juliet_modified directory")

    # Search for corresponding JSON files in juliet_anonymized
    json_files_pattern = "data/juliet_anonymized/CWE78_OS_Command_Injection/**/*.json"
    json_files = glob.glob(json_files_pattern, recursive=True)

    print(f"Found {len(json_files)} JSON files in juliet_anonymized directory")

    # Create output directory
    output_dir = "data/juliet_anonymized_extracted/v4"
    os.makedirs(output_dir, exist_ok=True)

    matched_files = []
    copied_count = 0

    # Find matching JSON files
    for json_file in json_files:
        json_filename = os.path.basename(json_file)
        json_filename_without_ext = os.path.splitext(json_filename)[0]

        # Check if this JSON file corresponds to any of the C files
        if json_filename_without_ext in c_filenames:
            # Copy the JSON file to the output directory
            output_path = os.path.join(output_dir, json_filename)
            shutil.copy2(json_file, output_path)
            matched_files.append((json_file, output_path))
            copied_count += 1
            print(f"Copied: {json_filename}")

    print(f"\nExtraction completed!")
    print(f"Total C files: {len(c_filenames)}")
    print(f"Total JSON files searched: {len(json_files)}")
    print(f"Matched and copied files: {copied_count}")

    if copied_count < len(c_filenames):
        print(f"Warning: {len(c_filenames) - copied_count} C files have no corresponding JSON files")

        # Show which C files don't have matches
        matched_basenames = {os.path.splitext(os.path.basename(match[1]))[0] for match in matched_files}
        unmatched = set(c_filenames) - matched_basenames
        if unmatched:
            print("Unmatched C files:")
            for filename in sorted(unmatched):
                print(f"  - {filename}")

if __name__ == "__main__":
    extract_matching_files()