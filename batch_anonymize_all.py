#!/usr/bin/env python3
"""
Batch anonymization of all Juliet Test Suite files for basic testing
Processes bad() vs good() functions only and saves to data/juliet_anonymized
"""

import os
import json
from pathlib import Path
from anonymize_juliet import JulietAnonymizer
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

class BatchAnonymizer:
    def __init__(self, source_dir="data/juliet/testcases", output_dir="data/juliet_anonymized"):
        self.source_dir = Path(source_dir)
        self.output_dir = Path(output_dir)
        self.anonymizer = JulietAnonymizer()
        self.stats = {
            'total_files': 0,
            'processed_files': 0,
            'successful_extractions': 0,
            'failed_files': 0,
            'errors': []
        }
        self.lock = threading.Lock()
        
    def setup_output_directory(self):
        """Create output directory structure"""
        print(f"Setting up output directory: {self.output_dir}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create summary directory
        (self.output_dir / "summaries").mkdir(exist_ok=True)
        print(f"✅ Output directory ready: {self.output_dir}")
    
    def find_all_c_files(self):
        """Find all .c files in testcases"""
        print("🔍 Scanning for .c files...")
        c_files = list(self.source_dir.rglob("*.c"))
        
        # Filter out support files
        test_files = [f for f in c_files if "testcasesupport" not in str(f)]
        
        print(f"📊 Found {len(test_files)} test files (excluded {len(c_files) - len(test_files)} support files)")
        return test_files
    
    def process_single_file(self, file_path):
        """Process a single file and return result"""
        try:
            result = self.anonymizer.process_file(file_path)
            
            if not result:
                return {
                    'file': str(file_path),
                    'status': 'failed',
                    'error': 'Failed to process file'
                }
            
            # Extract only bad and good functions for basic testing
            functions = result.get('functions', {})
            vulnerable = functions.get('vulnerable', '')
            secure = functions.get('secure', '')
            
            if not vulnerable or not secure:
                return {
                    'file': str(file_path),
                    'status': 'incomplete',
                    'error': f'Missing functions - vulnerable: {bool(vulnerable)}, secure: {bool(secure)}'
                }
            
            # Create output data for basic testing
            output_data = {
                'original_file': str(file_path),
                'cwe_category': self.extract_cwe_category(file_path),
                'functions': {
                    'vulnerable': {
                        'code': vulnerable,
                        'label': 1,  # 1 = vulnerable
                        'description': 'Function with vulnerability'
                    },
                    'secure': {
                        'code': secure,
                        'label': 0,  # 0 = secure
                        'description': 'Function without vulnerability'
                    }
                },
                'metadata': {
                    'anonymization_version': '2.0',
                    'test_type': 'basic',
                    'processed_at': time.strftime('%Y-%m-%d %H:%M:%S')
                }
            }
            
            return {
                'file': str(file_path),
                'status': 'success',
                'data': output_data
            }
            
        except Exception as e:
            return {
                'file': str(file_path),
                'status': 'error',
                'error': str(e)
            }
    
    def extract_cwe_category(self, file_path):
        """Extract CWE category from file path"""
        parts = file_path.parts
        for part in parts:
            if part.startswith('CWE'):
                return part
        return 'Unknown'
    
    def save_result(self, result_data, file_path):
        """Save individual result to JSON file"""
        # Create relative path for output
        rel_path = file_path.relative_to(self.source_dir)
        output_path = self.output_dir / rel_path.with_suffix('.json')
        
        # Create directory if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save JSON
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result_data, f, indent=2, ensure_ascii=False)
    
    def update_stats(self, result):
        """Thread-safe stats update"""
        with self.lock:
            self.stats['processed_files'] += 1
            
            if result['status'] == 'success':
                self.stats['successful_extractions'] += 1
            else:
                self.stats['failed_files'] += 1
                self.stats['errors'].append({
                    'file': result['file'],
                    'error': result.get('error', 'Unknown error')
                })
    
    def process_all_files(self, max_workers=4):
        """Process all files with multithreading"""
        c_files = self.find_all_c_files()
        self.stats['total_files'] = len(c_files)
        
        print(f"🚀 Starting batch anonymization with {max_workers} workers...")
        print(f"📁 Processing {len(c_files)} files...")
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all jobs
            future_to_file = {
                executor.submit(self.process_single_file, file_path): file_path 
                for file_path in c_files
            }
            
            # Process results as they complete
            for i, future in enumerate(as_completed(future_to_file), 1):
                file_path = future_to_file[future]
                result = future.result()
                
                # Update statistics
                self.update_stats(result)
                
                # Save successful results
                if result['status'] == 'success':
                    self.save_result(result['data'], file_path)
                
                # Progress reporting
                if i % 100 == 0 or i == len(c_files):
                    elapsed = time.time() - start_time
                    rate = i / elapsed if elapsed > 0 else 0
                    print(f"📊 Progress: {i:5}/{len(c_files)} ({i/len(c_files)*100:.1f}%) | "
                          f"Rate: {rate:.1f} files/sec | "
                          f"Success: {self.stats['successful_extractions']}")
        
        elapsed_time = time.time() - start_time
        print(f"⏱️  Total processing time: {elapsed_time:.1f} seconds")
        
        return self.stats
    
    def generate_summary(self, stats):
        """Generate comprehensive summary"""
        summary = {
            'processing_summary': stats,
            'success_rate': stats['successful_extractions'] / stats['total_files'] if stats['total_files'] > 0 else 0,
            'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'output_directory': str(self.output_dir),
            'total_function_pairs': stats['successful_extractions'] * 2  # vulnerable + secure
        }
        
        # Save summary
        summary_path = self.output_dir / "summaries" / "batch_anonymization_summary.json"
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        # Print summary
        print(f"\\n{'='*80}")
        print("BATCH ANONYMIZATION SUMMARY")
        print('='*80)
        print(f"📁 Total files found: {stats['total_files']}")
        print(f"✅ Successfully processed: {stats['successful_extractions']}")
        print(f"❌ Failed to process: {stats['failed_files']}")
        print(f"📊 Success rate: {summary['success_rate']:.1%}")
        print(f"🎯 Total function pairs generated: {summary['total_function_pairs']}")
        print(f"💾 Output directory: {self.output_dir}")
        print(f"📋 Summary saved to: {summary_path}")
        
        if stats['errors']:
            print(f"\\n⚠️  First 5 errors:")
            for error in stats['errors'][:5]:
                file_name = Path(error['file']).name
                print(f"  - {file_name}: {error['error']}")
        
        print('='*80)
        
        return summary

def main():
    print("🎯 Juliet Test Suite Batch Anonymization for Basic Testing")
    print("="*80)
    
    # Initialize batch anonymizer
    batch_anonymizer = BatchAnonymizer()
    
    # Setup output directory
    batch_anonymizer.setup_output_directory()
    
    # Process all files
    print("\\n🔄 Starting batch processing...")
    stats = batch_anonymizer.process_all_files(max_workers=6)
    
    # Generate summary
    print("\\n📊 Generating summary...")
    summary = batch_anonymizer.generate_summary(stats)
    
    print("\\n🎉 Batch anonymization completed!")
    print(f"🎯 Ready for LLM vulnerability testing with {summary['total_function_pairs']} function pairs")

if __name__ == "__main__":
    main()