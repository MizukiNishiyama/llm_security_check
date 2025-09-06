#!/usr/bin/env python3
"""
Juliet Test Suite Code Anonymizer
LLMによる脆弱性判定のため、コードからヒント情報を除去する
"""

import re
import os
import json
from pathlib import Path
from typing import Dict, List, Tuple

class JulietAnonymizer:
    def __init__(self):
        # 除去対象のコメントパターン
        self.comment_patterns = [
            r'/\*\s*FLAW:.*?\*/',  # /* FLAW: ... */
            r'/\*\s*FIX:.*?\*/',   # /* FIX: ... */
            r'/\*\s*POTENTIAL FLAW:.*?\*/',  # /* POTENTIAL FLAW: ... */
            r'//\s*FLAW:.*',       # // FLAW: ...
            r'//\s*FIX:.*',        # // FIX: ...
            r'\*\s*BadSource:.*',     # * BadSource: ...
            r'\*\s*GoodSource:.*',    # * GoodSource: ...
            r'\*\s*BadSink:.*',       # * BadSink: ...
            r'\*\s*GoodSink:.*',      # * GoodSink: ...
            r'\*\s*Sink:.*',          # * Sink: ...
            r'CWE-?\d+:.*',           # CWE-15: ... or CWE15: ...
            r'Filename:.*CWE.*\.c',   # Filename: CWE...
            r'Label Definition File:.*\.xml', # Label Definition File: ...
        ]
        
        # 関数名匿名化パターン
        self.function_patterns = [
            (r'(\w+)_bad\b', r'\1_func1'),      # _bad -> _func1
            (r'(\w+)_good\b', r'\1_func2'),     # _good -> _func2  
            (r'goodG2B\b', 'functionA'),        # goodG2B -> functionA
            (r'goodB2G\b', 'functionB'),        # goodB2G -> functionB
        ]
    
    def anonymize_content(self, content: str) -> str:
        """コード内容を匿名化"""
        anonymized = content
        
        # 1. ヒント的なコメントを除去
        for pattern in self.comment_patterns:
            anonymized = re.sub(pattern, '', anonymized, flags=re.DOTALL)
        
        # 2. 関数名を匿名化
        for old_pattern, new_pattern in self.function_patterns:
            anonymized = re.sub(old_pattern, new_pattern, anonymized)
        
        # 3. 余分な空行を削除
        anonymized = re.sub(r'\n\s*\n\s*\n', '\n\n', anonymized)
        
        return anonymized
    
    def extract_function_body(self, lines: List[str], start_idx: int) -> str:
        """指定開始位置から関数本体を抽出"""
        brace_count = 0
        function_lines = []
        
        for i in range(start_idx, len(lines)):
            line = lines[i]
            function_lines.append(line)
            brace_count += line.count('{') - line.count('}')
            if brace_count == 0 and '}' in line:
                break
        
        return '\n'.join(function_lines[:-1]).strip()  # 最後の}を除く

    def extract_functions(self, content: str) -> Dict[str, str]:
        """bad関数とgood関数を個別に抽出"""
        functions = {}
        lines = content.split('\n')
        
        # bad関数の抽出
        for i, line in enumerate(lines):
            if '_bad()' in line and 'void' in line:
                functions['vulnerable'] = self.extract_function_body(lines, i + 1)
                break
        
        # good関数とgoodG2B関数の抽出
        good_found = False
        goodG2B_content = ""
        
        # まずgoodG2B関数を探す
        for i, line in enumerate(lines):
            if 'goodG2B()' in line and ('static void' in line or 'void goodG2B' in line):
                goodG2B_content = self.extract_function_body(lines, i + 1)
                break
        
        # good関数を探す
        for i, line in enumerate(lines):
            if '_good()' in line and 'void' in line:
                good_content = self.extract_function_body(lines, i + 1)
                # goodG2B()を呼んでいるだけの場合は、goodG2Bの内容を使用
                if 'goodG2B()' in good_content and goodG2B_content:
                    functions['secure'] = goodG2B_content
                else:
                    functions['secure'] = good_content
                break
                
        return functions
    
    def process_file(self, filepath: Path) -> Dict:
        """単一ファイルを処理"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                original_content = f.read()
            
            # 匿名化処理
            anonymized_content = self.anonymize_content(original_content)
            
            # 関数個別抽出
            functions = self.extract_functions(original_content)
            
            result = {
                'original_file': str(filepath),
                'anonymized_full': anonymized_content,
                'functions': {}
            }
            
            # 各関数も匿名化
            for func_type, func_content in functions.items():
                result['functions'][func_type] = self.anonymize_content(func_content)
            
            return result
            
        except Exception as e:
            print(f"Error processing {filepath}: {e}")
            return None

def main():
    anonymizer = JulietAnonymizer()
    
    # テスト用サンプルファイル
    sample_file = Path("data/juliet/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_01.c")
    
    if sample_file.exists():
        print("Processing sample file...")
        result = anonymizer.process_file(sample_file)
        
        if result:
            # 結果出力
            print("=== ANONYMIZED FULL CODE ===")
            print(result['anonymized_full'][:1000] + "...")
            
            print("\n=== EXTRACTED FUNCTIONS ===")
            for func_type, func_content in result['functions'].items():
                print(f"\n--- {func_type.upper()} FUNCTION ---")
                print(func_content[:500] + "...")
    else:
        print(f"Sample file not found: {sample_file}")

if __name__ == "__main__":
    main()