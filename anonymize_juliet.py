#!/usr/bin/env python3
"""
Juliet Test Suite Code Anonymizer
LLMによる脆弱性判定のため、コードからヒント情報を除去する

匿名化ロジック詳細:
=================

1. コメント除去パターン (comment_patterns):
   - FLAW/FIX関連のコメント除去
   - BadSource/GoodSource/Sink情報の除去  
   - CWE番号と脆弱性種別名の除去
   - ファイル情報とテンプレート情報の除去
   - 全コメントの完全除去

2. 関数名匿名化パターン (function_patterns):
   - _bad -> _func1, _good -> _func2
   - goodG2B -> functionA, goodB2G -> functionB

3. 変数名匿名化パターン (variable_patterns):
   - 型を示唆する変数名の中性化 (charBuffer -> buffer1)
   - セキュリティ関連変数名の一般化 (password -> userInput)
   - データ型の匿名化 (unsigned int -> uint_type)

4. 文字列パターン匿名化 (string_patterns):
   - デバッグメッセージの一般化 ("Inside the ..." -> "debug_message")
   - ステータスメッセージの統一化 ("success/fail/error" -> 汎用メッセージ)

5. 定数パターン匿名化 (constant_patterns):
   - ネットワーク定数の匿名化 (INVALID_SOCKET -> INVALID_HANDLE)
   - システム定数の匿名化 (FILENAME -> FILE_PATH)

6. 処理フロー:
   a. ヒント的コメントの段階的除去
   b. 関数名の匿名化 (API関数、ネットワーク・メモリ関数含む)
   c. 変数名・型名の匿名化 (Windows型、文字列型含む)
   d. 文字列パターンの匿名化 (エラー・ステータスメッセージ)
   e. 定数パターンの匿名化
   f. 空行整理

5. 関数抽出:
   - 波括弧カウンティングによる正確な関数本体抽出
   - goodG2B()間接呼び出しの解決
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
            # 明示的な脆弱性ヒント
            r'/\*\s*FLAW:.*?\*/',  # /* FLAW: ... */
            r'/\*\s*FIX:.*?\*/',   # /* FIX: ... */
            r'/\*\s*POTENTIAL FLAW:.*?\*/',  # /* POTENTIAL FLAW: ... */
            r'//\s*FLAW:.*',       # // FLAW: ...
            r'//\s*FIX:.*',        # // FIX: ...
            
            # Source/Sink情報
            r'\*\s*BadSource:.*',     # * BadSource: ...
            r'\*\s*GoodSource:.*',    # * GoodSource: ...
            r'\*\s*BadSink:.*',       # * BadSink: ...
            r'\*\s*GoodSink:.*',      # * GoodSink: ...
            r'\*\s*Sink:.*',          # * Sink: ...
            
            # CWE情報と脆弱性種別
            r'CWE-?\d+:.*',           # CWE-15: ... or CWE15: ...
            r'Type Confusion',         # 脆弱性種別名
            r'External Control',       # 脆弱性種別名
            r'Buffer Overflow',        # 脆弱性種別名
            r'SQL Injection',          # 脆弱性種別名
            
            # ファイル情報
            r'Filename:.*CWE.*\.c',   # Filename: CWE...
            r'Label Definition File:.*\.xml', # Label Definition File: ...
            r'Template File:.*',       # Template File: ...
            
            # その他のヒント的コメント
            r'/\*\s*Initialize.*?\*/',  # /* Initialize data */
            r'\*\s*@description.*',    # * @description
            r'\*\s*Flow Variant:.*',   # * Flow Variant: ...
            
            # 全コメント除去（最後に実行）
            r'/\*.*?\*/',             # 全ての /* ... */
            r'//.*',                  # 全ての // ...
        ]
        
        # 関数名匿名化パターン
        self.function_patterns = [
            (r'(\w+)_bad\b', r'\1_func1'),      # _bad -> _func1
            (r'(\w+)_good\b', r'\1_func2'),     # _good -> _func2  
            (r'goodG2B\b', 'functionA'),        # goodG2B -> functionA
            (r'goodB2G\b', 'functionB'),        # goodB2G -> functionB
            (r'good1\b', 'functionC'),          # good1 -> functionC
            (r'good2\b', 'functionD'),          # good2 -> functionD
            (r'goodB2G1\b', 'functionE'),       # goodB2G1 -> functionE
            (r'goodB2G2\b', 'functionF'),       # goodB2G2 -> functionF
            (r'goodG2B1\b', 'functionG'),       # goodG2B1 -> functionG
            (r'goodG2B2\b', 'functionH'),       # goodG2B2 -> functionH
            # ランダム・テスト関数の匿名化
            (r'\bRAND32\(\)', 'getRandomValue()'), # RAND32() -> getRandomValue()
            (r'\brand\(\)', 'getRandomValue()'),    # rand() -> getRandomValue()
            (r'\bglobalReturnsTrue\(\)', 'checkCondition()'), # globalReturnsTrue() -> checkCondition()
            (r'\bglobalReturnsFalse\(\)', 'checkCondition()'), # globalReturnsFalse() -> checkCondition()
            # Windows APIの匿名化
            (r'\bLoadLibraryW?\b', 'loadModule'),    # LoadLibrary -> loadModule
            (r'\bFreeLibrary\b', 'freeModule'),     # FreeLibrary -> freeModule
            (r'\bCreateProcess[AW]?\b', 'startProcess'), # CreateProcess -> startProcess
            (r'\bWSAStartup\b', 'initNetwork'),     # WSAStartup -> initNetwork
            (r'\bWSACleanup\b', 'cleanupNetwork'), # WSACleanup -> cleanupNetwork
            # ネットワーク関数の匿名化
            (r'\bsocket\b', 'createSocket'),        # socket -> createSocket
            (r'\bconnect\b', 'connectTo'),          # connect -> connectTo
            (r'\bbind\b', 'bindSocket'),            # bind -> bindSocket
            (r'\blisten\b', 'listenSocket'),        # listen -> listenSocket
            (r'\baccept\b', 'acceptConnection'),    # accept -> acceptConnection
            (r'\brecv\b', 'receiveData'),           # recv -> receiveData
            (r'\bsend\b', 'sendData'),              # send -> sendData
            # メモリ関数の匿名化
            (r'\bmalloc\b', 'allocateMemory'),      # malloc -> allocateMemory
            (r'\bfree\b', 'freeMemory'),            # free -> freeMemory
            (r'\bmemmove\b', 'moveMemory'),         # memmove -> moveMemory
            (r'\bmemcpy\b', 'copyMemory'),          # memcpy -> copyMemory
            (r'\bmemset\b', 'setMemory'),           # memset -> setMemory
            # 文字列関数の匿名化
            (r'\bwcscpy\b', 'copyWideString'),      # wcscpy -> copyWideString
            (r'\bwcslen\b', 'getWideStringLength'), # wcslen -> getWideStringLength
            (r'\bwcschr\b', 'findWideChar'),       # wcschr -> findWideChar
            (r'\bstrcpy\b', 'copyString'),          # strcpy -> copyString
            (r'\bstrlen\b', 'getStringLength'),     # strlen -> getStringLength
            (r'\bfgetws\b', 'readWideString'),      # fgetws -> readWideString
            (r'\bfgets\b', 'readString'),           # fgets -> readString
            (r'\bsprintf\b', 'formatString'),       # sprintf -> formatString
            (r'\bvprintf\b', 'printFormatted'),     # vprintf -> printFormatted
            # ファイル関数の匿名化
            (r'\bfopen\b', 'openFile'),             # fopen -> openFile
            (r'\bfclose\b', 'closeFile'),           # fclose -> closeFile
            (r'\bfread\b', 'readFile'),             # fread -> readFile
            (r'\bfwrite\b', 'writeFile'),           # fwrite -> writeFile
        ]
        
        # 変数名匿名化パターン
        self.variable_patterns = [
            # 型を示唆する変数名
            (r'\bcharBuffer\b', 'buffer1'),     # charBuffer -> buffer1
            (r'\bintBuffer\b', 'buffer2'),      # intBuffer -> buffer2
            (r'\blongBuffer\b', 'buffer3'),     # longBuffer -> buffer3
            (r'\bfloatBuffer\b', 'buffer4'),    # floatBuffer -> buffer4
            (r'\bdoubleBuffer\b', 'buffer5'),   # doubleBuffer -> buffer5
            (r'\bwcharBuffer\b', 'buffer6'),    # wcharBuffer -> buffer6
            
            # セキュリティ関連の変数名
            (r'\bpassword\b', 'userInput'),     # password -> userInput
            (r'\bhostname\b', 'target'),        # hostname -> target
            (r'\busername\b', 'userid'),        # username -> userid
            (r'\bsecret\b', 'data'),            # secret -> data
            (r'\bkey\b', 'value'),              # key -> value
            
            # サイズや長さを示唆する変数名
            (r'\bpasswordLen\b', 'inputLen'),   # passwordLen -> inputLen
            (r'\bhostnameLen\b', 'targetLen'),  # hostnameLen -> targetLen
            
            # 型の匿名化
            (r'\bunsigned int\b', 'uint_type'), # unsigned int -> uint_type
            (r'\bsigned int\b', 'int_type'),    # signed int -> int_type
            # Windows型の匿名化
            (r'\bHMODULE\b', 'ModuleHandle'),   # HMODULE -> ModuleHandle
            (r'\bHANDLE\b', 'ResourceHandle'),  # HANDLE -> ResourceHandle
            (r'\bDWORD\b', 'UInt32Type'),       # DWORD -> UInt32Type
            (r'\bBYTE\b', 'UInt8Type'),         # BYTE -> UInt8Type
            (r'\bSOCKET\b', 'SocketHandle'),    # SOCKET -> SocketHandle
            (r'\bWSADATA\b', 'NetworkData'),    # WSADATA -> NetworkData
            # 文字列型の匿名化
            (r'\bwchar_t\b', 'WideCharType'),   # wchar_t -> WideCharType
            (r'\bTCHAR\b', 'CharType'),         # TCHAR -> CharType
            (r'\bLPWSTR\b', 'WideStringPtr'),   # LPWSTR -> WideStringPtr
            (r'\bLPSTR\b', 'StringPtr'),        # LPSTR -> StringPtr
            # サイズ型の匿名化
            (r'\bsize_t\b', 'SizeType'),        # size_t -> SizeType
            (r'\bssize_t\b', 'SignedSizeType'), # ssize_t -> SignedSizeType
            # カスタム型の匿名化
            (r'\btwoIntsStruct\b', 'DataStruct'), # twoIntsStruct -> DataStruct
            (r'\bunionType\b', 'DataUnion'),     # unionType -> DataUnion
        ]
        
        # 文字列パターンの匿名化
        self.string_patterns = [
            (r'"Inside the .*?"', '"debug_message"'),     # "Inside the ..." -> "debug_message"
            (r'"Hello from .*?"', '"status_message"'),    # "Hello from ..." -> "status_message"
            (r'"Calling .*?"', '"action_message"'),       # "Calling ..." -> "action_message"
            (r'"Finished .*?"', '"completion_message"'),  # "Finished ..." -> "completion_message"
            (r'"Benign.*?fixed.*?string"', '"test_string"'), # "Benign, fixed string" -> "test_string"
            # ステータスメッセージの匿名化
            (r'".*?success.*?"', '"operation_completed"'), # Success messages -> "operation_completed"
            (r'".*?fail.*?"', '"operation_failed"'),       # Failure messages -> "operation_failed"
            (r'".*?error.*?"', '"error_occurred"'),        # Error messages -> "error_occurred"
            (r'".*?login.*?"', '"auth_message"'),          # Login messages -> "auth_message"
            (r'"fgetws.*?failed"', '"input_error"'),       # fgetws() failed -> "input_error"
            (r'"Library loaded.*?"', '"lib_status"'),      # Library status -> "lib_status"
            (r'"command execution.*?"', '"exec_status"'),  # Execution status -> "exec_status"
        ]
        
        # 定数の匿名化
        self.constant_patterns = [
            (r'\bINVALID_SOCKET\b', 'INVALID_HANDLE'),    # INVALID_SOCKET -> INVALID_HANDLE
            (r'\bSOCKET_ERROR\b', 'HANDLE_ERROR'),       # SOCKET_ERROR -> HANDLE_ERROR
            (r'\bAF_INET\b', 'ADDR_FAMILY'),             # AF_INET -> ADDR_FAMILY
            (r'\bSOCK_STREAM\b', 'SOCKET_TYPE'),         # SOCK_STREAM -> SOCKET_TYPE
            (r'\bIPPROTO_TCP\b', 'PROTOCOL_TYPE'),       # IPPROTO_TCP -> PROTOCOL_TYPE
            (r'\bMAKEWORD\b', 'MAKE_VERSION'),           # MAKEWORD -> MAKE_VERSION
            (r'\bNO_ERROR\b', 'SUCCESS_CODE'),           # NO_ERROR -> SUCCESS_CODE
            (r'\bstaticTrue\b', 'CONDITION_TRUE'),       # staticTrue -> CONDITION_TRUE
            (r'\bstaticFalse\b', 'CONDITION_FALSE'),     # staticFalse -> CONDITION_FALSE
            (r'\bGLOBAL_CONST_TRUE\b', 'GLOBAL_TRUE'),   # GLOBAL_CONST_TRUE -> GLOBAL_TRUE
            (r'\bGLOBAL_CONST_FALSE\b', 'GLOBAL_FALSE'), # GLOBAL_CONST_FALSE -> GLOBAL_FALSE
            (r'\bFILENAME\b', 'FILE_PATH'),              # FILENAME -> FILE_PATH
            (r'\bIP_ADDRESS\b', 'TARGET_ADDR'),          # IP_ADDRESS -> TARGET_ADDR
            (r'\bTCP_PORT\b', 'TARGET_PORT'),            # TCP_PORT -> TARGET_PORT
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
        
        # 3. 変数名を匿名化
        for old_pattern, new_pattern in self.variable_patterns:
            anonymized = re.sub(old_pattern, new_pattern, anonymized)
        
        # 4. 文字列パターンを匿名化
        for old_pattern, new_pattern in self.string_patterns:
            anonymized = re.sub(old_pattern, new_pattern, anonymized, flags=re.IGNORECASE)
        
        # 5. 定数パターンを匿名化
        for old_pattern, new_pattern in self.constant_patterns:
            anonymized = re.sub(old_pattern, new_pattern, anonymized)
        
        # 6. 余分な空行を削除
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
    sample_file = Path("data/juliet/testcases/CWE843_Type_Confusion/CWE843_Type_Confusion__char_01.c")
    
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