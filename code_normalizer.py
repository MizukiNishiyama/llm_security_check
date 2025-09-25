#!/usr/bin/env python3
import os
import glob
import time
from pathlib import Path
from openai import OpenAI
from dotenv import load_dotenv

class CodeNormalizer:
    def __init__(self):
        load_dotenv()
        self.openai_client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

        # Get PROMPT_NORMALIZATION, handle multiline format
        self.normalization_prompt = os.environ.get("PROMPT_NORMALIZATION")

        # If not found in env, provide default normalization prompt
        if not self.normalization_prompt:
            self.normalization_prompt = """【目的】
以下に続けて貼り付ける逆コンパイル済みCコード（INPUT_CODE）と等価な機能を維持しつつ、読みやすく保守可能な正規化Cソースへ書き直してください。

【役割】
あなたは逆コンパイルコードの再構成に長けたCエンジニアです。POSIX/BSDソケットと文字列処理、エラー処理、可搬性に配慮した設計を行います。

【必須要件】
1) 機能等価：ソケット作成→127.0.0.1:ポート接続→受信→既存バッファ末尾に連結→CR/LF除去→コマンド処理呼び出しなど、元と同一の副作用と順序を保持。
2) 正規化：struct sockaddr直接書き換えをやめ、struct sockaddr_in＋htons/inet_addrで明示。マジックナンバーをシンボルへ。
3) 安全分離：末尾の不明瞭な呼出しはhandle_command(const char* cmd)に置換し、デフォルトは安全なスタブ実装。
4) エラー処理：socket/connect/recv/closeを明示チェック。
5) CR/LF除去：受信後、最初の'\r'を終端化し、次に最初の'\n'を終端化。
6) 可搬性/依存関係：必要なヘッダファイルのみ使用。
7) 可読性：小関数へ分割、各関数に1行docコメント。
8) 出力フォーマット：C言語の完全単一ファイルを提示。ヘッダ、定数、プロトタイプ、実装を含む。
"""

    def normalize_c_file(self, input_file_path: str) -> tuple[str, float]:
        """Normalize a C file using GPT-5 and return (normalized_code, processing_time)"""
        try:
            # Read the input C file
            with open(input_file_path, 'r', encoding='utf-8') as f:
                c_code = f.read()

            # Prepare the prompt
            full_prompt = f"{self.normalization_prompt}\n\nINPUT_CODE:\n{c_code}"

            # Record start time
            start_time = time.time()

            # Call GPT-5 for normalization
            response = self.openai_client.responses.create(
                model="gpt-5-mini",
                input=full_prompt,
                reasoning={"effort": "low"},
                text={"verbosity": "low"},
            )

            processing_time = time.time() - start_time
            normalized_code = response.output_text.strip()

            return normalized_code, processing_time

        except Exception as e:
            print(f"Error normalizing {input_file_path}: {e}")
            return None, 0.0

    def process_all_files(self, input_dir: str, output_dir: str):
        """Process all C files in the input directory"""
        # Get all C files
        c_files = glob.glob(os.path.join(input_dir, "*.c"))

        if not c_files:
            print(f"No C files found in {input_dir}")
            return

        print(f"Found {len(c_files)} C files to normalize")

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Process each file
        successful_normalizations = 0
        total_processing_time = 0.0

        for i, c_file in enumerate(c_files, 1):
            filename = os.path.basename(c_file)
            print(f"Processing {i}/{len(c_files)}: {filename}")

            # Normalize the file
            normalized_code, processing_time = self.normalize_c_file(c_file)

            if normalized_code:
                # Save normalized code to output directory
                output_file = os.path.join(output_dir, filename)

                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(normalized_code)

                successful_normalizations += 1
                total_processing_time += processing_time
                print(f"  ✓ Normalized and saved to {output_file} (took {processing_time:.2f}s)")
            else:
                print(f"  ✗ Failed to normalize {filename}")

        # Summary
        print(f"\nNormalization completed!")
        print(f"Total files processed: {len(c_files)}")
        print(f"Successful normalizations: {successful_normalizations}")
        print(f"Total processing time: {total_processing_time:.2f} seconds")
        if successful_normalizations > 0:
            avg_time = total_processing_time / successful_normalizations
            print(f"Average processing time: {avg_time:.2f} seconds per file")

def main():
    normalizer = CodeNormalizer()

    input_dir = "data/juliet_modified/1_Ghidra_LLM_CWE78_renamed_v4/bad"
    output_dir = "data/juliet_modified/1_Ghidra_LLM_CWE78_renamed_v4/normalized/gpt5"

    print(f"Input directory: {input_dir}")
    print(f"Output directory: {output_dir}")
    print(f"Using GPT-5 with PROMPT_NORMALIZATION")
    print("-" * 50)

    normalizer.process_all_files(input_dir, output_dir)

if __name__ == "__main__":
    main()