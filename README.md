# LLM Security Check

AIモデルを使用した脆弱性診断ツール

## 概要

このツールは、複数のAIモデル（Gemini、GPT-5、Groq）を使用してコードの脆弱性を自動検出します。3つの分析モードに対応し、カスタムプロンプトと並列処理をサポートしています。

## インストール

```bash
# 依存関係をインストール
pip install -r requirements.txt

# 環境変数を設定（.envファイルを作成）
cp .env.example .env
# APIキーとプロンプトを.envファイルに設定
```

## 使用方法

### 基本コマンド

```bash
python vulnerability_analyzer.py [オプション]
```

## オプション詳細

### 基本オプション

#### `--type` (分析タイプ)
- `original`: 既存のJSONファイル形式を分析（デフォルト）
- `modified_1`: Cファイルの`func_0`関数を直接分析
- `v4_extracted`: 抽出されたv4データセットを分析

#### `--model` (AIモデル選択)
- `gpt-oss-120b` / `gpt-oss-20b`: Groq経由のオープンソースGPT
- `gpt5` / `gpt-5-mini`: OpenAI GPT-5シリーズ

#### `--prompt` (プロンプトバージョン)
- `0`: デフォルトプロンプト（デフォルト）
- `1`, `2`, `3`...: `.env`の`PROMPT_1`, `PROMPT_2`, `PROMPT_3`...を使用

### データ処理オプション

#### `--directory` (ディレクトリ指定)
- 分析対象のディレクトリパス
- デフォルト: `data/juliet_anonymized`

#### `--number` (ファイル数制限)
- 処理するファイル数の上限
- `0`: 全ファイル処理（デフォルト）

#### `--random` (ランダム選択)
- ファイルをランダムに選択して処理

#### `--78` (CWE78フィルター)
- CWE78_OS_Command_Injectionファイルのみ処理

## 使用例

### v4抽出データ(生CWE78データ)の分析
```bash
# v4抽出データでGPT-5-miniとPROMPT_3を使用
python vulnerability_analyzer.py --type v4_extracted --model gpt-5-mini --prompt 3

# 5個のファイルをテスト実行
python vulnerability_analyzer.py --type v4_extracted --model gpt-5-mini --number 5
```

### 逆コンパイルされたCファイルの分析
```bash
# 修正されたCファイルを並列処理で分析
python vulnerability_analyzer.py --type modified_1 --model gpt-5-mini

# GPT-5でカスタムプロンプト使用
python vulnerability_analyzer.py --type modified_1 --model gpt5 --prompt 2
```

## 環境変数設定（.env）

```env
# APIキー
GROQ_API_KEY=your_groq_api_key
OPENAI_API_KEY=your_openai_api_key

# カスタムプロンプト
PROMPT_1=以下のコードを分析し、脆弱性がある場合は1,ない場合は0を出力せよ。必ず数値のみ出力せよ。説明は一切不要である。

PROMPT_2="# 命令書
あなたは経験豊富なセキュリティ専門家です。以下のタスクを厳密に実行してください。
..."

PROMPT_3="# OSコマンドインジェクション専門分析
CWE-78の脆弱性検出に特化した分析を行ってください。
..."
```

## 出力

### 出力フォルダ構造
分析結果は`./output/`ディレクトリに以下の形式で保存されます：

```
./output/{timestamp}_{type}_{model}_{options}/
├── report.txt  # 分析レポート
```

### フォルダ名の例
- `20250925_143022_v4_extracted_model-gpt-5-mini_prompt-1_limit-10_parallel-2`
- `20250925_144530_modified_1_model-gemini_parallel-4`
- `20250925_145000_original_model-gpt5_prompt-3_cwe78only_random`

### レポート内容
```
Vulnerability Analysis Report
Generated at: 2025-09-25T14:30:22.123456
Model: gpt-5-mini
Prompt version: 1
Analysis type: v4_extracted
Total files processed: 54
Files with vulnerabilities: 52
Vulnerability rate: 96.30%
Successful analyses: 54
Total analysis time: 234.567 seconds
Average analysis time: 4.344 seconds

Individual Results:
----------------------------------------------------------------------
File: /path/to/file1.json
Result: 1
Analysis time: 1.234 seconds
----------------------------------------------------------------------
```

## データ構造

### 分析対象データ
- `data/juliet_anonymized/`: オリジナルの匿名化されたJSONデータ
- `data/juliet_modified/1_Ghidra_LLM_CWE78_renamed_v4/bad/`: 修正されたCファイル
- `data/juliet_anonymized_extracted/v4/`: 抽出された対応するJSONファイル

### ファイル抽出
対応するファイルを抽出するには：
```bash
python extract_matching_files.py
```

## 注意事項

- APIキーは`.env`ファイルに安全に保存してください
- 大量のファイルを処理する際は`--parallel`オプションの使用を推奨します
- プロンプトバージョンは`.env`ファイルに定義されている必要があります
- 各AIモデルには利用制限がある場合があります

## トラブルシューティング

### よくある問題
1. **APIキーエラー**: `.env`ファイルでAPIキーが正しく設定されているか確認
2. **タイムアウト**: `--parallel`オプションで並列処理数を調整
3. **プロンプトが見つからない**: `.env`ファイルに`PROMPT_N`が定義されているか確認

### デバッグ
- 少数のファイルで先にテスト実行: `--number 3`
- エラーメッセージは出力レポートに記録されます