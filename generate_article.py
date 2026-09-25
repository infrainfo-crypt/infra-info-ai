import csv
import os
from openai import OpenAI

INPUT_FILE = "msrc_2026-09.csv"
OUTPUT_FILE = "article_2026-09.md"

client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"]
)

# =========================
# CSVから1件取得
# =========================

with open(
    INPUT_FILE,
    "r",
    encoding="utf-8-sig",
    newline=""
) as f:

    reader = csv.DictReader(f)

    # 今回はテストとして1件だけ
    row = next(reader)


# =========================
# AIに渡す情報
# =========================

prompt = f"""
あなたは企業向けのサイバーセキュリティ情報を
わかりやすく整理する編集者です。

以下はMicrosoft Security Response Center (MSRC)
から取得した脆弱性情報です。

この情報だけを事実情報として使用してください。

情報に存在しない製品、バージョン、攻撃方法、
影響、対策などを推測して追加しないでください。

以下の構成で、日本語の記事を作成してください。

# 構成

1. タイトル
2. 概要
3. 脆弱性の種類
4. CVSS
5. 対象製品
6. 修正版
7. 対応について
8. まとめ

「対応について」では、
提供されたFixedBuildを確認することを基本とし、
具体的な環境での影響については対象製品・バージョンを
確認する必要がある、としてください。

# 脆弱性情報

CVE:
{row["CVE"]}

Title:
{row["Title"]}

Severity:
{row["Severity"]}

AttackType:
{row["AttackType"]}

CVSS:
{row["CVSS"]}

Product:
{row["Product"]}

FixedBuild:
{row["FixedBuild"]}
"""


# =========================
# AI記事生成
# =========================

response = client.responses.create(
    model="gpt-5.6-luna",
    input=prompt
)

article = response.output_text


# =========================
# Markdown保存
# =========================

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as f:

    f.write(article)

print("--------------------------------------")
print(f"記事生成完了: {OUTPUT_FILE}")
print(f"CVE: {row['CVE']}")
