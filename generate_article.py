```python
import csv
import os
import re
from pathlib import Path

from openai import OpenAI


INPUT_FILE = "msrc_2026-09.csv"
OUTPUT_DIR = Path("articles")

client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"]
)


# =========================
# 出力先
# =========================

OUTPUT_DIR.mkdir(exist_ok=True)


# =========================
# ファイル名用
# =========================

def safe_filename(value):
    return re.sub(r"[^a-zA-Z0-9._-]", "_", value)


# =========================
# CSV読み込み
# =========================

with open(
    INPUT_FILE,
    "r",
    encoding="utf-8-sig",
    newline=""
) as f:

    reader = csv.DictReader(f)
    rows = list(reader)


print("--------------------------------------")
print(f"記事生成開始")
print(f"対象件数: {len(rows)}")
print("--------------------------------------")


# =========================
# 1件ずつ記事生成
# =========================

for index, row in enumerate(rows, start=1):

    cve = row["CVE"]

    print(f"[{index}/{len(rows)}] {cve} を処理中...")


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

AttackTypeが空欄の場合は、
「記載なし」としてください。

FixedBuildが複数ある場合は、
対象製品とFixedBuildの対応関係が分かるようにしてください。

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


    response = client.responses.create(
        model="gpt-5.6-luna",
        input=prompt
    )

    article = response.output_text


    # =========================
    # Markdown保存
    # =========================

    output_file = OUTPUT_DIR / f"{safe_filename(cve)}.md"

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(article)


    print(f"    完了: {output_file}")


print("--------------------------------------")
print("記事生成完了")
print(f"生成件数: {len(rows)}")
print(f"保存先: {OUTPUT_DIR}")
print("--------------------------------------")
```
