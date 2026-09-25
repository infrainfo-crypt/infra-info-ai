import csv
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from openai import OpenAI


INPUT_FILE = "msrc_2026-09.csv"
OUTPUT_DIR = Path("articles")

MAX_WORKERS = 20
MAX_RETRIES = 5


def safe_filename(value):
    return re.sub(r"[^a-zA-Z0-9._-]", "_", value)


def create_prompt(row):
    return f"""
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


def generate_one(row):
    cve = row["CVE"]
    output_file = OUTPUT_DIR / f"{safe_filename(cve)}.md"

    if output_file.exists():
        return cve, "skipped", None

    client = OpenAI(
        api_key=os.environ["OPENAI_API_KEY"]
    )

    prompt = create_prompt(row)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = client.responses.create(
                model="gpt-5.6-luna",
                input=prompt
            )

            article = response.output_text

            temp_file = OUTPUT_DIR / f"{safe_filename(cve)}.tmp"

            with open(
                temp_file,
                "w",
                encoding="utf-8"
            ) as f:
                f.write(article)

            temp_file.replace(output_file)

            return cve, "generated", None

        except Exception as e:
            error_text = str(e)

            if "insufficient_quota" in error_text:
                return cve, "failed", error_text

            if attempt == MAX_RETRIES:
                return cve, "failed", error_text

            wait_seconds = 2 ** attempt

            time.sleep(wait_seconds)

    return cve, "failed", "unknown error"


OUTPUT_DIR.mkdir(exist_ok=True)

with open(
    INPUT_FILE,
    "r",
    encoding="utf-8-sig",
    newline=""
) as f:
    reader = csv.DictReader(f)
    rows = list(reader)


print("--------------------------------------")
print("記事生成開始")
print(f"対象件数: {len(rows)}")
print(f"同時実行数: {MAX_WORKERS}")
print("--------------------------------------")


generated_count = 0
skipped_count = 0
failed_count = 0
failed_items = []


with ThreadPoolExecutor(
    max_workers=MAX_WORKERS
) as executor:

    futures = [
        executor.submit(generate_one, row)
        for row in rows
    ]

    for index, future in enumerate(
        as_completed(futures),
        start=1
    ):
        cve, status, error = future.result()

        if status == "generated":
            generated_count += 1
            print(
                f"[{index}/{len(rows)}] "
                f"{cve} → 完了"
            )

        elif status == "skipped":
            skipped_count += 1
            print(
                f"[{index}/{len(rows)}] "
                f"{cve} → スキップ"
            )

        else:
            failed_count += 1
            failed_items.append(
                f"{cve}: {error}"
            )

            print(
                f"[{index}/{len(rows)}] "
                f"{cve} → 失敗"
            )


if failed_items:
    with open(
        OUTPUT_DIR / "failed_articles.txt",
        "w",
        encoding="utf-8"
    ) as f:
        for item in failed_items:
            f.write(item + "\n")


print("--------------------------------------")
print("記事生成完了")
print(f"対象件数: {len(rows)}")
print(f"新規生成: {generated_count}")
print(f"スキップ: {skipped_count}")
print(f"失敗: {failed_count}")
print(f"保存先: {OUTPUT_DIR}")
print("--------------------------------------")
