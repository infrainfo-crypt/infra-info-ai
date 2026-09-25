import requests
import csv

# =========================
# 1. MSRCの月例更新情報を取得
# =========================

updates_url = (
    "https://api.msrc.microsoft.com/cvrf/v3.0/"
    "Updates('2026-Sep')?api-version=2023-11-01"
)

response = requests.get(
    updates_url,
    headers={"Accept": "application/json"},
    timeout=30
)

response.raise_for_status()

updates = response.json()["value"]

print("Microsoft Security Update Information")
print("--------------------------------------")


# =========================
# 2. CSVに保存するデータ
# =========================

results = []


# =========================
# 3. 各更新情報を処理
# =========================

for update in updates:

    print(f"ID: {update['ID']}")
    print(f"Title: {update['DocumentTitle']}")

    # CVRF詳細情報を取得
    cvrf_response = requests.get(
        update["CvrfUrl"],
        headers={"Accept": "application/json"},
        timeout=30
    )

    cvrf_response.raise_for_status()

    cvrf_data = cvrf_response.json()


    # =========================
    # 4. ProductID → 製品名の辞書を作成
    # =========================

    product_map = {
        product["ProductID"]: product.get("Value", "")
        for product in cvrf_data["ProductTree"].get(
            "FullProductName", []
        )
    }


    # =========================
    # 5. 脆弱性を全部処理
    # =========================

    vulnerabilities = cvrf_data.get(
        "Vulnerability", []
    )

    print(f"Vulnerability件数: {len(vulnerabilities)}")


    for vulnerability in vulnerabilities:

        # -------------------------
        # CVE
        # -------------------------

        cve = vulnerability.get("CVE", "")


        # -------------------------
        # Title
        # -------------------------

        title = vulnerability.get(
            "Title", {}
        ).get("Value", "")


        # -------------------------
        # Severity / Threat
        # -------------------------

        severity = ""

        for threat in vulnerability.get(
            "Threats", []
        ):

            value = threat.get(
                "Description", {}
            ).get("Value", "")

            if value:
                severity = value
                break


        # -------------------------
        # CVSS
        # -------------------------

        cvss = ""

        cvss_sets = vulnerability.get(
            "CVSSScoreSets", []
        )

        if cvss_sets:
            cvss = cvss_sets[0].get(
                "BaseScore", ""
            )


        # -------------------------
        # ProductID → 製品名
        # -------------------------

        product_ids = set()

        for status in vulnerability.get(
            "ProductStatuses", []
        ):

            for product_id in status.get(
                "ProductID", []
            ):

                product_ids.add(product_id)


        product_names = []

        for product_id in product_ids:

            product_name = product_map.get(
                product_id
            )

            if product_name:
                product_names.append(
                    product_name
                )


        # 重複削除
        product_names = list(
            dict.fromkeys(product_names)
        )


        # -------------------------
        # Remediation
        # -------------------------

        fixed_build = ""

        remediations = vulnerability.get(
            "Remediations", []
        )

        for remediation in remediations:

            build = remediation.get(
                "FixedBuild", ""
            )

            if build:
                fixed_build = build
                break


        # -------------------------
        # 1件分を保存
        # -------------------------

        results.append({
            "CVE": cve,
            "Title": title,
            "Severity": severity,
            "CVSS": cvss,
            "Product": "; ".join(product_names),
            "FixedBuild": fixed_build
        })


# =========================
# 6. CSV出力
# =========================

output_file = "msrc_2026-09.csv"

with open(
    output_file,
    "w",
    newline="",
    encoding="utf-8-sig"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=[
            "CVE",
            "Title",
            "Severity",
            "CVSS",
            "Product",
            "FixedBuild"
        ]
    )

    writer.writeheader()

    writer.writerows(results)


# =========================
# 7. 完了メッセージ
# =========================

print("--------------------------------------")
print(f"CSV出力完了: {output_file}")
print(f"出力件数: {len(results)}")
