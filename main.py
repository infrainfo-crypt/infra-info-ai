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
# CSVに保存するデータ
# =========================

results = []


# =========================
# 各更新情報を処理
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

    vulnerabilities = cvrf_data.get(
        "Vulnerability", []
    )

    print(f"Vulnerability件数: {len(vulnerabilities)}")


    # =========================
    # ProductID → 製品名
    # =========================

    product_map = {
        product["ProductID"]: product.get("Value", "")
        for product in cvrf_data["ProductTree"].get(
            "FullProductName", []
        )
    }


    # =========================
    # 脆弱性を処理
    # =========================

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
        # Severity
        # -------------------------

        severity = ""

        for threat in vulnerability.get(
            "Threats", []
        ):

            description = threat.get(
                "Description", {}
            )

            value = description.get(
                "Value", ""
            )

            if value in [
                "Critical",
                "Important",
                "Moderate",
                "Low"
            ]:
                severity = value
                break


        # -------------------------
        # Attack Type
        # -------------------------

        attack_types = []

        for threat in vulnerability.get(
            "Threats", []
        ):

            description = threat.get(
                "Description", {}
            )

            value = description.get(
                "Value", ""
            )

            if value and value not in [
                "Critical",
                "Important",
                "Moderate",
                "Low"
            ]:
                attack_types.append(value)

        attack_types = list(
            dict.fromkeys(attack_types)
        )

        attack_type = "; ".join(
            attack_types
        )


        # -------------------------
        # CVSS
        # -------------------------

        cvss_scores = []

        for score_set in vulnerability.get(
            "CVSSScoreSets", []
        ):

            base_score = score_set.get(
                "BaseScore"
            )

            if base_score is not None:
                cvss_scores.append(
                    str(base_score)
                )

        cvss = "; ".join(
            dict.fromkeys(cvss_scores)
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

        product_names = list(
            dict.fromkeys(product_names)
        )

        product = "; ".join(
            product_names
        )


        # -------------------------
        # FixedBuild
        # -------------------------

        fixed_builds = []

        for remediation in vulnerability.get(
            "Remediations", []
        ):

            fixed_build = remediation.get(
                "FixedBuild"
            )

            if fixed_build:
                fixed_builds.append(
                    str(fixed_build)
                )

        fixed_builds = list(
            dict.fromkeys(fixed_builds)
        )

        fixed_build = "; ".join(
            fixed_builds
        )


        # -------------------------
        # CSV用データ
        # -------------------------

        results.append({
            "CVE": cve,
            "Title": title,
            "Severity": severity,
            "AttackType": attack_type,
            "CVSS": cvss,
            "Product": product,
            "FixedBuild": fixed_build
        })


# =========================
# CSV出力
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
            "AttackType",
            "CVSS",
            "Product",
            "FixedBuild"
        ]
    )

    writer.writeheader()

    writer.writerows(results)


# =========================
# 完了
# =========================

print("--------------------------------------")
print(f"CSV出力完了: {output_file}")
print(f"出力件数: {len(results)}")
