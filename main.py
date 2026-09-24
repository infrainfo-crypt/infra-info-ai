import requests

updates_url = "https://api.msrc.microsoft.com/cvrf/v3.0/Updates('2026-Sep')?api-version=2023-11-01"

response = requests.get(
    updates_url,
    headers={"Accept": "application/json"},
    timeout=30
)

response.raise_for_status()

updates = response.json()["value"]

print("Microsoft Security Update Information")
print("--------------------------------------")

for update in updates:
    print(f"ID: {update['ID']}")
    print(f"Title: {update['DocumentTitle']}")
    print(f"Initial Release: {update['InitialReleaseDate']}")
    print(f"Current Release: {update['CurrentReleaseDate']}")
    print(f"CVRF URL: {update['CvrfUrl']}")

    cvrf_response = requests.get(
        update["CvrfUrl"],
        headers={"Accept": "application/json"},
        timeout=30
    )

    cvrf_response.raise_for_status()

    cvrf_data = cvrf_response.json()

    print("\n取得した詳細データのキー:")
    print(list(cvrf_data.keys()))

    print("\n詳細データ:")
    print(cvrf_data)
