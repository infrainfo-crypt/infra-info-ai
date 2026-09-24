import requests

url = "https://api.msrc.microsoft.com/cvrf/v3.0/Updates('2026-Sep')?api-version=2023-11-01"

response = requests.get(
    url,
    headers={"Accept": "application/json"},
    timeout=30
)

response.raise_for_status()

data = response.json()

print("Microsoft Security Update Information")
print("--------------------------------------")
print(f"取得件数: {len(data)}")

for item in data[:5]:
    print(item)
