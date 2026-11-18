
import pandas as pd
import requests
import tldextract

from urllib.parse import urlsplit

INPUT_PATH = "dataset/augmentation/legitimate_homepages_candidates.csv"
OUTPUT_PATH = "dataset/augmentation/homepage_verification_report.csv"


def registered_domain(url):
    hostname = urlsplit(url).hostname or ""
    extracted = tldextract.extract(hostname)

    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"

    return hostname.lower()


df = pd.read_csv(INPUT_PATH)

results = []

print("\nPHISHGUARD HOMEPAGE VERIFICATION")
print("=" * 70)

for _, row in df.iterrows():
    url = str(row["url"]).strip()

    print(f"\nChecking: {url}")

    status_code = None
    final_url = ""
    same_domain = False
    verification_status = "needs_review"
    error_message = ""

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "PhishGuard-Research/1.0"},
            stream=True
        )

        status_code = response.status_code
        final_url = response.url

        same_domain = (
            registered_domain(url) ==
            registered_domain(final_url)
        )

        if response.ok and same_domain:
            verification_status = "reachable_same_domain"
        elif response.ok:
            verification_status = "redirected_other_domain"
        else:
            verification_status = "http_error"

        response.close()

    except requests.RequestException as error:
        error_message = str(error)
        verification_status = "connection_error"

    results.append({
        "url": url,
        "candidate_label": row["candidate_label"],
        "http_status": status_code,
        "final_url": final_url,
        "same_registered_domain": same_domain,
        "verification_status": verification_status,
        "error": error_message
    })

    print("HTTP status:", status_code)
    print("Final URL:", final_url)
    print("Verification:", verification_status)

report = pd.DataFrame(results)
report.to_csv(OUTPUT_PATH, index=False)

print("\n" + "=" * 70)
print("VERIFICATION SUMMARY")
print("=" * 70)

print(report["verification_status"].value_counts())

print("\nReport saved to:", OUTPUT_PATH)
print("Verification completed.")
