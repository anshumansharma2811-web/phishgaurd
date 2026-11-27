import pandas as pd
import tldextract

from pathlib import Path
from urllib.parse import urlsplit


BASE_DIR = Path(__file__).resolve().parent

DATASET_PATH = (
    BASE_DIR / "dataset" / "phishstorm_clean.csv"
)

CANDIDATE_PATH = (
    BASE_DIR / "evaluation" / "legitimate_candidates.csv"
)

OUTPUT_PATH = (
    BASE_DIR / "evaluation" / "legitimate_candidate_review.csv"
)


def get_registered_domain(url):

    url = str(url).strip()

    if "://" not in url:
        url = "http://" + url

    try:
        hostname = urlsplit(url).hostname or ""
    except ValueError:
        return ""

    extracted = tldextract.extract(hostname)

    if extracted.domain and extracted.suffix:
        return (
            extracted.domain + "." + extracted.suffix
        )

    return hostname.lower()


print("=" * 65)
print("PHISHGUARD INDEPENDENT DATASET OVERLAP CHECK")
print("=" * 65)

print("\nLoading original dataset...")

original = pd.read_csv(DATASET_PATH)

original = original.dropna(subset=["domain"])

original_domains = set(
    original["domain"].apply(get_registered_domain)
)

original_domains.discard("")

print("Original registered domains:", len(original_domains))


# Check previously used evaluation and augmentation domains.

previous_domains = set()

previous_files = [
    BASE_DIR / "evaluation" / "trusted_homepages.csv",
    BASE_DIR / "evaluation" / "homepage_candidate_pool.csv",
    BASE_DIR / "dataset" / "augmentation" /
    "legitimate_homepages_candidates.csv"
]

for file in previous_files:

    if file.exists() and file.stat().st_size > 0:

        previous = pd.read_csv(file)

        if "url" in previous.columns:

            previous_domains.update(
                previous["url"].dropna().apply(
                    get_registered_domain
                )
            )

# Additional legitimate URLs used during V3 smoke testing.

previous_domains.update([
    "adobe.com",
    "ibm.com",
    "nvidia.com",
    "google.com",
    "github.com"
])

print("Previously evaluated domains:", len(previous_domains))


# Load candidate URLs.

candidates = pd.read_csv(CANDIDATE_PATH)

candidates = candidates.drop_duplicates(
    subset=["url"]
).copy()

candidates["registered_domain"] = (
    candidates["url"].apply(get_registered_domain)
)

candidates["exists_in_original"] = (
    candidates["registered_domain"].isin(original_domains)
)

candidates["previously_evaluated"] = (
    candidates["registered_domain"].isin(previous_domains)
)

candidates["eligible_for_verification"] = (
    ~candidates["exists_in_original"] &
    ~candidates["previously_evaluated"] &
    candidates["registered_domain"].ne("")
)

candidates["verification_status"] = "pending"

candidates["evaluation_status"] = "not_approved"

print("\nCANDIDATE REVIEW")
print("-" * 65)

for _, row in candidates.iterrows():

    status = (
        "ELIGIBLE"
        if row["eligible_for_verification"]
        else "EXCLUDED"
    )

    print(
        f"{row['registered_domain']:30s} | {status}"
    )

eligible = int(
    candidates["eligible_for_verification"].sum()
)

print("\nSUMMARY")
print("-" * 65)

print("Total candidates:", len(candidates))
print("Eligible candidates:", eligible)
print("Excluded candidates:", len(candidates) - eligible)
print("Verified candidates: 0")

candidates.to_csv(OUTPUT_PATH, index=False)

print("\nReview saved to:", OUTPUT_PATH)
print("Overlap check completed successfully.")
