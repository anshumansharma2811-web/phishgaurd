
import pandas as pd
import tldextract
from urllib.parse import urlsplit

INPUT = "dataset/augmentation/legitimate_homepages_candidates.csv"
ORIGINAL = "dataset/phishstorm_clean.csv"
OUTPUT = "evaluation/homepage_candidate_pool.csv"


def get_registered_domain(url):
    url = str(url).strip()

    if "://" not in url:
        url = "http://" + url

    hostname = urlsplit(url).hostname or ""
    ext = tldextract.extract(hostname)

    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"

    return hostname.lower()


candidates = pd.read_csv(INPUT)
original = pd.read_csv(ORIGINAL)

original_domains = set(
    original["domain"].dropna().apply(get_registered_domain)
)

candidates["registered_domain"] = (
    candidates["url"].apply(get_registered_domain)
)

# Exclude domains already present in the original dataset.
pool = candidates[
    ~candidates["registered_domain"].isin(original_domains)
].copy()

# Exclude domains already used in the training shortlist.
shortlist = pd.read_csv(
    "dataset/augmentation/augmentation_shortlist.csv"
)

shortlist_domains = set(shortlist["registered_domain"])

pool = pool[
    ~pool["registered_domain"].isin(shortlist_domains)
].copy()

pool["evaluation_status"] = "pending_verification"

pool.to_csv(OUTPUT, index=False)

print("\nPHISHGUARD HOMEPAGE EVALUATION POOL")
print("=" * 70)

print("Candidate URLs:", len(candidates))
print("Independent evaluation candidates:", len(pool))

print("\nSaved to:", OUTPUT)

if pool.empty:
    print(
        "\nNo eligible independent candidates remain."
        "\nCollect new domains for a separate evaluation pool."
    )
else:
    print(pool.to_string(index=False))

print("\nStep 22 completed.")
