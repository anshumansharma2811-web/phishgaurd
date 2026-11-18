
import pandas as pd
import tldextract
from urllib.parse import urlsplit

ORIGINAL = "dataset/phishstorm_clean.csv"
CANDIDATES = "dataset/augmentation/legitimate_homepages_candidates.csv"
VERIFICATION = "dataset/augmentation/homepage_verification_report.csv"
OUTPUT = "dataset/augmentation/augmentation_review.csv"


def registered_domain(url):
    url = str(url).strip()

    if "://" not in url:
        url = "http://" + url

    hostname = urlsplit(url).hostname or ""
    ext = tldextract.extract(hostname)

    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"

    return hostname.lower()


original = pd.read_csv(ORIGINAL)
candidates = pd.read_csv(CANDIDATES)
verification = pd.read_csv(VERIFICATION)

original_domains = set(
    original["domain"].dropna().apply(registered_domain)
)


# Rename the candidate's original verification column
# to avoid a conflict during the merge.

candidates = candidates.rename(
    columns={
        "verification_status": "candidate_verification_status"
    }
)

review = candidates.merge(
    verification[
        [
            "url",
            "http_status",
            "final_url",
            "verification_status"
        ]
    ],
    on="url",
    how="left",
    validate="one_to_one"
)


review["registered_domain"] = review["url"].apply(
    registered_domain
)

review["exists_in_original"] = review[
    "registered_domain"
].isin(original_domains)

review["label_review"] = "pending_independent_verification"

review["training_status"] = "not_approved"

review.to_csv(OUTPUT, index=False)

print("\nPHISHGUARD AUGMENTATION REVIEW")
print("=" * 75)

print(
    review[
        [
            "registered_domain",
            "verification_status",
            "exists_in_original",
            "training_status"
        ]
    ].to_string(index=False)
)

print("\nTotal candidates:", len(review))
print(
    "Already in original dataset:",
    int(review["exists_in_original"].sum())
)
print(
    "Not in original dataset:",
    int((~review["exists_in_original"]).sum())
)

print("\nReport saved to:", OUTPUT)
print("Review preparation completed.")
