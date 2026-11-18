
import pandas as pd
import tldextract
from urllib.parse import urlsplit

ORIGINAL_PATH = "dataset/phishstorm_clean.csv"
CANDIDATE_PATH = "dataset/augmentation/legitimate_homepages_candidates.csv"
EVALUATION_PATH = "evaluation/trusted_homepages.csv"


def registered_domain(url):
    url = str(url).strip()

    if "://" not in url:
        url = "http://" + url

    hostname = urlsplit(url).hostname

    if not hostname:
        return ""

    extracted = tldextract.extract(hostname)

    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"

    return hostname.lower()


print("\nPHISHGUARD AUGMENTATION OVERLAP CHECK")
print("=" * 65)

original = pd.read_csv(ORIGINAL_PATH)
candidates = pd.read_csv(CANDIDATE_PATH)
evaluation = pd.read_csv(EVALUATION_PATH)

original_domains = set(
    original["domain"].dropna().apply(registered_domain)
)

evaluation_domains = set(
    evaluation["url"].dropna().apply(registered_domain)
)

print("Original registered domains:", len(original_domains))
print("Evaluation registered domains:", len(evaluation_domains))

print("\nCANDIDATE DOMAIN CHECK")
print("-" * 65)

for _, row in candidates.iterrows():
    url = row["url"]
    domain = registered_domain(url)

    in_original = domain in original_domains
    in_evaluation = domain in evaluation_domains

    if in_evaluation:
        status = "OVERLAPS EVALUATION"
    elif in_original:
        status = "EXISTS IN ORIGINAL DATASET"
    else:
        status = "NO OVERLAP"

    print(f"{domain:30s} {status}")

print("\nCheck completed.")
