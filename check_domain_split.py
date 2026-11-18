
import pandas as pd
import tldextract

from sklearn.model_selection import GroupShuffleSplit

df = pd.read_csv("dataset/phishstorm_clean.csv")
df = df.drop_duplicates(subset=["domain"]).reset_index(drop=True)


def get_registered_domain(url):
    url = str(url).strip()

    if "://" not in url:
        url = "http://" + url

    extracted = tldextract.extract(url)

    if extracted.domain and extracted.suffix:
        return extracted.domain + "." + extracted.suffix

    return extracted.domain or url


df["registered_domain"] = df["domain"].apply(
    get_registered_domain
)

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42
)

train_idx, test_idx = next(
    splitter.split(
        df,
        df["label"],
        groups=df["registered_domain"]
    )
)

train_domains = set(
    df.iloc[train_idx]["registered_domain"]
)

test_domains = set(
    df.iloc[test_idx]["registered_domain"]
)

for domain in ["google.com", "github.com"]:
    print("\nDomain:", domain)

    if domain in train_domains:
        print("Allocation: TRAINING SET")
    elif domain in test_domains:
        print("Allocation: TESTING SET")
    else:
        print("Allocation: NOT FOUND")

    matching = df[df["registered_domain"] == domain]

    print("Total dataset URLs:", len(matching))
    print("Legitimate:", int((matching["label"] == 0).sum()))
    print("Phishing:", int((matching["label"] == 1).sum()))

