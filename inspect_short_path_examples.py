
import pandas as pd
from urllib.parse import urlsplit

DATASET_PATH = "dataset/phishstorm_clean.csv"

df = pd.read_csv(DATASET_PATH)

df = df.dropna(subset=["domain", "label"]).copy()
df["label"] = pd.to_numeric(df["label"], errors="coerce")
df = df[df["label"].isin([0, 1])]
df = df.drop_duplicates(subset=["domain"])


def get_path_length(url):
    url = str(url).strip()

    if "://" not in url:
        url = "http://" + url

    return len(urlsplit(url).path)


df["path_length"] = df["domain"].apply(get_path_length)

print("\nPHISHGUARD SHORT PATH EXAMPLES")
print("=" * 75)

for label, name in [(0, "LEGITIMATE"), (1, "PHISHING")]:

    subset = df[df["label"] == label]

    print(f"\n{name} EXAMPLES")
    print("-" * 75)

    for length in [0, 1, 2, 3, 4, 5]:

        examples = subset[
            subset["path_length"] == length
        ]["domain"].head(5)

        print(f"\nPath length {length}:")

        if examples.empty:
            print("  No examples")
        else:
            for url in examples:
                print(" ", url)

print("\nInspection completed.")
