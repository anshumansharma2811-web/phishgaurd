
import pandas as pd
from feature_extraction import extract_features

DATASET_PATH = "dataset/phishstorm_clean.csv"

df = pd.read_csv(DATASET_PATH)

df = df.dropna(subset=["domain", "label"]).copy()
df["label"] = pd.to_numeric(df["label"], errors="coerce")
df = df[df["label"].isin([0, 1])]
df = df.drop_duplicates(subset=["domain"])

records = []

for url, label in zip(df["domain"], df["label"]):
    try:
        features = extract_features(url)

        records.append({
            "label": int(label),
            "path_length": features["path_length"],
            "url_length": features["url_length"]
        })

    except (ValueError, TypeError):
        continue

data = pd.DataFrame(records)

print("\nPHISHGUARD SHORT PATH ANALYSIS")
print("=" * 65)

for label, name in [(0, "LEGITIMATE"), (1, "PHISHING")]:

    subset = data[data["label"] == label]

    print(f"\n{name} URLS")
    print("-" * 45)

    for length in range(0, 11):
        count = int((subset["path_length"] == length).sum())

        percentage = count / len(subset) * 100

        print(
            f"Path length {length:2d}: "
            f"{count:6d} URLs ({percentage:6.2f}%)"
        )

    short_paths = int((subset["path_length"] <= 5).sum())

    print(
        f"\nTotal with path length <= 5: "
        f"{short_paths} "
        f"({short_paths / len(subset) * 100:.2f}%)"
    )

print("\nAnalysis completed.")
