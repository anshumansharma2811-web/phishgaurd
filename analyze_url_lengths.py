
import pandas as pd
from feature_extraction import extract_features

df = pd.read_csv("dataset/phishstorm_clean.csv")

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
            "url_length": features["url_length"],
            "path_length": features["path_length"],
            "hostname_length": features["hostname_length"]
        })

    except (ValueError, TypeError):
        continue

data = pd.DataFrame(records)

print("\nURL LENGTH DISTRIBUTION")
print("=" * 60)

for label, name in [(0, "LEGITIMATE"), (1, "PHISHING")]:

    subset = data[data["label"] == label]

    print(f"\n{name} URLs: {len(subset)}")

    print("Average URL length:", round(subset["url_length"].mean(), 2))
    print("Median URL length:", round(subset["url_length"].median(), 2))
    print("Average path length:", round(subset["path_length"].mean(), 2))

    for limit in [20, 30, 40, 50, 100]:
        count = (subset["url_length"] <= limit).sum()
        percentage = count / len(subset) * 100

        print(
            f"URLs <= {limit} characters: "
            f"{count} ({percentage:.2f}%)"
        )

    no_path = (subset["path_length"] == 0).sum()

    print(
        f"URLs without a path: {no_path} "
        f"({no_path / len(subset) * 100:.2f}%)"
    )
