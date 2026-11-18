
import pandas as pd

DATASET_PATH = "dataset/phishstorm_clean.csv"

df = pd.read_csv(DATASET_PATH)

df = df.dropna(subset=["domain", "label"]).copy()

df["domain"] = df["domain"].astype(str).str.strip()

df["label"] = pd.to_numeric(
    df["label"],
    errors="coerce"
)

df = df[df["label"].isin([0, 1])]

print("\nPHISHGUARD LABEL CONFLICT ANALYSIS")
print("=" * 70)

print("Total records:", len(df))

unique_urls = df["domain"].nunique()

print("Unique URL strings:", unique_urls)

label_counts = df.groupby("domain")["label"].nunique()

conflicting_urls = label_counts[label_counts > 1].index

print("URLs with conflicting labels:", len(conflicting_urls))

if len(conflicting_urls) > 0:

    print("\nCONFLICTING URL EXAMPLES")
    print("-" * 70)

    conflicts = df[
        df["domain"].isin(conflicting_urls)
    ]

    print(
        conflicts[
            ["domain", "label"]
        ].head(20).to_string(index=False)
    )

else:
    print("\nNo exact URL label conflicts found.")

duplicate_count = df.duplicated(
    subset=["domain"]
).sum()

print("\nDuplicate URL records:", duplicate_count)

print("\nAnalysis completed.")
