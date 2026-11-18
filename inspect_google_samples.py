
import pandas as pd

df = pd.read_csv("dataset/phishstorm_clean.csv")

google = df[
    df["domain"].str.contains(
        r"(^|[./])google\.com([/:?]|$)",
        case=False,
        regex=True,
        na=False
    )
]

print("\nGOOGLE DATASET SAMPLES")
print("=" * 60)

print("\nLEGITIMATE URLS:")
print(
    google[google["label"] == 0]["domain"]
    .head(15)
    .to_string(index=False)
)

print("\nPHISHING-LABELLED URLS:")
print(
    google[google["label"] == 1]["domain"]
    .head(15)
    .to_string(index=False)
)

print("\nLABEL COUNTS:")
print(google["label"].value_counts())
