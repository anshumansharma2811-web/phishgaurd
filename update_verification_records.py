
import pandas as pd
from datetime import date

FILE_PATH = "dataset/augmentation/augmentation_shortlist.csv"

df = pd.read_csv(FILE_PATH)

verified_urls = [
    "https://www.sqlite.org",
    "https://www.rust-lang.org"
]

df["manual_access_check"] = df["url"].apply(
    lambda url: "opened_in_browser"
    if url in verified_urls
    else "not_checked"
)

df["manual_check_date"] = date.today().isoformat()

# Browser accessibility alone does not verify ownership.
df["label_review"] = "pending_independent_verification"
df["training_status"] = "not_approved"

df.to_csv(FILE_PATH, index=False)

print("\nPHISHGUARD MANUAL ACCESS CHECK")
print("=" * 75)

print(
    df[
        [
            "registered_domain",
            "manual_access_check",
            "label_review",
            "training_status"
        ]
    ].to_string(index=False)
)

print("\nRecords updated successfully.")
print("File:", FILE_PATH)
