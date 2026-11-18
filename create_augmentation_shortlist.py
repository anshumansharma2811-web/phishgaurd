
import pandas as pd

INPUT_PATH = "dataset/augmentation/augmentation_review.csv"
OUTPUT_PATH = "dataset/augmentation/augmentation_shortlist.csv"

df = pd.read_csv(INPUT_PATH)

shortlist = df[
    (df["exists_in_original"] == False) &
    (df["verification_status"] == "reachable_same_domain")
].copy()

shortlist["label_review"] = "pending_independent_verification"
shortlist["training_status"] = "not_approved"

shortlist.to_csv(OUTPUT_PATH, index=False)

print("\nPHISHGUARD AUGMENTATION SHORTLIST")
print("=" * 65)

print(
    shortlist[
        [
            "url",
            "registered_domain",
            "label_review",
            "training_status"
        ]
    ].to_string(index=False)
)

print("\nShortlisted candidates:", len(shortlist))
print("Saved to:", OUTPUT_PATH)
print("\nShortlist preparation completed.")
