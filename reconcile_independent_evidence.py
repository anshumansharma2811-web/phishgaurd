import pandas as pd

from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

EVALUATION_DIR = BASE_DIR / "evaluation"

REVIEW_PATH = (
    EVALUATION_DIR / "legitimate_candidate_review.csv"
)

EVIDENCE_PATH = (
    EVALUATION_DIR / "independent_source_evidence.csv"
)

OUTPUT_PATH = (
    EVALUATION_DIR / "independent_verification_queue.csv"
)


print("=" * 65)
print("PHISHGUARD INDEPENDENT EVIDENCE RECONCILIATION")
print("=" * 65)


# ===== LOAD EXISTING RECORDS =====

review = pd.read_csv(REVIEW_PATH)

evidence = pd.read_csv(EVIDENCE_PATH)

if review["url"].duplicated().any():
    raise ValueError("Duplicate URLs in candidate review.")

if evidence["url"].duplicated().any():
    raise ValueError("Duplicate URLs in source evidence.")


# ===== SELECT ELIGIBLE CANDIDATES =====

eligible = review[
    review["eligible_for_verification"] == True
].copy()

eligible = eligible[
    ["url", "candidate_label", "category",
     "registered_domain"]
]


# ===== MATCH SOURCE EVIDENCE =====

evidence = evidence[
    ["url", "label", "source", "verification_date"]
]

merged = eligible.merge(
    evidence,
    on="url",
    how="left",
    validate="one_to_one"
)

has_evidence = (
    merged["source"].fillna("").str.strip().ne("") &
    merged["verification_date"].fillna("").str.strip().ne("") &
    merged["label"].eq(merged["candidate_label"])
)

merged["evidence_status"] = "pending"

merged.loc[
    has_evidence,
    "evidence_status"
] = "evidence_recorded"


# Evidence must still be reviewed manually.

merged["evaluation_status"] = "not_approved"


# ===== DISPLAY RESULTS =====

print("\nVERIFICATION QUEUE")
print("-" * 65)

for _, row in merged.iterrows():

    print(
        f"{row['registered_domain']:30s} | "
        f"{row['evidence_status']}"
    )


recorded = int(has_evidence.sum())

pending = len(merged) - recorded

print("\nSUMMARY")
print("-" * 65)

print("Eligible candidates:", len(merged))
print("Evidence recorded:", recorded)
print("Evidence pending:", pending)
print("Approved samples: 0")


# ===== SAVE VERIFICATION QUEUE =====

merged.to_csv(
    OUTPUT_PATH,
    index=False
)

print("\nVerification queue saved to:")
print(OUTPUT_PATH)

print("\nReconciliation completed successfully.")
