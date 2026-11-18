
import pandas as pd
from datetime import date

INPUT_PATH = "dataset/augmentation/augmentation_shortlist.csv"
OUTPUT_PATH = "dataset/augmentation/official_source_evidence.csv"

df = pd.read_csv(INPUT_PATH)

official_sources = {
    "sqlite.org": {
        "project": "SQLite",
        "source_url": "https://www.sqlite.org/",
        "evidence_type": "project_homepage",
    },
    "rust-lang.org": {
        "project": "Rust Programming Language",
        "source_url": "https://www.rust-lang.org/",
        "evidence_type": "project_homepage",
    }
}

records = []

for _, row in df.iterrows():
    domain = row["registered_domain"]

    if domain not in official_sources:
        continue

    source = official_sources[domain]

    records.append({
        "url": row["url"],
        "registered_domain": domain,
        "project_name": source["project"],
        "official_source_url": source["source_url"],
        "evidence_type": source["evidence_type"],
        "browser_access": row["manual_access_check"],
        "evidence_recorded_date": date.today().isoformat(),
        "independent_ownership_verified": False,
        "training_status": "not_approved"
    })

evidence = pd.DataFrame(records)

evidence.to_csv(OUTPUT_PATH, index=False)

print("\nPHISHGUARD OFFICIAL SOURCE EVIDENCE")
print("=" * 75)

print(
    evidence[
        [
            "registered_domain",
            "project_name",
            "evidence_type",
            "independent_ownership_verified",
            "training_status"
        ]
    ].to_string(index=False)
)

print("\nEvidence records:", len(evidence))
print("Saved to:", OUTPUT_PATH)
print("\nStep 21 completed.")
