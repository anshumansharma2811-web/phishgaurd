
import os
import pandas as pd

from risk_classifier import load_model, analyze_url

DATASET_PATH = "evaluation/trusted_homepages.csv"
OUTPUT_PATH = "evaluation/homepage_results.csv"

print("\nPHISHGUARD HOMEPAGE EVALUATION")
print("=" * 65)

# Load dataset
df = pd.read_csv(DATASET_PATH)

required_columns = {"url", "label"}

if not required_columns.issubset(df.columns):
    raise ValueError("CSV must contain url and label columns.")

# Load trained model
print("\nLoading contextual model...")

model, feature_names = load_model()

results = []

print("\nEvaluating URLs...")

for _, row in df.iterrows():

    url = str(row["url"]).strip()
    actual_label = int(row["label"])

    result = analyze_url(url, model, feature_names)

    predicted_label = (
        1 if result["prediction"] == "PHISHING" else 0
    )

    correct = predicted_label == actual_label

    results.append({
        "url": url,
        "actual_label": actual_label,
        "predicted_label": predicted_label,
        "phishing_score": round(
            result["phishing_score"] * 100, 2
        ),
        "risk_level": result["risk_level"],
        "correct": correct
    })

    status = "CORRECT" if correct else "INCORRECT"

    print(
        f"{url:40s} "
        f"Score: {result['phishing_score'] * 100:6.2f}% "
        f"{status}"
    )

results_df = pd.DataFrame(results)

total = len(results_df)
correct_count = int(results_df["correct"].sum())
incorrect_count = total - correct_count

false_positives = int(
    (
        (results_df["actual_label"] == 0) &
        (results_df["predicted_label"] == 1)
    ).sum()
)

accuracy = correct_count / total * 100 if total else 0

print("\n" + "=" * 65)
print("EVALUATION SUMMARY")
print("=" * 65)

print("Total URLs:", total)
print("Correct predictions:", correct_count)
print("Incorrect predictions:", incorrect_count)
print("False positives:", false_positives)
print(f"Accuracy: {accuracy:.2f}%")

os.makedirs("evaluation", exist_ok=True)

results_df.to_csv(OUTPUT_PATH, index=False)

print("\nResults saved to:", OUTPUT_PATH)
print("\nEvaluation completed.")
