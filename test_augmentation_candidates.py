
import pandas as pd
from risk_classifier import load_model, analyze_url

INPUT_PATH = "dataset/augmentation/legitimate_homepages_candidates.csv"

df = pd.read_csv(INPUT_PATH)

model, feature_names = load_model()

print("\nPHISHGUARD AUGMENTATION CANDIDATE TEST")
print("=" * 75)

results = []

for _, row in df.iterrows():
    url = str(row["url"]).strip()

    result = analyze_url(url, model, feature_names)

    results.append({
        "url": url,
        "score": result["phishing_score"] * 100,
        "prediction": result["prediction"],
        "risk": result["risk_level"]
    })

    print(f"\nURL: {url}")
    print(f"Phishing Score: {result['phishing_score'] * 100:.2f}%")
    print(f"Prediction: {result['prediction']}")
    print(f"Risk Level: {result['risk_level']}")

print("\n" + "=" * 75)
print("SUMMARY")
print("=" * 75)

results_df = pd.DataFrame(results)

print("Total candidates:", len(results_df))
print(
    "Flagged as phishing:",
    int((results_df["prediction"] == "PHISHING").sum())
)
print(
    "Classified as legitimate:",
    int((results_df["prediction"] == "LEGITIMATE").sum())
)

print("\nCandidate test completed.")
