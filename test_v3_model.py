
import joblib

from pathlib import Path
from risk_classifier import analyze_url


BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = (
    BASE_DIR / "models" /
    "phishguard_v3_c_model.pkl"
)

print("=" * 60)
print("       PHISHGUARD V3-C MODEL TESTING")
print("=" * 60)

print("\nLoading V3-C model...")

saved = joblib.load(MODEL_PATH)

model = saved["model"]
feature_names = saved["feature_names"]

print("Model loaded successfully!")
print("Total features:", len(feature_names))
print("Model classes:", model.classes_)

while True:

    print("\n" + "-" * 60)

    url = input(
        "Enter URL (or type exit): "
    ).strip()

    if url.lower() == "exit":
        print("Testing completed.")
        break

    if not url:
        print("Please enter a URL.")
        continue

    try:

        result = analyze_url(
            url, model, feature_names
        )

        print("\n========== ANALYSIS RESULT ==========")

        print("URL:", result["url"])

        print(
            f"Phishing Score: "
            f"{result['phishing_score'] * 100:.2f}%"
        )

        print("Prediction:", result["prediction"])
        print("Risk Level:", result["risk_level"])

        print("\nDetection Indicators:")

        for reason in result["reasons"]:
            print("-", reason)

        print("\nNote: Predictions are estimates,")
        print("not guarantees of URL safety.")

    except Exception as error:

        print("Analysis failed:", error)
