
import joblib
import pandas as pd

from feature_extraction import extract_features

MODEL_PATH = "models/phishguard_live_model.pkl"

print("Loading PhishGuard Live Model...")

saved_data = joblib.load(MODEL_PATH)
model = saved_data["model"]
feature_names = saved_data["feature_names"]

print("Model loaded successfully!")

while True:
    url = input("\nEnter URL (or type exit): ").strip()

    if url.lower() == "exit":
        print("PhishGuard testing completed.")
        break

    if not url:
        print("Please enter a URL.")
        continue

    try:
        features = extract_features(url)

        # Display extracted features
        print("\nExtracted URL Features:")
        for name, value in features.items():
            print(f"{name}: {value}")

        # Display important model features
        print("\nTop 10 Important Model Features:")

        importance = sorted(
            zip(feature_names, model.feature_importances_),
            key=lambda item: item[1],
            reverse=True
        )

        for name, score in importance[:10]:
            print(f"{name}: {score:.4f}")

        # Prepare model input
        input_data = pd.DataFrame(
            [features],
            columns=feature_names
        )

        prediction = model.predict(input_data)[0]
        probabilities = model.predict_proba(input_data)[0]

        confidence = probabilities[prediction] * 100

        print("\n========== SCAN RESULT ==========")

        if prediction == 1:
            print("WARNING: Potential Phishing URL!")
        else:
            print("Result: Likely Legitimate URL")

        print(f"Model confidence: {confidence:.2f}%")

    except Exception as error:
        print("Unable to scan URL:", error)
