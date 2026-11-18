
import joblib
import pandas as pd

from feature_extraction import extract_features


MODEL_PATH = "models/phishguard_context_model.pkl"

# Initial application risk bands
LOW_RISK_LIMIT = 0.30
HIGH_RISK_LIMIT = 0.70

# Existing model decision threshold
DETECTION_THRESHOLD = 0.50


def load_model():
    saved = joblib.load(MODEL_PATH)

    return saved["model"], saved["feature_names"]


def classify_risk(score):

    if score < LOW_RISK_LIMIT:
        return "LOW RISK"

    elif score < HIGH_RISK_LIMIT:
        return "MEDIUM RISK"

    else:
        return "HIGH RISK"


def generate_explanations(features):

    reasons = []

    if features.get("has_ip", 0):
        reasons.append("URL uses an IP address instead of a domain name.")

    if features.get("has_punycode", 0):
        reasons.append("URL contains a potentially deceptive encoded domain.")

    if features.get("has_shortening_service", 0):
        reasons.append("URL uses a URL shortening service.")

    if features.get("suspicious_keyword_count", 0) > 0:
        reasons.append("URL contains suspicious keywords.")

    if features.get("brand_impersonation_count", 0) > 0:
        reasons.append("URL contains possible brand impersonation indicators.")

    if features.get("has_login_path", 0):
        reasons.append("URL contains a login-related path.")

    if features.get("has_form_path", 0):
        reasons.append("URL contains a form-related path.")

    if features.get("has_account_path", 0):
        reasons.append("URL contains an account-related path.")

    if features.get("has_encoded_characters", 0):
        reasons.append("URL contains encoded characters.")

    if features.get("has_double_slash_path", 0):
        reasons.append("URL contains an unusual double-slash path.")

    if not features.get("uses_https", 0):
        reasons.append("URL does not use HTTPS.")

    if not reasons:
        reasons.append("No strong suspicious URL patterns were detected.")

    return reasons


def analyze_url(url, model, feature_names):

    features = extract_features(url)

    # Maintain the exact feature order used during training.
    input_data = pd.DataFrame(
        [[features[name] for name in feature_names]],
        columns=feature_names
    )

    probabilities = model.predict_proba(input_data)[0]

    phishing_index = list(model.classes_).index(1)

    phishing_score = float(probabilities[phishing_index])

    risk_level = classify_risk(phishing_score)

    prediction = (
        "PHISHING"
        if phishing_score >= DETECTION_THRESHOLD
        else "LEGITIMATE"
    )

    reasons = generate_explanations(features)

    return {
        "url": url,
        "phishing_score": phishing_score,
        "risk_level": risk_level,
        "prediction": prediction,
        "reasons": reasons
    }


def main():

    print("=" * 55)
    print("             PHISHGUARD URL ANALYZER")
    print("=" * 55)

    print("\nLoading AI detection model...")

    model, feature_names = load_model()

    print("Model loaded successfully!")

    while True:

        print("\n" + "-" * 55)

        url = input("Enter URL (or type 'exit' to quit): ").strip()

        if url.lower() == "exit":
            print("\nThank you for using PhishGuard!")
            break

        if not url:
            print("Please enter a URL.")
            continue

        try:
            result = analyze_url(url, model, feature_names)

            print("\n" + "=" * 55)
            print("             ANALYSIS RESULT")
            print("=" * 55)

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

            print("\nNote: Model predictions are estimates,")
            print("not guarantees that a URL is safe or malicious.")

        except Exception as error:
            print("\nUnable to analyze this URL.")
            print("Error:", error)


if __name__ == "__main__":
    main()
