
import joblib
import pandas as pd

from feature_extraction import extract_features

saved = joblib.load("models/phishguard_context_model.pkl")
model = saved["model"]
feature_names = saved["feature_names"]

test_urls = [
    # Google URLs
    "https://www.google.com",
    "https://www.google.com/services/",
    "https://code.google.com/chromium/",
    "https://docs.google.com/spreadsheet/viewform",
    "https://docs.google.com/spreadsheet/embeddedform",
    "https://docs.google.com/spreadsheet/formResponse",
    "https://accounts.google.com/ServiceLogin",
    "https://sites.google.com/site/valleyvistafarm/",
    "https://groups.google.com/group/kaas",

    # Other trusted platforms
    "https://github.com",
    "https://github.com/jberkel/sms-backup-plus/",

    # Suspicious-looking URLs
    "http://paypal-login-security.example.com/verify",
    "http://192.168.1.1/login",
    "http://xn--pple-43d.com",
]

print("\nPHISHGUARD GOOGLE URL EVALUATION")
print("=" * 75)

for url in test_urls:
    features = extract_features(url)
    data = pd.DataFrame([features], columns=feature_names)

    probabilities = model.predict_proba(data)[0]
    prediction = model.predict(data)[0]

    print("-" * 75)
    print("URL:", url)
    print("Prediction:", "Phishing" if prediction == 1 else "Legitimate")
    print(f"Legitimate probability: {probabilities[0] * 100:.2f}%")
    print(f"Phishing probability:   {probabilities[1] * 100:.2f}%")
