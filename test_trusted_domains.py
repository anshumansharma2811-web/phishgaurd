
from risk_classifier import load_model, analyze_url

test_urls = [
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.github.com",
    "https://www.microsoft.com",
    "https://www.amazon.com",
    "https://www.wikipedia.org",
    "https://www.apple.com",
    "https://www.cloudflare.com",
    "https://www.python.org",
    "https://www.openai.com"
]

print("\nPHISHGUARD - TRUSTED DOMAIN SANITY CHECK")
print("=" * 75)

model, feature_names = load_model()

false_positives = 0

for url in test_urls:

    result = analyze_url(url, model, feature_names)

    print(f"\nURL: {url}")
    print(f"Phishing Score: {result['phishing_score'] * 100:.2f}%")
    print(f"Prediction: {result['prediction']}")
    print(f"Risk Level: {result['risk_level']}")

    if result["prediction"] == "PHISHING":
        false_positives += 1

print("\n" + "=" * 75)
print("Total URLs Tested:", len(test_urls))
print("URLs Flagged as Phishing:", false_positives)
print("URLs Classified as Legitimate:", len(test_urls) - false_positives)

print("\nNote: This is a small sanity check, not a formal accuracy test.")

