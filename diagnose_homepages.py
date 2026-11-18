
from risk_classifier import load_model, analyze_url

model, feature_names = load_model()

urls = [
    "https://www.google.com",
    "https://www.google.com/",
    "https://www.google.com/search",
    "https://www.google.com/search?q=python",
    "https://www.google.com/about/",
    "https://www.github.com",
    "https://www.github.com/",
    "https://www.github.com/features",
    "https://www.python.org",
    "https://www.python.org/downloads/"
]

print("\nPHISHGUARD HOMEPAGE DIAGNOSTIC")
print("=" * 75)

for url in urls:
    result = analyze_url(url, model, feature_names)

    print(f"\nURL: {url}")
    print(f"Phishing Score: {result['phishing_score'] * 100:.2f}%")
    print(f"Prediction: {result['prediction']}")
    print(f"Risk Level: {result['risk_level']}")

print("\nDiagnostic completed.")
