
import pandas as pd

from feature_extraction import extract_features
from risk_classifier import load_model


model, feature_names = load_model()

homepage = "https://www.google.com"
with_path = "https://www.google.com/search"

base_features = extract_features(homepage)
path_features = extract_features(with_path)


def get_phishing_score(features):

    X = pd.DataFrame(
        [[features[name] for name in feature_names]],
        columns=feature_names
    )

    probabilities = model.predict_proba(X)[0]

    phishing_index = list(model.classes_).index(1)

    return probabilities[phishing_index] * 100


print("\nPHISHGUARD FEATURE SENSITIVITY ANALYSIS")
print("=" * 75)

base_score = get_phishing_score(base_features)
path_score = get_phishing_score(path_features)

print(f"\nOriginal homepage score: {base_score:.2f}%")
print(f"URL with path score:     {path_score:.2f}%")

changed_features = [
    name
    for name in feature_names
    if base_features[name] != path_features[name]
]

print("\nCHANGING ONE FEATURE AT A TIME")
print("-" * 75)

for feature in changed_features:

    modified = base_features.copy()
    modified[feature] = path_features[feature]

    score = get_phishing_score(modified)

    print(
        f"{feature:30s} "
        f"{base_features[feature]} -> {path_features[feature]} "
        f"| Score: {score:.2f}%"
    )

print("\nCHANGING ALL FOUR FEATURES TOGETHER")
print("-" * 75)

modified = base_features.copy()

for feature in changed_features:
    modified[feature] = path_features[feature]

score = get_phishing_score(modified)

print(f"Combined score: {score:.2f}%")

print("\nAnalysis completed.")
