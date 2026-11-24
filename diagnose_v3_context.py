
import joblib
import pandas as pd

from pathlib import Path
from feature_extraction import extract_features


BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = (
    BASE_DIR / "models" /
    "phishguard_v3_c_model.pkl"
)

saved = joblib.load(MODEL_PATH)

model = saved["model"]
feature_names = saved["feature_names"]

phishing_index = list(model.classes_).index(1)


def get_score(features):

    X = pd.DataFrame(
        [[features[name] for name in feature_names]],
        columns=feature_names
    )

    return model.predict_proba(X)[0][phishing_index] * 100


url_pairs = [
    (
        "GitHub",
        "https://github.com",
        "https://github.com/login"
    ),
    (
        "Google Forms",
        "https://docs.google.com",
        "https://docs.google.com/forms/"
    ),
    (
        "Google Accounts",
        "https://google.com",
        "https://accounts.google.com"
    )
]


print("=" * 75)
print("PHISHGUARD V3-C CONTEXTUAL FEATURE DIAGNOSIS")
print("=" * 75)


for name, base_url, target_url in url_pairs:

    base_features = extract_features(base_url)
    target_features = extract_features(target_url)

    base_score = get_score(base_features)
    target_score = get_score(target_features)

    print("\n" + "=" * 75)
    print("WEBSITE:", name)
    print("=" * 75)

    print("Base URL:", base_url)
    print(f"Base Score: {base_score:.2f}%")

    print("\nTarget URL:", target_url)
    print(f"Target Score: {target_score:.2f}%")

    changed_features = [
        feature
        for feature in feature_names
        if base_features[feature] != target_features[feature]
    ]

    print("\nCHANGED FEATURES")
    print("-" * 75)

    for feature in changed_features:

        print(
            f"{feature:30s} "
            f"{base_features[feature]} -> "
            f"{target_features[feature]}"
        )

    print("\nINDIVIDUAL FEATURE SENSITIVITY")
    print("-" * 75)

    for feature in changed_features:

        modified = target_features.copy()

        modified[feature] = base_features[feature]

        score = get_score(modified)

        difference = score - target_score

        print(
            f"{feature:30s} "
            f"Score: {score:6.2f}% "
            f"| Change: {difference:+.2f}"
        )


print("\n" + "=" * 75)
print("TOP 15 MODEL FEATURE IMPORTANCES")
print("=" * 75)

importance = pd.Series(
    model.feature_importances_,
    index=feature_names
).sort_values(ascending=False)

for feature, value in importance.head(15).items():

    print(f"{feature:30s} {value * 100:.2f}%")

print("\nDiagnosis completed successfully.")
