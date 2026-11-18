
import os
import joblib
import pandas as pd
import tldextract

from urllib.parse import urlsplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

from feature_extraction import extract_features


DATASET_PATH = "dataset/phishstorm_clean.csv"

# Save separately to preserve the original model.
MODEL_PATH = "models/phishguard_context_model.pkl"


def get_registered_domain(url):
    """Get registered domain for group-based splitting."""

    url = str(url).strip()

    if "://" not in url:
        url = "http://" + url

    hostname = urlsplit(url).hostname

    if not hostname:
        return url.lower()

    extracted = tldextract.extract(hostname)

    if extracted.domain and extracted.suffix:
        return extracted.domain + "." + extracted.suffix

    return hostname.lower()


print("Loading PhishGuard dataset...")

df = pd.read_csv(DATASET_PATH)

df = df.dropna(subset=["domain", "label"]).copy()
df["label"] = pd.to_numeric(df["label"], errors="coerce")
df = df.dropna(subset=["label"])
df = df[df["label"].isin([0, 1])].copy()

df = df.drop_duplicates(subset=["domain"]).reset_index(drop=True)

print("Extracting URL features...")

feature_rows = []
valid_indices = []

for index, url in enumerate(df["domain"]):
    try:
        features = extract_features(url)
        feature_rows.append(features)
        valid_indices.append(index)

    except (ValueError, TypeError) as error:
        print(f"Skipping invalid URL: {url} ({error})")

df = df.iloc[valid_indices].reset_index(drop=True)

X = pd.DataFrame(feature_rows)
y = df["label"].astype(int)

feature_names = list(X.columns)

print("\nDataset information:")
print("Total URLs:", len(X))
print("Total features:", len(feature_names))
print("Legitimate URLs:", int((y == 0).sum()))
print("Phishing URLs:", int((y == 1).sum()))

print("\nSplitting data by registered domain...")

groups = df["domain"].apply(get_registered_domain)

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42
)

train_indices, test_indices = next(
    splitter.split(X, y, groups=groups)
)

X_train = X.iloc[train_indices]
X_test = X.iloc[test_indices]

y_train = y.iloc[train_indices]
y_test = y.iloc[test_indices]

train_domains = set(groups.iloc[train_indices])
test_domains = set(groups.iloc[test_indices])

print("Training URLs:", len(X_train))
print("Testing URLs:", len(X_test))
print("Overlapping domains:", len(train_domains & test_domains))

if train_domains & test_domains:
    raise RuntimeError("Domain leakage detected!")

print("\nTraining contextual Random Forest model...")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

model.fit(X_train, y_train)

print("\nEvaluating model...")

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print(f"\nDomain-based Accuracy: {accuracy * 100:.2f}%")

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        target_names=["Legitimate", "Phishing"],
        zero_division=0
    )
)

print("\nTop 15 Important Features:")

importance = sorted(
    zip(feature_names, model.feature_importances_),
    key=lambda item: item[1],
    reverse=True
)

for name, score in importance[:15]:
    print(f"{name}: {score:.4f}")

os.makedirs("models", exist_ok=True)

joblib.dump(
    {
        "model": model,
        "feature_names": feature_names,
        "feature_version": 2
    },
    MODEL_PATH
)

print("\nContextual model saved successfully:", MODEL_PATH)
