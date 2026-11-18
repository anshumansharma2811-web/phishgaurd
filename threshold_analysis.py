
import joblib
import pandas as pd
import tldextract

from urllib.parse import urlsplit
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

from feature_extraction import extract_features


DATASET_PATH = "dataset/phishstorm_clean.csv"
MODEL_PATH = "models/phishguard_context_model.pkl"

THRESHOLDS = [0.30, 0.40, 0.50, 0.60]


def get_registered_domain(url):
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


print("Loading contextual model...")

saved = joblib.load(MODEL_PATH)
model = saved["model"]
feature_names = saved["feature_names"]

print("Loading dataset...")

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
        print(f"Skipping URL: {url} ({error})")

df = df.iloc[valid_indices].reset_index(drop=True)

X = pd.DataFrame(feature_rows)
X = X[feature_names]

y = df["label"].astype(int)

print("\nCreating the same domain-based test split...")

groups = df["domain"].apply(get_registered_domain)

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42
)

train_indices, test_indices = next(
    splitter.split(X, y, groups=groups)
)

train_domains = set(groups.iloc[train_indices])
test_domains = set(groups.iloc[test_indices])

if train_domains & test_domains:
    raise RuntimeError("Domain leakage detected!")

X_test = X.iloc[test_indices]
y_test = y.iloc[test_indices]

print("Testing URLs:", len(X_test))
print("Overlapping domains:", len(train_domains & test_domains))

print("\nGenerating phishing scores...")

probabilities = model.predict_proba(X_test)

phishing_class_index = list(model.classes_).index(1)
phishing_scores = probabilities[:, phishing_class_index]

print("\nTHRESHOLD COMPARISON")
print("=" * 75)

for threshold in THRESHOLDS:

    predictions = (phishing_scores >= threshold).astype(int)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions, zero_division=0)
    recall = recall_score(y_test, predictions, zero_division=0)
    f1 = f1_score(y_test, predictions, zero_division=0)

    tn, fp, fn, tp = confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1]
    ).ravel()

    false_positive_rate = fp / (tn + fp) if (tn + fp) else 0

    print(f"\nTHRESHOLD: {threshold:.2f}")
    print("-" * 45)

    print(f"Accuracy:             {accuracy * 100:.2f}%")
    print(f"Phishing Precision:   {precision * 100:.2f}%")
    print(f"Phishing Recall:      {recall * 100:.2f}%")
    print(f"Phishing F1-score:    {f1 * 100:.2f}%")
    print(f"False Positive Rate:  {false_positive_rate * 100:.2f}%")

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, predictions, labels=[0, 1]))

    print(f"True Negatives:  {tn}")
    print(f"False Positives: {fp}")
    print(f"False Negatives: {fn}")
    print(f"True Positives:  {tp}")

print("\nThreshold analysis completed.")
