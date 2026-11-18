
import joblib
import pandas as pd
import tldextract

from urllib.parse import urlsplit
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score
)

from feature_extraction_backup import extract_features as extract_original_features
from feature_extraction import extract_features as extract_context_features


DATASET_PATH = "dataset/phishstorm_clean.csv"

ORIGINAL_MODEL_PATH = "models/phishguard_live_model.pkl"
CONTEXT_MODEL_PATH = "models/phishguard_context_model.pkl"


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


def load_saved_model(path):
    saved = joblib.load(path)

    if isinstance(saved, dict):
        model = saved["model"]
        feature_names = saved["feature_names"]
    else:
        model = saved
        feature_names = None

    return model, feature_names


def evaluate_model(name, model, X_test, y_test):
    predictions = model.predict(X_test)

    print("\n" + "=" * 65)
    print(name)
    print("=" * 65)

    print(f"Accuracy:  {accuracy_score(y_test, predictions) * 100:.2f}%")
    print(f"Precision: {precision_score(y_test, predictions, zero_division=0):.4f}")
    print(f"Recall:    {recall_score(y_test, predictions, zero_division=0):.4f}")
    print(f"F1-score:  {f1_score(y_test, predictions, zero_division=0):.4f}")

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


print("Loading dataset...")

df = pd.read_csv(DATASET_PATH)
df = df.dropna(subset=["domain", "label"]).copy()

df["label"] = pd.to_numeric(df["label"], errors="coerce")
df = df.dropna(subset=["label"])
df = df[df["label"].isin([0, 1])].copy()

df = df.drop_duplicates(subset=["domain"]).reset_index(drop=True)

print("Dataset URLs:", len(df))

print("\nLoading saved models...")

original_model, original_names = load_saved_model(ORIGINAL_MODEL_PATH)
context_model, context_names = load_saved_model(CONTEXT_MODEL_PATH)

print("Original model loaded.")
print("Contextual model loaded.")

print("\nExtracting features for both models...")

original_rows = []
context_rows = []
valid_indices = []

for index, url in enumerate(df["domain"]):
    try:
        original_features = extract_original_features(url)
        context_features = extract_context_features(url)

        original_rows.append(original_features)
        context_rows.append(context_features)
        valid_indices.append(index)

    except (ValueError, TypeError) as error:
        print(f"Skipping URL: {url} ({error})")

df = df.iloc[valid_indices].reset_index(drop=True)

X_original = pd.DataFrame(original_rows)
X_context = pd.DataFrame(context_rows)

y = df["label"].astype(int)

print("\nOriginal feature count:", len(X_original.columns))
print("Contextual feature count:", len(X_context.columns))

# Use the saved feature order when available.
if original_names is not None:
    X_original = X_original[original_names]

if context_names is not None:
    X_context = X_context[context_names]

print("\nCreating identical domain-based test split...")

groups = df["domain"].apply(get_registered_domain)

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42
)

train_indices, test_indices = next(
    splitter.split(X_context, y, groups=groups)
)

train_domains = set(groups.iloc[train_indices])
test_domains = set(groups.iloc[test_indices])

print("Training URLs:", len(train_indices))
print("Testing URLs:", len(test_indices))
print("Overlapping domains:", len(train_domains & test_domains))

if train_domains & test_domains:
    raise RuntimeError("Domain leakage detected!")

X_original_test = X_original.iloc[test_indices]
X_context_test = X_context.iloc[test_indices]
y_test = y.iloc[test_indices]

print("\nEvaluating both saved models...")

evaluate_model(
    "ORIGINAL MODEL (27 FEATURES)",
    original_model,
    X_original_test,
    y_test
)

evaluate_model(
    "CONTEXTUAL MODEL (37 FEATURES)",
    context_model,
    X_context_test,
    y_test
)

print("\nComparison completed.")
