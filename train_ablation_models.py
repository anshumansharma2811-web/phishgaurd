
import gc
import joblib
import pandas as pd
import tldextract

from pathlib import Path
from urllib.parse import urlsplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

from feature_extraction import extract_features


# ===== CONFIGURATION =====

BASE_DIR = Path(__file__).resolve().parent

DATASET_PATH = BASE_DIR / "dataset" / "phishstorm_clean.csv"
HOMEPAGE_PATH = BASE_DIR / "evaluation" / "trusted_homepages.csv"

MODEL_DIR = BASE_DIR / "models"
EVALUATION_DIR = BASE_DIR / "evaluation"

MODEL_DIR.mkdir(exist_ok=True)
EVALUATION_DIR.mkdir(exist_ok=True)


# ===== EXPERIMENT CONFIGURATIONS =====

EXPERIMENTS = {
    "v3_a": [
        "path_length"
    ],

    "v3_b": [
        "path_length",
        "url_length",
        "decoded_url_length"
    ],

    "v3_c": [
        "path_length",
        "url_length",
        "decoded_url_length",
        "url_entropy"
    ]
}


# ===== REGISTERED DOMAIN EXTRACTION =====

def get_registered_domain(url):

    url = str(url).strip()

    if "://" not in url:
        url = "http://" + url

    hostname = urlsplit(url).hostname or ""

    extracted = tldextract.extract(hostname)

    if extracted.domain and extracted.suffix:
        return extracted.domain + "." + extracted.suffix

    return hostname.lower()


# ===== MAIN TRAINING FUNCTION =====

def main():

    print("=" * 65)
    print("       PHISHGUARD V3 - FEATURE ABLATION EXPERIMENT")
    print("=" * 65)

    print("\nLoading dataset...")

    df = pd.read_csv(DATASET_PATH)

    df = df.dropna(subset=["domain", "label"]).copy()

    df["label"] = pd.to_numeric(
        df["label"],
        errors="coerce"
    )

    df = df[df["label"].isin([0, 1])].copy()

    df = df.drop_duplicates(
        subset=["domain"]
    ).reset_index(drop=True)

    print("Extracting URL features...")

    feature_rows = []
    valid_indices = []

    for index, url in enumerate(df["domain"]):

        try:

            features = extract_features(url)

            feature_rows.append(features)
            valid_indices.append(index)

        except (ValueError, TypeError):

            continue

        if (index + 1) % 10000 == 0:

            print(
                f"Processed {index + 1}/{len(df)} URLs"
            )

    df = df.iloc[valid_indices].reset_index(drop=True)

    X = pd.DataFrame(feature_rows)
    y = df["label"].astype(int)

    del feature_rows
    gc.collect()

    print("\nDataset information:")
    print("Total URLs:", len(X))
    print("Total features:", len(X.columns))
    print("Legitimate URLs:", int((y == 0).sum()))
    print("Phishing URLs:", int((y == 1).sum()))


    # ===== DOMAIN-BASED SPLIT =====

    print("\nCreating domain-based split...")

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

    overlap = train_domains & test_domains

    print("Training URLs:", len(train_indices))
    print("Testing URLs:", len(test_indices))
    print("Overlapping domains:", len(overlap))

    if overlap:

        raise RuntimeError(
            "Domain leakage detected!"
        )


    # ===== HOMEPAGE DIAGNOSTIC DATA =====

    homepage_df = pd.read_csv(HOMEPAGE_PATH)

    homepage_features = pd.DataFrame([
        extract_features(url)
        for url in homepage_df["url"]
    ])

    homepage_labels = homepage_df["label"].astype(int)

    homepage_domains = set(
        homepage_df["url"].apply(get_registered_domain)
    )

    print(
        "Homepage diagnostic domains in training:",
        len(homepage_domains & train_domains)
    )

    results = []
    homepage_results = []


    # ===== TRAIN EXPERIMENTAL MODELS =====

    for experiment_name, removed_features in EXPERIMENTS.items():

        print("\n" + "=" * 65)
        print("TRAINING EXPERIMENT:", experiment_name.upper())
        print("=" * 65)

        print("Removed features:", removed_features)

        feature_names = [
            name for name in X.columns
            if name not in removed_features
        ]

        print("Remaining features:", len(feature_names))

        X_train = X.iloc[train_indices][feature_names]
        X_test = X.iloc[test_indices][feature_names]

        y_train = y.iloc[train_indices]
        y_test = y.iloc[test_indices]

        model = RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            class_weight="balanced",
            n_jobs=2
        )

        print("\nTraining Random Forest model...")

        model.fit(X_train, y_train)

        print("Training completed.")


        # ===== MODEL EVALUATION =====

        predictions = model.predict(X_test)

        accuracy = accuracy_score(y_test, predictions)

        precision = precision_score(
            y_test, predictions, zero_division=0
        )

        recall = recall_score(
            y_test, predictions, zero_division=0
        )

        f1 = f1_score(
            y_test, predictions, zero_division=0
        )

        tn, fp, fn, tp = confusion_matrix(
            y_test,
            predictions,
            labels=[0, 1]
        ).ravel()

        false_positive_rate = (
            fp / (fp + tn) if fp + tn else 0
        )

        print("\nMODEL EVALUATION")

        print(f"Accuracy:  {accuracy * 100:.2f}%")
        print(f"Precision: {precision * 100:.2f}%")
        print(f"Recall:    {recall * 100:.2f}%")
        print(f"F1-score:  {f1 * 100:.2f}%")

        print(
            f"False Positive Rate: "
            f"{false_positive_rate * 100:.2f}%"
        )

        print("\nConfusion Matrix:")
        print([[tn, fp], [fn, tp]])


        # ===== HOMEPAGE DIAGNOSTIC =====

        print("\nHOMEPAGE DIAGNOSTIC RESULTS")

        homepage_input = homepage_features[feature_names]

        homepage_predictions = model.predict(
            homepage_input
        )

        phishing_index = list(model.classes_).index(1)

        homepage_scores = model.predict_proba(
            homepage_input
        )[:, phishing_index]

        homepage_correct = int(
            (homepage_predictions == homepage_labels).sum()
        )

        homepage_fp = int(
            (
                (homepage_predictions == 1) &
                (homepage_labels == 0)
            ).sum()
        )

        for url, score, prediction, label in zip(
            homepage_df["url"],
            homepage_scores,
            homepage_predictions,
            homepage_labels
        ):

            status = (
                "CORRECT"
                if prediction == label
                else "INCORRECT"
            )

            print(
                f"{url:35s} "
                f"{score * 100:6.2f}% | {status}"
            )

            homepage_results.append({
                "experiment": experiment_name,
                "url": url,
                "actual_label": int(label),
                "predicted_label": int(prediction),
                "phishing_score": round(score * 100, 2),
                "correct": bool(prediction == label)
            })

        print(
            f"\nHomepage correct: "
            f"{homepage_correct}/{len(homepage_df)}"
        )


        # ===== SAVE EXPERIMENTAL MODEL =====

        model_path = (
            MODEL_DIR /
            f"phishguard_{experiment_name}_model.pkl"
        )

        joblib.dump(
            {
                "model": model,
                "feature_names": feature_names,
                "feature_version": 3,
                "experiment": experiment_name,
                "removed_features": removed_features
            },
            model_path,
            compress=3
        )

        print("\nModel saved:", model_path)

        results.append({
            "experiment": experiment_name,
            "features": len(feature_names),
            "accuracy": round(accuracy * 100, 2),
            "precision": round(precision * 100, 2),
            "recall": round(recall * 100, 2),
            "f1_score": round(f1 * 100, 2),
            "false_positive_rate": round(
                false_positive_rate * 100, 2
            ),
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
            "homepage_correct": homepage_correct,
            "homepage_total": len(homepage_df),
            "homepage_false_positives": homepage_fp
        })

        # Save results after each completed experiment.

        pd.DataFrame(results).to_csv(
            EVALUATION_DIR / "ablation_results.csv",
            index=False
        )

        pd.DataFrame(homepage_results).to_csv(
            EVALUATION_DIR / "ablation_homepage_results.csv",
            index=False
        )

        # Release memory before the next experiment.

        del model
        del X_train
        del X_test

        gc.collect()


    # ===== FINAL COMPARISON =====

    print("\n" + "=" * 65)
    print("FINAL ABLATION EXPERIMENT COMPARISON")
    print("=" * 65)

    results_df = pd.DataFrame(results)

    print(results_df.to_string(index=False))

    print("\nAll experiments completed successfully.")


if __name__ == "__main__":
    main()
