
import pandas as pd
import joblib

from feature_extraction import extract_features

# Load dataset and trained model
df = pd.read_csv("dataset/phishstorm_clean.csv")
df = df.drop_duplicates(subset=["domain"]).reset_index(drop=True).copy()

saved = joblib.load("models/phishguard_live_model.pkl")
model = saved["model"]
feature_names = saved["feature_names"]

# Extract training features
feature_data = df["domain"].astype(str).apply(extract_features)
X = pd.DataFrame(feature_data.tolist()).reset_index(drop=True)
y = df["label"].astype(int).reset_index(drop=True)

# URLs to investigate
test_urls = [
    "www.google.com",
    "https://github.com"
]

for url in test_urls:

    features = extract_features(url)

    input_data = pd.DataFrame(
        [features],
        columns=feature_names
    )

    prediction = model.predict(input_data)[0]

    print("\n================================")
    print("URL:", url)
    print("Prediction:", "Phishing" if prediction == 1 else "Legitimate")

    # Compare similar training records
    selected = (
        (X["hostname_length"].between(
            features["hostname_length"] - 3,
            features["hostname_length"] + 3
        ))
        &
        (X["path_length"] == features["path_length"])
        &
        (X["subdomain_count"] == features["subdomain_count"])
    )

    similar = X[selected].copy()
    similar["label"] = y[selected].values
    similar["domain"] = df.loc[selected, "domain"].values

    print("\nSimilar training records:", len(similar))

    print("\nClass distribution:")
    print(similar["label"].value_counts().rename(
        index={0: "Legitimate", 1: "Phishing"}
    ))

    print("\nExample similar URLs:")
    print(
        similar[["domain", "label"]]
        .head(10)
        .to_string(index=False)
    )
