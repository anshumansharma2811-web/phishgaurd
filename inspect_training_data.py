
import pandas as pd

from feature_extraction import extract_features

df = pd.read_csv("dataset/phishstorm_clean.csv")
df = df.drop_duplicates(subset=["domain"]).copy()

features = df["domain"].astype(str).apply(extract_features)
feature_df = pd.DataFrame(features.tolist())

df = pd.concat([df.reset_index(drop=True), feature_df], axis=1)

print("\n========== DATASET URL EXAMPLES ==========")

print("\nLEGITIMATE URLS:")
print(df[df["label"] == 0]["domain"].head(10).to_string(index=False))

print("\nPHISHING URLS:")
print(df[df["label"] == 1]["domain"].head(10).to_string(index=False))

print("\n========== FEATURE AVERAGES ==========")

print(
    df.groupby("label")[
        ["url_length", "hostname_length", "path_length",
         "dot_count", "subdomain_count", "digit_count",
         "has_https", "suspicious_keyword_count"]
    ].mean().round(2)
)

print("\n========== HTTPS DISTRIBUTION ==========")

print(pd.crosstab(df["label"], df["has_https"]))

print("\n========== SHORTEST LEGITIMATE URLS ==========")

print(
    df[df["label"] == 0]
    .sort_values("url_length")
    [["domain", "url_length", "hostname_length", "subdomain_count"]]
    .head(15)
    .to_string(index=False)
)

print("\n========== SHORTEST PHISHING URLS ==========")

print(
    df[df["label"] == 1]
    .sort_values("url_length")
    [["domain", "url_length", "hostname_length", "subdomain_count"]]
    .head(15)
    .to_string(index=False)
)
