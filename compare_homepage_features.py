
from feature_extraction import extract_features

url_a = "https://www.google.com"
url_b = "https://www.google.com/search"

features_a = extract_features(url_a)
features_b = extract_features(url_b)

print("\nHOMEPAGE FEATURE COMPARISON")
print("=" * 75)

print("Homepage:", url_a)
print("With path:", url_b)

print("\nCHANGED FEATURES")
print("-" * 75)

for name in features_a:
    value_a = features_a[name]
    value_b = features_b[name]

    if value_a != value_b:
        print(f"{name:30s} {str(value_a):15s} -> {value_b}")

print("\nComparison completed.")
