
import joblib

saved = joblib.load("models/phishguard_context_model.pkl")

model = saved["model"]
feature_names = saved["feature_names"]

importance = sorted(
    zip(feature_names, model.feature_importances_),
    key=lambda item: item[1],
    reverse=True
)

print("\nCONTEXTUAL FEATURE IMPORTANCE")
print("=" * 55)

context_features = [
    "is_google_host",
    "is_google_docs",
    "is_google_accounts",
    "is_google_sites",
    "is_github_host",
    "has_form_path",
    "has_login_path",
    "has_account_path",
    "uses_https",
    "has_query_parameters"
]

for name, score in importance:
    if name in context_features:
        print(f"{name:30s}: {score:.6f}")

print("\nOVERALL TOP 20 FEATURES")
print("=" * 55)

for name, score in importance[:20]:
    print(f"{name:30s}: {score:.6f}")

