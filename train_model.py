
import pandas as pd
import joblib

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# File locations
DATASET_PATH = "dataset/phishstorm_clean.csv"
MODEL_PATH = "models/phishing_model.pkl"

print("Loading PhishStorm dataset...")

# Load dataset
df = pd.read_csv(DATASET_PATH)

# Remove exact duplicate records
df = df.drop_duplicates().copy()

# Separate input features and target
# Domain is excluded because this dataset provides
# precomputed numerical features.
X = df.drop(columns=["domain", "label"])
y = df["label"].astype(int)

# Split dataset: 80% training, 20% testing
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nDataset preparation completed!")
print("Training records:", len(X_train))
print("Testing records:", len(X_test))
print("Number of features:", X.shape[1])

# Create Random Forest model
print("\nTraining Random Forest model...")

model = RandomForestClassifier(
    n_estimators=150,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

# Train model
model.fit(X_train, y_train)

# Make predictions
y_pred = model.predict(X_test)

# Evaluate model
accuracy = accuracy_score(y_test, y_pred)

print("\n========== MODEL EVALUATION ==========")

print(f"\nAccuracy: {accuracy * 100:.2f}%")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=["Legitimate", "Phishing"],
        zero_division=0
    )
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Save trained model and feature information
Path("models").mkdir(exist_ok=True)

joblib.dump(
    {
        "model": model,
        "feature_names": list(X.columns)
    },
    MODEL_PATH
)

print("\nModel saved successfully!")
print("Location:", MODEL_PATH)
print("\nPhishGuard training completed!")
