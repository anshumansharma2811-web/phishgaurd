
import csv
from pathlib import Path
from collections import Counter

input_file = Path("dataset/urlset.csv")

total_records = 0
valid_records = 0
invalid_records = 0
label_counts = Counter()
invalid_examples = []

print("Starting PhishStorm dataset inspection...")

with input_file.open("r", encoding="utf-8", errors="replace", newline="") as file:

    reader = csv.reader(file)

    header = next(reader)
    expected_columns = len(header)

    print("Expected columns:", expected_columns)
    print("Column names:", header)

    for row_number, row in enumerate(reader, start=2):

        total_records += 1

        if len(row) != expected_columns:
            invalid_records += 1

            if len(invalid_examples) < 10:
                invalid_examples.append(
                    (row_number, len(row))
                )
            continue

        try:
            label = float(row[-1])

            if label not in (0.0, 1.0):
                invalid_records += 1
                continue

        except ValueError:
            invalid_records += 1
            continue

        valid_records += 1
        label_counts[label] += 1


print("\n========== INSPECTION REPORT ==========")
print("Total records:", total_records)
print("Valid records:", valid_records)
print("Invalid records:", invalid_records)

print("\nLabel distribution:")
print("Legitimate (0):", label_counts[0.0])
print("Phishing (1):", label_counts[1.0])

print("\nFirst invalid examples:")
for example in invalid_examples:
    print("Row:", example[0], "| Columns found:", example[1])

print("\nInspection completed.")
