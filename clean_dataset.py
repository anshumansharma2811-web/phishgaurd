
import csv
import math
from pathlib import Path

input_file = Path("dataset/urlset.csv")
output_file = Path("dataset/phishstorm_clean.csv")

valid_count = 0
invalid_count = 0
label_counts = {0: 0, 1: 0}

with input_file.open(
    "r", encoding="utf-8", errors="replace", newline=""
) as source:

    reader = csv.reader(source)
    header = next(reader)

    with output_file.open(
        "w", encoding="utf-8", newline=""
    ) as destination:

        writer = csv.writer(destination)
        writer.writerow(header)

        for row in reader:

            # Check the number of columns
            if len(row) != len(header):
                invalid_count += 1
                continue

            url = row[0].strip()

            # Reject empty URLs and control characters
            if not url or any(ord(c) < 32 or ord(c) == 127 for c in url):
                invalid_count += 1
                continue

            try:
                values = [float(value) for value in row[1:]]

                # Reject NaN and infinity
                if not all(math.isfinite(value) for value in values):
                    invalid_count += 1
                    continue

                label = int(values[-1])

                if label not in (0, 1) or values[-1] != label:
                    invalid_count += 1
                    continue

            except (ValueError, OverflowError):
                invalid_count += 1
                continue

            writer.writerow(row)
            valid_count += 1
            label_counts[label] += 1

print("\n========== CLEANING REPORT ==========")
print("Valid records saved:", valid_count)
print("Rejected records:", invalid_count)
print("Legitimate URLs:", label_counts[0])
print("Phishing URLs:", label_counts[1])
print("Clean dataset:", output_file)
print("\nCleaning completed!")
