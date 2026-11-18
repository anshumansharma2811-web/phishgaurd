
import pandas as pd
from urllib.parse import urlsplit

df = pd.read_csv("dataset/phishstorm_clean.csv")

def get_hostname(url):
    url = str(url).strip().strip("'\"")
    if "://" not in url:
        url = "http://" + url
    return (urlsplit(url).hostname or "").lower()

def get_path(url):
    url = str(url).strip().strip("'\"")
    if "://" not in url:
        url = "http://" + url
    return urlsplit(url).path.lower()

df["hostname"] = df["domain"].apply(get_hostname)
df["path"] = df["domain"].apply(get_path)

google = df[
    df["hostname"].apply(
        lambda h: h == "google.com" or h.endswith(".google.com")
    )
].copy()

print("\nHOSTNAME LABEL COMPARISON")
print("=" * 55)

hostname_table = pd.crosstab(
    google["hostname"],
    google["label"]
).rename(columns={0: "Legitimate", 1: "Phishing"})

print(hostname_table)

print("\nPATH LABEL COMPARISON")
print("=" * 55)

path_table = pd.crosstab(
    google["path"],
    google["label"]
).rename(columns={0: "Legitimate", 1: "Phishing"})

path_table["Total"] = path_table.sum(axis=1)

print(
    path_table.sort_values(
        "Total", ascending=False
    ).head(20)
)
