
import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit, unquote

import tldextract


SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "signin", "banking", "password", "confirm", "wallet",
    "paypal", "free", "bonus", "webscr", "support",
    "recover", "authenticate", "credential", "suspend"
]

KNOWN_BRANDS = [
    "google", "paypal", "amazon", "microsoft", "apple",
    "facebook", "instagram", "netflix", "github", "bank"
]

SHORTENING_SERVICES = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "is.gd", "buff.ly", "ow.ly", "cutt.ly"
]


def calculate_entropy(value):
    """Calculate the Shannon entropy of a string."""
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def extract_features(url):
    """Extract numerical security-related features from a URL."""

    url = str(url).strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    # Add a scheme if the user provides a URL without one.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    parsed = urlsplit(url)

    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_url = url.lower()

    if not hostname:
        raise ValueError("Could not identify a valid hostname.")

    # Extract the registered domain and subdomains.
    extracted = tldextract.extract(hostname)

    registered_domain = extracted.domain.lower()
    suffix = extracted.suffix.lower()

    if suffix:
        domain_name = registered_domain + "." + suffix
    else:
        domain_name = hostname

    subdomains = [
        part for part in extracted.subdomain.split(".")
        if part and part != "www"
    ]

    # Check whether the hostname is an IP address.
    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    # Count suspicious keywords in different URL sections.
    suspicious_hostname_count = sum(
        keyword in hostname for keyword in SUSPICIOUS_KEYWORDS
    )

    suspicious_path_count = sum(
        keyword in (path + " " + query)
        for keyword in SUSPICIOUS_KEYWORDS
    )

    # Look for brand names in the path/query but not in the domain.
    brand_impersonation_count = sum(
    brand in (hostname + " " + path + " " + query)
    and brand not in domain_name
    for brand in KNOWN_BRANDS
)

    # Detect URL shortening services.
    has_shortening_service = int(
        any(hostname == service or hostname.endswith("." + service)
            for service in SHORTENING_SERVICES)
    )

    # Safely check for an explicitly supplied port.
    try:
        port = parsed.port
    except ValueError:
        port = None

    # Count URL components.
    labels = [part for part in hostname.split(".") if part]

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),

        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "at_count": url.count("@"),
        "question_count": url.count("?"),
        "equal_count": url.count("="),
        "digit_count": sum(char.isdigit() for char in url),

        "has_ip": has_ip,
        "subdomain_count": len(subdomains),
        "domain_length": len(registered_domain),
        "tld_length": len(suffix),

        "suspicious_keyword_count": (
            suspicious_hostname_count + suspicious_path_count
        ),
        "suspicious_hostname_count": suspicious_hostname_count,
        "suspicious_path_count": suspicious_path_count,
        "brand_impersonation_count": brand_impersonation_count,

        "has_shortening_service": has_shortening_service,
        "has_double_slash_path": int("//" in path),
        "has_punycode": int("xn--" in hostname),
        "has_port": int(port is not None),
        "has_encoded_characters": int(
            bool(re.search(r"%[0-9a-fA-F]{2}", url))
        ),
        "encoded_character_count": len(
            re.findall(r"%[0-9a-fA-F]{2}", url)
        ),
        "subdomain_label_count": len(labels),
        "url_entropy": calculate_entropy(url),
        "decoded_url_length": len(unquote(url))
    }

    return features
