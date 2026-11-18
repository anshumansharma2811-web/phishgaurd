
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

FORM_PATH_KEYWORDS = [
    "form", "viewform", "formresponse", "embeddedform"
]

LOGIN_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "serviceLogin", "auth"
]

ACCOUNT_PATH_KEYWORDS = [
    "account", "profile", "credential", "password"
]


def calculate_entropy(value):
    """Calculate Shannon entropy."""
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def extract_features(url):
    """Extract 37 numerical URL security features."""

    url = str(url).strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    parsed = urlsplit(url)

    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_url = url.lower()

    if not hostname:
        raise ValueError("Could not identify a valid hostname.")

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

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    suspicious_hostname_count = sum(
        keyword in hostname for keyword in SUSPICIOUS_KEYWORDS
    )

    suspicious_path_count = sum(
        keyword in (path + " " + query)
        for keyword in SUSPICIOUS_KEYWORDS
    )

    brand_impersonation_count = sum(
        brand in (hostname + " " + path + " " + query)
        and brand not in domain_name
        for brand in KNOWN_BRANDS
    )

    has_shortening_service = int(
        any(
            hostname == service or hostname.endswith("." + service)
            for service in SHORTENING_SERVICES
        )
    )

    try:
        port = parsed.port
    except ValueError:
        port = None

    labels = [part for part in hostname.split(".") if part]

    # Platform-context features
    is_google_host = int(
        hostname == "google.com" or hostname.endswith(".google.com")
    )

    is_google_docs = int(hostname == "docs.google.com")
    is_google_accounts = int(hostname == "accounts.google.com")
    is_google_sites = int(
        hostname == "sites.google.com"
        or hostname.endswith(".sites.google.com")
    )

    is_github_host = int(
        hostname == "github.com" or hostname.endswith(".github.com")
    )

    # URL path-context features
    has_form_path = int(
        any(keyword in path for keyword in FORM_PATH_KEYWORDS)
    )

    has_login_path = int(
        any(keyword.lower() in path for keyword in LOGIN_PATH_KEYWORDS)
    )

    has_account_path = int(
        any(keyword in path for keyword in ACCOUNT_PATH_KEYWORDS)
    )

    uses_https = int(parsed.scheme.lower() == "https")
    has_query_parameters = int(bool(query))

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
        "decoded_url_length": len(unquote(url)),

        # 10 new contextual features
        "is_google_host": is_google_host,
        "is_google_docs": is_google_docs,
        "is_google_accounts": is_google_accounts,
        "is_google_sites": is_google_sites,
        "is_github_host": is_github_host,
        "has_form_path": has_form_path,
        "has_login_path": has_login_path,
        "has_account_path": has_account_path,
        "uses_https": uses_https,
        "has_query_parameters": has_query_parameters
    }

    return features
