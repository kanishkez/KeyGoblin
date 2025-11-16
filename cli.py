#!/usr/bin/env python3
import argparse
import json
from scanner import APISecurityScannerV4

LINE = "-" * 70


def classify_secret(pattern: str):
    """Map internal pattern names to human-readable categories."""
    mapping = {
        "hf_token": "HuggingFace Token",
        "bearer_header": "Bearer Token",
        "openai_sk": "OpenAI Key",
        "google_api": "Google API Key",
        "mapbox_pk": "Mapbox Public Token",
        "mapbox_sk": "Mapbox Secret Token",
        "aws_access_key": "AWS Access Key",
        "github_pat": "GitHub PAT",
        "stripe_sk": "Stripe Secret Key",
        "jwt": "JWT",
        "firebase_apikey": "Firebase API Key",
        "query_param": "Query Param Key",
        "generic_kv": "Generic API Key",
    }
    return mapping.get(pattern, pattern)


def print_title(title):
    print(title)
    print(LINE)


def print_api_keys(findings):
    print_title("API KEYS FOUND")
    seen = set()

    for s in findings.get("secrets", []):
        token = s["value"].strip()
        category = classify_secret(s["pattern"])

        if token not in seen:
            seen.add(token)
            print(f"{category}: {token}")

    if not seen:
        print("None")
    print("")


def print_api_endpoints(findings):
    print_title("API ENDPOINTS")
    seen = set()

    for ep in findings.get("api_endpoints", []):
        root = ep.get("root")
        if root and root not in seen:
            seen.add(root)
            print(root)

    if not seen:
        print("None")
    print("")


def print_headers(findings):
    print_title("SUSPICIOUS HEADERS")
    seen = set()

    for h in findings.get("suspicious_headers", []):
        name = h.get("header_name")
        urls = h.get("examples", [])
        if not name or name in seen:
            continue

        seen.add(name)
        if urls:
            print(f"{name} → {urls[0]}")
        else:
            print(name)

    if not seen:
        print("None")
    print("")


def main():
    parser = argparse.ArgumentParser(description="APISecurityScannerV4 CLI")
    parser.add_argument("target", help="Target site URL")
    parser.add_argument("--json", action="store_true", help="Return raw JSON")
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--no-js", action="store_true")
    parser.add_argument("--timeout", type=int, default=60000)
    parser.add_argument("--depth", type=int, default=1)
    args = parser.parse_args()

    scanner = APISecurityScannerV4(
        timeout=args.timeout,
        headless=not args.headful,
        scan_js=not args.no_js,
        crawl_depth=args.depth,
    )

    findings = scanner.run(args.target)

    if args.json:
        print(json.dumps(findings, indent=2))
        return

    print("\nAPI SECURITY SCAN REPORT")
    print("=" * 70)

    print_api_keys(findings)
    print_api_endpoints(findings)
    print_headers(findings)

    print("=" * 70)
    print("Done.")


if __name__ == "__main__":
    main()
