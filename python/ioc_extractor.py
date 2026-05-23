#!/usr/bin/env python3
"""
IOC extractor for defensive incident notes and logs.

What it does:
- Extracts IP addresses, URLs, domains, emails, MD5, SHA1, and SHA256 hashes.
- Prints results as readable text or JSON.

How to run:
    python python/ioc_extractor.py incident.txt
    python python/ioc_extractor.py incident.txt --json

Safe lab disclaimer:
    Use only on data you own or are authorized to review.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "url": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
}


def unique_sorted(matches: list[str]) -> list[str]:
    return sorted(set(match.strip(".,);]") for match in matches if match.strip()))


def extract_iocs(text: str) -> dict[str, list[str]]:
    results: dict[str, list[str]] = {}
    for name, pattern in PATTERNS.items():
        results[name] = unique_sorted(pattern.findall(text))

    # Avoid listing domains already present inside email addresses.
    email_domains = {email.split("@", 1)[1].lower() for email in results["email"]}
    results["domain"] = [
        domain for domain in results["domain"] if domain.lower() not in email_domains
    ]
    return results


def print_text(results: dict[str, list[str]]) -> None:
    for category, values in results.items():
        print(f"\n[+] {category.upper()} ({len(values)})")
        if not values:
            print("    No matches found")
            continue
        for value in values:
            print(f"    {value}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract IOCs from a text file.")
    parser.add_argument("input_file", type=Path, help="Text file to review")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args()

    try:
        text = args.input_file.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        raise SystemExit(f"File not found: {args.input_file}")

    results = extract_iocs(text)
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_text(results)


if __name__ == "__main__":
    main()
