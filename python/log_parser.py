#!/usr/bin/env python3
"""
Defensive log parser for quick web/server log review.

What it does:
- Counts total lines.
- Shows top source IP addresses.
- Shows HTTP status code counts when present.
- Flags common suspicious paths and keywords.

How to run:
    python python/log_parser.py sample.log
    python python/log_parser.py sample.log --top 20

Safe lab disclaimer:
    Use only on logs you own or are authorized to review.
"""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
STATUS_RE = re.compile(r'"\s(?P<status>[1-5]\d{2})\s')

SUSPICIOUS_KEYWORDS = [
    "/admin",
    "/wp-login.php",
    "/xmlrpc.php",
    "../",
    "%2e%2e",
    "cmd=",
    "passwd",
    "select%20",
    "union%20",
    "<script",
    "etc/passwd",
]


def read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        raise SystemExit(f"File not found: {path}")


def parse_log(lines: list[str]) -> dict[str, Counter[str] | int]:
    ip_counter: Counter[str] = Counter()
    status_counter: Counter[str] = Counter()
    keyword_counter: Counter[str] = Counter()

    for line in lines:
        ip_match = IP_RE.search(line)
        if ip_match:
            ip_counter[ip_match.group(0)] += 1

        status_match = STATUS_RE.search(line)
        if status_match:
            status_counter[status_match.group("status")] += 1

        lower_line = line.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in lower_line:
                keyword_counter[keyword] += 1

    return {
        "total_lines": len(lines),
        "ips": ip_counter,
        "statuses": status_counter,
        "keywords": keyword_counter,
    }


def print_counter(title: str, counter: Counter[str], top: int) -> None:
    print(f"\n[+] {title}")
    if not counter:
        print("    No matches found")
        return

    for value, count in counter.most_common(top):
        print(f"    {value:<24} {count}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize logs for defensive review.")
    parser.add_argument("log_file", type=Path, help="Path to the log file to parse")
    parser.add_argument("--top", type=int, default=10, help="Number of results to show")
    args = parser.parse_args()

    lines = read_lines(args.log_file)
    result = parse_log(lines)

    print(f"[+] Parsed {result['total_lines']} log lines from {args.log_file}")
    print_counter("Top source IPs", result["ips"], args.top)
    print_counter("HTTP status codes", result["statuses"], args.top)
    print_counter("Suspicious keywords", result["keywords"], args.top)


if __name__ == "__main__":
    main()
