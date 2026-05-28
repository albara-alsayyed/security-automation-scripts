#!/usr/bin/env python3
"""
Professional IOC extractor for defensive investigations.

What it does:
- Extracts IPv4, IPv6, URLs, domains, emails, MD5, SHA1, and SHA256 values.
- Supports defanged indicators such as hxxp://example[.]com.
- Captures optional line context for analyst review.
- Exports text, JSON, or CSV.

How to run:
    python python/ioc_extractor.py incident.txt
    python python/ioc_extractor.py incident.txt --include-private --context --format json

Safe lab disclaimer:
    Use only on files, alerts, and notes you own or are authorized to review.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path


PATTERNS = {
    "url": re.compile(r"\b(?:https?|hxxps?)://[^\s\"'<>]+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "ipv6": re.compile(r"\b(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+(?:\.|\[\.\]))+[a-zA-Z]{2,}\b"),
}


@dataclass(frozen=True)
class Indicator:
    kind: str
    value: str
    line: int
    context: str


def refang(value: str) -> str:
    return (
        value.replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("[.]", ".")
        .replace("(.)", ".")
        .strip(".,);]")
    )


def is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast


def extract(text: str, include_private: bool, include_context: bool) -> list[Indicator]:
    indicators: set[Indicator] = set()
    seen: set[tuple[str, str]] = set()

    for number, line in enumerate(text.splitlines(), start=1):
        normalized_line = refang(line)
        for kind, pattern in PATTERNS.items():
            for match in pattern.findall(normalized_line):
                value = refang(match)
                if kind in {"ipv4", "ipv6"} and not include_private and is_private_ip(value):
                    continue
                key = (kind, value.lower())
                if key in seen:
                    continue
                seen.add(key)
                indicators.add(
                    Indicator(
                        kind=kind,
                        value=value,
                        line=number,
                        context=line.strip() if include_context else "",
                    )
                )

    return sorted(indicators, key=lambda item: (item.kind, item.value))


def write_csv(path: Path, indicators: list[Indicator]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["kind", "value", "line", "context"])
        writer.writeheader()
        for indicator in indicators:
            writer.writerow(asdict(indicator))


def render_text(indicators: list[Indicator]) -> str:
    grouped: dict[str, list[Indicator]] = {}
    for indicator in indicators:
        grouped.setdefault(indicator.kind, []).append(indicator)

    lines: list[str] = []
    for kind in sorted(grouped):
        values = grouped[kind]
        lines.append(f"\n[+] {kind.upper()} ({len(values)})")
        for indicator in values:
            suffix = f" line={indicator.line}" if indicator.line else ""
            lines.append(f"    {indicator.value}{suffix}")
            if indicator.context:
                lines.append(f"      context: {indicator.context}")
    return "\n".join(lines).lstrip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract IOCs from text files.")
    parser.add_argument("input_file", type=Path)
    parser.add_argument("--include-private", action="store_true", help="Keep private, loopback, and link-local IPs")
    parser.add_argument("--context", action="store_true", help="Include source line context")
    parser.add_argument("--format", choices=["text", "json", "csv"], default="text")
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    try:
        text = args.input_file.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        raise SystemExit(f"File not found: {args.input_file}")

    indicators = extract(text, args.include_private, args.context)

    if args.format == "json":
        output = json.dumps([asdict(item) for item in indicators], indent=2)
    elif args.format == "csv":
        if not args.output:
            raise SystemExit("--format csv requires --output")
        write_csv(args.output, indicators)
        print(f"[+] Wrote CSV indicators: {args.output}")
        return
    else:
        output = render_text(indicators)

    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
        print(f"[+] Wrote indicators: {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
