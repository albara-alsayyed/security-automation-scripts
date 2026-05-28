#!/usr/bin/env python3
"""
Professional defensive web log analyzer.

What it does:
- Parses common Apache/Nginx access log formats.
- Summarizes source IPs, HTTP status codes, methods, paths, and user agents.
- Flags suspicious activity using simple, explainable detection rules.
- Exports findings to text, JSON, CSV, or Markdown.

How to run:
    python python/log_parser.py access.log
    python python/log_parser.py access.log --format markdown -o report.md
    python python/log_parser.py access.log --min-risk medium --top 20

Safe lab disclaimer:
    Use only on logs you own or are authorized to review.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


LOG_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/[0-9.]+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)


@dataclass
class LogEntry:
    ip: str
    time: str
    method: str
    path: str
    status: int
    size: str
    referer: str
    agent: str


@dataclass
class Finding:
    rule: str
    severity: str
    ip: str
    path: str
    reason: str
    count: int


RULES = [
    ("admin-probing", "medium", re.compile(r"/(admin|administrator|wp-admin|wp-login)", re.I), "Admin/login probing"),
    ("path-traversal", "high", re.compile(r"(\.\./|%2e%2e|etc/passwd|boot\.ini)", re.I), "Path traversal pattern"),
    ("sql-injection", "high", re.compile(r"(union(\+|%20| )select|select(\+|%20| ).*from|sleep\(|benchmark\()", re.I), "SQL injection pattern"),
    ("xss-probe", "medium", re.compile(r"(<script|%3cscript|javascript:|onerror=)", re.I), "XSS probing pattern"),
    ("command-injection", "high", re.compile(r"(;|\||%7c|&&).*(whoami|id|uname|curl|wget|powershell|cmd\.exe)", re.I), "Command injection pattern"),
    ("sensitive-file", "medium", re.compile(r"(\.env|\.git/config|id_rsa|backup\.zip|db\.sql)", re.I), "Sensitive file probing"),
]

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


def parse_entries(lines: Iterable[str]) -> tuple[list[LogEntry], list[str]]:
    entries: list[LogEntry] = []
    unparsed: list[str] = []

    for line in lines:
        match = LOG_RE.search(line)
        if not match:
            if line.strip():
                unparsed.append(line.rstrip())
            continue

        data = match.groupdict(default="")
        entries.append(
            LogEntry(
                ip=data["ip"],
                time=data["time"],
                method=data["method"],
                path=data["path"],
                status=int(data["status"]),
                size=data["size"],
                referer=data["referer"],
                agent=data["agent"],
            )
        )
    return entries, unparsed


def detect_findings(entries: list[LogEntry]) -> list[Finding]:
    grouped: dict[tuple[str, str, str, str], int] = defaultdict(int)
    reasons: dict[tuple[str, str, str, str], str] = {}

    for entry in entries:
        for rule, severity, pattern, reason in RULES:
            if pattern.search(entry.path):
                key = (rule, severity, entry.ip, entry.path)
                grouped[key] += 1
                reasons[key] = reason

    findings = [
        Finding(rule=rule, severity=severity, ip=ip, path=path, reason=reasons[key], count=count)
        for key, count in grouped.items()
        for rule, severity, ip, path in [key]
    ]
    return sorted(findings, key=lambda item: (SEVERITY_ORDER[item.severity], item.count), reverse=True)


def build_summary(entries: list[LogEntry], unparsed: list[str], findings: list[Finding], top: int) -> dict[str, object]:
    return {
        "total_lines_parsed": len(entries),
        "unparsed_lines": len(unparsed),
        "top_ips": Counter(entry.ip for entry in entries).most_common(top),
        "status_codes": Counter(str(entry.status) for entry in entries).most_common(),
        "methods": Counter(entry.method for entry in entries).most_common(),
        "top_paths": Counter(entry.path for entry in entries).most_common(top),
        "top_user_agents": Counter(entry.agent or "unknown" for entry in entries).most_common(top),
        "findings": [asdict(finding) for finding in findings],
    }


def filter_findings(findings: list[Finding], min_risk: str) -> list[Finding]:
    minimum = SEVERITY_ORDER[min_risk]
    return [finding for finding in findings if SEVERITY_ORDER[finding.severity] >= minimum]


def write_csv(path: Path, findings: list[Finding]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["severity", "rule", "ip", "path", "reason", "count"])
        writer.writeheader()
        for finding in findings:
            writer.writerow(asdict(finding))


def render_text(summary: dict[str, object]) -> str:
    lines = [
        "Web Log Analysis Report",
        "=======================",
        f"Parsed lines: {summary['total_lines_parsed']}",
        f"Unparsed lines: {summary['unparsed_lines']}",
        "",
        "Top IPs:",
    ]
    lines.extend(f"  {ip:<20} {count}" for ip, count in summary["top_ips"])
    lines.append("\nStatus Codes:")
    lines.extend(f"  {code:<5} {count}" for code, count in summary["status_codes"])
    lines.append("\nFindings:")
    if not summary["findings"]:
        lines.append("  No suspicious patterns matched.")
    else:
        for finding in summary["findings"]:
            lines.append(
                f"  [{finding['severity'].upper()}] {finding['rule']} "
                f"{finding['ip']} {finding['path']} ({finding['count']}x) - {finding['reason']}"
            )
    return "\n".join(lines)


def render_markdown(summary: dict[str, object]) -> str:
    lines = [
        "# Web Log Analysis Report",
        "",
        "## Summary",
        "",
        f"- Parsed lines: `{summary['total_lines_parsed']}`",
        f"- Unparsed lines: `{summary['unparsed_lines']}`",
        f"- Findings: `{len(summary['findings'])}`",
        "",
        "## Top IPs",
        "",
        "| IP | Count |",
        "| --- | ---: |",
    ]
    lines.extend(f"| {ip} | {count} |" for ip, count in summary["top_ips"])
    lines.extend(["", "## Findings", "", "| Severity | Rule | IP | Path | Count | Reason |", "| --- | --- | --- | --- | ---: | --- |"])
    if summary["findings"]:
        for finding in summary["findings"]:
            lines.append(
                f"| {finding['severity']} | {finding['rule']} | {finding['ip']} | "
                f"`{finding['path']}` | {finding['count']} | {finding['reason']} |"
            )
    else:
        lines.append("| info | none | - | - | 0 | No suspicious patterns matched |")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze web logs for defensive triage.")
    parser.add_argument("log_file", type=Path, help="Apache/Nginx-style access log")
    parser.add_argument("--top", type=int, default=10, help="Number of top results to show")
    parser.add_argument("--min-risk", choices=["low", "medium", "high"], default="low")
    parser.add_argument("--format", choices=["text", "json", "csv", "markdown"], default="text")
    parser.add_argument("-o", "--output", type=Path, help="Optional output file")
    args = parser.parse_args()

    try:
        lines = args.log_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        raise SystemExit(f"File not found: {args.log_file}")

    entries, unparsed = parse_entries(lines)
    findings = filter_findings(detect_findings(entries), args.min_risk)
    summary = build_summary(entries, unparsed, findings, args.top)

    if args.format == "json":
        output = json.dumps(summary, indent=2)
    elif args.format == "csv":
        if not args.output:
            raise SystemExit("--format csv requires --output")
        write_csv(args.output, findings)
        print(f"[+] Wrote CSV findings: {args.output}")
        return
    elif args.format == "markdown":
        output = render_markdown(summary)
    else:
        output = render_text(summary)

    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
        print(f"[+] Wrote report: {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
