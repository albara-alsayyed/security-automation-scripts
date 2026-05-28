#!/usr/bin/env python3
"""
BloodHound export risk mapper for defensive AD remediation.

What it does:
- Reads BloodHound-style JSON exports from a file or directory.
- Extracts relationship/edge names where present.
- Scores high-risk AD relationships for remediation planning.
- Exports Markdown, JSON, or CSV.

How to run:
    python python/bloodhound_risk_mapper.py bloodhound-export/ -o bloodhound-risk.md
    python python/bloodhound_risk_mapper.py edges.json --format csv -o bloodhound-risk.csv

Safe lab disclaimer:
    Use only with BloodHound data collected from domains you are authorized to
    assess. This script does not collect AD data and does not execute attacks.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


EDGE_RISK = {
    "GenericAll": (95, "Full control relationship; remove unnecessary delegation."),
    "GenericWrite": (90, "Write control can enable account or object abuse; review ACL delegation."),
    "WriteDacl": (95, "DACL modification can grant control; remediate excessive ACLs."),
    "WriteOwner": (90, "Ownership control can lead to permission changes; review ownership."),
    "AddMember": (85, "Group membership control can grant privilege; restrict group managers."),
    "ForceChangePassword": (85, "Password reset rights are sensitive; review helpdesk delegation."),
    "AllExtendedRights": (90, "Extended rights may include sensitive control paths; review ACLs."),
    "DCSync": (100, "Domain replication rights are critical; restrict to approved DC/admin identities."),
    "AdminTo": (80, "Administrative control over a host; validate tiering and local admin rights."),
    "CanRDP": (70, "Interactive remote access; restrict and monitor."),
    "CanPSRemote": (75, "PowerShell remoting access; restrict and monitor."),
    "ExecuteDCOM": (75, "Remote execution path; restrict and monitor."),
    "HasSession": (65, "Session presence can create credential exposure; reduce admin logons."),
    "AllowedToDelegate": (90, "Delegation can expose identity risk; review constrained/unconstrained delegation."),
    "AddAllowedToAct": (95, "Resource-based constrained delegation control; review object ACLs."),
    "ReadLAPSPassword": (85, "Local admin password read rights are sensitive; restrict readers."),
    "Owns": (90, "Object ownership can permit control; review owner assignments."),
}


@dataclass
class BloodHoundFinding:
    edge_type: str
    risk_score: int
    source: str
    target: str
    remediation: str


def load_json_documents(path: Path) -> list[Any]:
    paths = sorted(path.rglob("*.json")) if path.is_dir() else [path]
    documents = []
    for item in paths:
        try:
            documents.append(json.loads(item.read_text(encoding="utf-8", errors="replace")))
        except json.JSONDecodeError:
            continue
    return documents


def walk(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def first_present(data: dict[str, Any], keys: list[str]) -> str:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, dict):
            name = value.get("name") or value.get("objectid") or value.get("id")
            if name:
                return str(name)
    return ""


def extract_findings(documents: list[Any]) -> list[BloodHoundFinding]:
    findings: list[BloodHoundFinding] = []
    seen: set[tuple[str, str, str]] = set()

    for document in documents:
        for node in walk(document):
            edge = first_present(node, ["label", "kind", "relationship", "edge_type", "EdgeType", "type"])
            if edge not in EDGE_RISK:
                continue
            source = first_present(node, ["source", "start", "from", "src", "startNode", "StartNode"])
            target = first_present(node, ["target", "end", "to", "dst", "endNode", "EndNode"])
            key = (edge, source, target)
            if key in seen:
                continue
            seen.add(key)
            score, remediation = EDGE_RISK[edge]
            findings.append(BloodHoundFinding(edge, score, source or "unknown", target or "unknown", remediation))

    return sorted(findings, key=lambda item: item.risk_score, reverse=True)


def render_markdown(findings: list[BloodHoundFinding]) -> str:
    counts = Counter(item.edge_type for item in findings)
    lines = [
        "# BloodHound Defensive Risk Map",
        "",
        "Authorized AD attack-path remediation view generated from BloodHound-style JSON.",
        "",
        "## Edge Summary",
        "",
        "| Edge | Count |",
        "| --- | ---: |",
    ]
    for edge, count in counts.most_common():
        lines.append(f"| {edge} | {count} |")

    lines.extend(["", "## Prioritized Findings", "", "| Risk | Edge | Source | Target | Remediation |", "| ---: | --- | --- | --- | --- |"])
    if not findings:
        lines.append("| 0 | none | - | - | No recognized high-risk edges found |")
    for item in findings:
        lines.append(f"| {item.risk_score} | {item.edge_type} | `{item.source}` | `{item.target}` | {item.remediation} |")
    return "\n".join(lines)


def write_csv(path: Path, findings: list[BloodHoundFinding]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["risk_score", "edge_type", "source", "target", "remediation"])
        writer.writeheader()
        for item in findings:
            writer.writerow(asdict(item))


def main() -> None:
    parser = argparse.ArgumentParser(description="Map BloodHound JSON exports to remediation priorities.")
    parser.add_argument("input", type=Path, help="BloodHound JSON file or directory")
    parser.add_argument("--format", choices=["markdown", "json", "csv"], default="markdown")
    parser.add_argument("-o", "--output", type=Path, default=Path("bloodhound-risk.md"))
    args = parser.parse_args()

    findings = extract_findings(load_json_documents(args.input))
    if args.format == "json":
        args.output.write_text(json.dumps([asdict(item) for item in findings], indent=2), encoding="utf-8")
    elif args.format == "csv":
        write_csv(args.output, findings)
    else:
        args.output.write_text(render_markdown(findings), encoding="utf-8")

    print(f"[+] Wrote {args.format} BloodHound risk map: {args.output}")


if __name__ == "__main__":
    main()
