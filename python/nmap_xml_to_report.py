#!/usr/bin/env python3
"""
Professional Nmap XML report generator.

What it does:
- Converts authorized Nmap XML into Markdown, JSON, or CSV.
- Summarizes hosts, open ports, services, versions, and scripts.
- Adds defensive review notes for commonly exposed services.

How to run:
    nmap -sV -sC -oX scan.xml 192.168.56.0/24
    python python/nmap_xml_to_report.py scan.xml -o report.md
    python python/nmap_xml_to_report.py scan.xml --format csv -o services.csv

Safe lab disclaimer:
    Only scan networks and review scan data you are authorized to test.
"""

from __future__ import annotations

import argparse
import csv
import json
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path


SERVICE_NOTES = {
    "ftp": "Confirm anonymous access is disabled and TLS is required where possible.",
    "ssh": "Confirm strong authentication, current OpenSSH, and no direct root login.",
    "telnet": "Replace Telnet with SSH; Telnet sends credentials in cleartext.",
    "smtp": "Check relay controls, SPF/DKIM/DMARC, and banner exposure.",
    "dns": "Confirm zone transfers are restricted and recursion is controlled.",
    "http": "Review web app security headers, auth, directory listing, and patch level.",
    "https": "Review TLS configuration, certificates, headers, and application exposure.",
    "smb": "Confirm SMB signing, disable SMBv1, and review share permissions.",
    "ldap": "Review anonymous bind, LDAPS, and directory exposure.",
    "microsoft-ds": "Confirm SMB hardening, patching, and access controls.",
    "rdp": "Restrict RDP exposure, enforce MFA/VPN, and monitor failed logons.",
    "winrm": "Restrict WinRM to management networks and monitor remote admin use.",
}


@dataclass
class PortRecord:
    host: str
    hostname: str
    port: str
    protocol: str
    service: str
    product: str
    version: str
    scripts: list[str] = field(default_factory=list)
    review_note: str = ""


def text_or_empty(value: str | None) -> str:
    return value or ""


def parse_xml(path: Path) -> list[PortRecord]:
    try:
        root = ET.parse(path).getroot()
    except FileNotFoundError:
        raise SystemExit(f"File not found: {path}")
    except ET.ParseError as error:
        raise SystemExit(f"Invalid XML: {error}")

    records: list[PortRecord] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        address_node = host.find("address")
        address = text_or_empty(address_node.get("addr") if address_node is not None else "")
        hostnames = [node.get("name", "") for node in host.findall("hostnames/hostname") if node.get("name")]
        hostname = ", ".join(hostnames)

        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")
            service_name = text_or_empty(service.get("name") if service is not None else "")
            scripts = [
                f"{script.get('id', 'script')}: {script.get('output', '').strip()}"
                for script in port.findall("script")
                if script.get("output")
            ]

            records.append(
                PortRecord(
                    host=address,
                    hostname=hostname,
                    port=text_or_empty(port.get("portid")),
                    protocol=text_or_empty(port.get("protocol")),
                    service=service_name,
                    product=text_or_empty(service.get("product") if service is not None else ""),
                    version=text_or_empty(service.get("version") if service is not None else ""),
                    scripts=scripts,
                    review_note=SERVICE_NOTES.get(service_name, "Review exposure, patch level, authentication, and logs."),
                )
            )
    return records


def write_csv(path: Path, records: list[PortRecord]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = ["host", "hostname", "port", "protocol", "service", "product", "version", "review_note"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            row = asdict(record)
            row.pop("scripts")
            writer.writerow(row)


def render_markdown(records: list[PortRecord]) -> str:
    hosts = sorted({record.host for record in records})
    lines = [
        "# Nmap Scan Report",
        "",
        "Generated from authorized Nmap XML output.",
        "",
        "## Executive Summary",
        "",
        f"- Hosts with open ports: `{len(hosts)}`",
        f"- Open services: `{len(records)}`",
        "",
        "## Open Services",
        "",
        "| Host | Hostname | Port | Service | Version | Defensive Review Note |",
        "| --- | --- | --- | --- | --- | --- |",
    ]

    for record in records:
        version = " ".join(part for part in [record.product, record.version] if part) or "unknown"
        lines.append(
            f"| {record.host} | {record.hostname or '-'} | {record.port}/{record.protocol} | "
            f"{record.service or '-'} | {version} | {record.review_note} |"
        )

    script_records = [record for record in records if record.scripts]
    if script_records:
        lines.extend(["", "## Nmap Script Output", ""])
        for record in script_records:
            lines.append(f"### {record.host}:{record.port}/{record.protocol}")
            for script in record.scripts:
                lines.append(f"- `{script}`")
            lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert Nmap XML into professional reports.")
    parser.add_argument("xml_file", type=Path)
    parser.add_argument("--format", choices=["markdown", "json", "csv"], default="markdown")
    parser.add_argument("-o", "--output", type=Path, default=Path("nmap-report.md"))
    args = parser.parse_args()

    records = parse_xml(args.xml_file)

    if args.format == "json":
        args.output.write_text(json.dumps([asdict(record) for record in records], indent=2), encoding="utf-8")
    elif args.format == "csv":
        write_csv(args.output, records)
    else:
        args.output.write_text(render_markdown(records), encoding="utf-8")

    print(f"[+] Wrote {args.format} report: {args.output}")


if __name__ == "__main__":
    main()
