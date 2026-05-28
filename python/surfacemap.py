#!/usr/bin/env python3
"""
Attack surface mapper for authorized Nmap XML.

What it does:
- Converts Nmap XML into a prioritized exposure model.
- Groups services by host and security domain.
- Produces Markdown, JSON, CSV, and Mermaid graph output.
- Helps senior analysts decide what to validate first.

How to run:
    python python/attack_surface_mapper.py scan.xml -o attack-surface.md
    python python/attack_surface_mapper.py scan.xml --format mermaid -o graph.mmd

Safe lab disclaimer:
    Use only for authorized security research, owned assets, CTFs, and labs.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path

from nmap_enum_mapper import ServiceFinding, parse_nmap


DOMAIN_BY_SERVICE = {
    "FTP": "Legacy/File Transfer",
    "SSH": "Remote Admin",
    "Telnet": "Legacy/High Risk",
    "SMTP": "Email",
    "DNS": "Infrastructure",
    "HTTP": "Web",
    "HTTPS": "Web",
    "SMB": "Windows/Identity",
    "LDAP": "Windows/Identity",
    "LDAPS": "Windows/Identity",
    "Kerberos": "Windows/Identity",
    "RDP": "Remote Admin",
    "WinRM HTTP": "Remote Admin",
    "WinRM HTTPS": "Remote Admin",
    "NFS": "File Sharing",
    "Redis": "Data Store",
    "MSSQL": "Database",
    "MySQL": "Database",
    "PostgreSQL": "Database",
}


def classify_domain(service: str) -> str:
    return DOMAIN_BY_SERVICE.get(service, "Other")


def host_scores(findings: list[ServiceFinding]) -> list[dict[str, object]]:
    grouped: dict[str, list[ServiceFinding]] = defaultdict(list)
    for item in findings:
        grouped[item.host].append(item)

    scored = []
    for host, services in grouped.items():
        score = min(100, max(item.risk_score for item in services) + (len(services) * 3))
        domains = sorted({classify_domain(item.mapped_service) for item in services})
        scored.append(
            {
                "host": host,
                "score": score,
                "open_services": len(services),
                "security_domains": domains,
                "highest_risk_service": max(services, key=lambda item: item.risk_score).mapped_service,
            }
        )
    return sorted(scored, key=lambda row: row["score"], reverse=True)


def render_markdown(findings: list[ServiceFinding]) -> str:
    hosts = host_scores(findings)
    lines = [
        "# Attack Surface Map",
        "",
        "Authorized exposure model generated from Nmap XML.",
        "",
        "## Host Prioritization",
        "",
        "| Score | Host | Open Services | Security Domains | Highest Risk Service |",
        "| ---: | --- | ---: | --- | --- |",
    ]
    for host in hosts:
        lines.append(
            f"| {host['score']} | {host['host']} | {host['open_services']} | "
            f"{', '.join(host['security_domains'])} | {host['highest_risk_service']} |"
        )

    lines.extend(["", "## Service Exposure Detail", ""])
    for item in findings:
        lines.append(f"### {item.host}:{item.port}/{item.protocol} - {item.mapped_service}")
        lines.append(f"- Risk score: `{item.risk_score}`")
        lines.append(f"- Security domain: `{classify_domain(item.mapped_service)}`")
        lines.append(f"- Risk reason: {item.risk_reason}")
        lines.append("- First validation questions:")
        for question in item.review_questions:
            lines.append(f"  - {question}")
        lines.append("")

    return "\n".join(lines)


def render_mermaid(findings: list[ServiceFinding]) -> str:
    lines = ["flowchart LR", '  root["Authorized Scope"]']
    for item in findings:
        host_id = "host_" + item.host.replace(".", "_").replace(":", "_")
        service_id = f"{host_id}_{item.port}"
        domain_id = "domain_" + classify_domain(item.mapped_service).replace("/", "_").replace(" ", "_")
        lines.append(f'  {domain_id}["{classify_domain(item.mapped_service)}"]')
        lines.append(f'  {host_id}["{item.host}"]')
        lines.append(f'  {service_id}["{item.port}/{item.protocol} {item.mapped_service} Risk {item.risk_score}"]')
        lines.append(f"  root --> {domain_id}")
        lines.append(f"  {domain_id} --> {host_id}")
        lines.append(f"  {host_id} --> {service_id}")
    return "\n".join(dict.fromkeys(lines))


def write_csv(path: Path, findings: list[ServiceFinding]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["host", "port", "protocol", "mapped_service", "security_domain", "risk_score", "risk_reason"],
        )
        writer.writeheader()
        for item in findings:
            writer.writerow(
                {
                    "host": item.host,
                    "port": item.port,
                    "protocol": item.protocol,
                    "mapped_service": item.mapped_service,
                    "security_domain": classify_domain(item.mapped_service),
                    "risk_score": item.risk_score,
                    "risk_reason": item.risk_reason,
                }
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Build an authorized attack surface map from Nmap XML.")
    parser.add_argument("xml_file", type=Path)
    parser.add_argument("--format", choices=["markdown", "json", "csv", "mermaid"], default="markdown")
    parser.add_argument("-o", "--output", type=Path, default=Path("attack-surface.md"))
    args = parser.parse_args()

    findings = parse_nmap(args.xml_file)
    if args.format == "json":
        data = {
            "hosts": host_scores(findings),
            "services": [asdict(item) for item in findings],
        }
        args.output.write_text(json.dumps(data, indent=2), encoding="utf-8")
    elif args.format == "csv":
        write_csv(args.output, findings)
    elif args.format == "mermaid":
        args.output.write_text(render_mermaid(findings), encoding="utf-8")
    else:
        args.output.write_text(render_markdown(findings), encoding="utf-8")

    print(f"[+] Wrote {args.format} attack surface map: {args.output}")


if __name__ == "__main__":
    main()
