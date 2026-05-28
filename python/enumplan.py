#!/usr/bin/env python3
"""
Nmap service mapper and first-step enumeration planner.

What it does:
- Reads authorized Nmap XML output.
- Maps open ports to service families and likely security review areas.
- Generates safe first-step enumeration commands and analyst questions.
- Produces Markdown, JSON, or CSV output.

How to run:
    nmap -sV -sC -oX scan.xml 192.168.56.0/24
    python python/nmap_enum_mapper.py scan.xml -o enum-plan.md
    python python/nmap_enum_mapper.py scan.xml --format json -o enum-plan.json

Safe lab disclaimer:
    Use only for assets you own, lab targets, CTF boxes, or systems where you
    have written permission to assess exposure.
"""

from __future__ import annotations

import argparse
import csv
import json
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path


SERVICE_MAP = {
    21: ("FTP", "File transfer", ["Check anonymous login policy", "Confirm TLS/FTPS requirement", "Review exposed banners"]),
    22: ("SSH", "Remote administration", ["Confirm root login is disabled", "Check accepted auth methods", "Review failed logon logs"]),
    23: ("Telnet", "Legacy remote administration", ["Replace with SSH", "Confirm no cleartext credentials", "Restrict network exposure"]),
    25: ("SMTP", "Mail transfer", ["Check open relay controls", "Review SPF/DKIM/DMARC", "Confirm TLS and banner hygiene"]),
    53: ("DNS", "Name service", ["Confirm zone transfers are restricted", "Check recursion policy", "Review exposed records"]),
    80: ("HTTP", "Web application", ["Identify framework and server", "Review security headers", "Check auth and directory listing"]),
    88: ("Kerberos", "Active Directory authentication", ["Confirm domain controller role", "Review time sync", "Monitor Kerberos failures"]),
    110: ("POP3", "Mail retrieval", ["Confirm TLS", "Review authentication exposure", "Prefer modern mail access controls"]),
    135: ("RPC", "Windows RPC endpoint mapper", ["Confirm host role", "Restrict exposure", "Review Windows event logs"]),
    139: ("NetBIOS", "Windows file/name service", ["Review legacy exposure", "Check SMB hardening", "Restrict untrusted networks"]),
    143: ("IMAP", "Mail retrieval", ["Confirm TLS", "Review authentication exposure", "Monitor suspicious logons"]),
    389: ("LDAP", "Directory service", ["Check anonymous bind policy", "Prefer LDAPS", "Review sensitive attribute exposure"]),
    443: ("HTTPS", "Web application over TLS", ["Review TLS configuration", "Check security headers", "Map application routes"]),
    445: ("SMB", "Windows file sharing", ["Disable SMBv1", "Require SMB signing where needed", "Review share permissions"]),
    464: ("Kerberos password", "AD password operations", ["Confirm DC role", "Monitor password change failures", "Review account lockouts"]),
    593: ("RPC over HTTP", "Windows RPC", ["Confirm business need", "Restrict exposure", "Review patch level"]),
    636: ("LDAPS", "Secure directory service", ["Validate certificate", "Review bind policies", "Audit directory exposure"]),
    993: ("IMAPS", "Secure mail retrieval", ["Validate TLS", "Monitor auth failures", "Review mailbox access policy"]),
    995: ("POP3S", "Secure mail retrieval", ["Validate TLS", "Monitor auth failures", "Review legacy mail use"]),
    1433: ("MSSQL", "Database", ["Restrict network access", "Review authentication mode", "Check patch level"]),
    1521: ("Oracle", "Database", ["Restrict network access", "Review listener exposure", "Check patch level"]),
    2049: ("NFS", "Network file system", ["Review exports", "Restrict clients", "Check no_root_squash risk"]),
    3306: ("MySQL", "Database", ["Restrict exposure", "Review auth policy", "Check TLS and patching"]),
    3389: ("RDP", "Remote desktop", ["Require VPN/MFA", "Monitor failed logons", "Restrict source networks"]),
    5432: ("PostgreSQL", "Database", ["Restrict exposure", "Review pg_hba.conf", "Check TLS and patching"]),
    5985: ("WinRM HTTP", "Windows remote management", ["Restrict management networks", "Monitor remote admin use", "Prefer HTTPS"]),
    5986: ("WinRM HTTPS", "Windows remote management", ["Validate TLS", "Restrict management networks", "Monitor remote admin use"]),
    6379: ("Redis", "Data store", ["Bind to trusted interfaces", "Require authentication", "Disable dangerous exposure"]),
    8080: ("HTTP alternate", "Web application", ["Identify service", "Review auth", "Check proxy/admin panels"]),
    8443: ("HTTPS alternate", "Web application over TLS", ["Review TLS", "Identify service", "Check admin exposure"]),
}

SAFE_ENUM_COMMANDS = {
    "FTP": ["nmap -sV --version-light --script ftp-anon,ftp-syst -p {port} {host}"],
    "SSH": ["nmap -sV --version-light --script ssh2-enum-algos,ssh-hostkey -p {port} {host}"],
    "DNS": ["nmap -sU -sV --version-light --script dns-nsid,dns-recursion -p {port} {host}"],
    "HTTP": ["nmap -sV --version-light --script http-title,http-headers,http-server-header -p {port} {host}"],
    "HTTPS": ["nmap -sV --version-light --script ssl-cert,ssl-enum-ciphers,http-title,http-headers -p {port} {host}"],
    "SMB": ["nmap -sV --version-light --script smb-protocols,smb-security-mode,smb2-security-mode -p {port} {host}"],
    "LDAP": ["nmap -sV --version-light --script ldap-rootdse -p {port} {host}"],
    "LDAPS": ["nmap -sV --version-light --script ssl-cert,ldap-rootdse -p {port} {host}"],
    "RDP": ["nmap -sV --version-light --script rdp-enum-encryption,rdp-ntlm-info -p {port} {host}"],
    "WinRM HTTP": ["nmap -sV --version-light --script http-title,http-headers -p {port} {host}"],
    "WinRM HTTPS": ["nmap -sV --version-light --script ssl-cert,http-title,http-headers -p {port} {host}"],
    "NFS": ["nmap -sV --version-light --script nfs-showmount,nfs-statfs -p {port} {host}"],
    "Redis": ["nmap -sV --version-light --script redis-info -p {port} {host}"],
}


@dataclass
class ServiceFinding:
    host: str
    hostname: str
    port: int
    protocol: str
    detected_service: str
    mapped_service: str
    category: str
    product: str
    version: str
    review_questions: list[str] = field(default_factory=list)
    safe_first_steps: list[str] = field(default_factory=list)
    risk_score: int = 0
    risk_reason: str = ""


RISK_WEIGHTS = {
    "Telnet": (95, "Cleartext remote administration is exposed."),
    "FTP": (70, "Legacy file transfer service needs authentication and TLS review."),
    "SMB": (80, "File sharing exposure can create high lateral-movement risk if misconfigured."),
    "LDAP": (70, "Directory exposure can reveal sensitive identity information."),
    "LDAPS": (55, "Secure LDAP still requires bind, certificate, and data exposure review."),
    "Kerberos": (65, "Domain authentication service indicates AD exposure and requires monitoring."),
    "RDP": (85, "Remote desktop exposure is high value and should be tightly restricted."),
    "WinRM HTTP": (80, "Remote management over HTTP requires strict network controls."),
    "WinRM HTTPS": (65, "Remote management requires strict admin and network controls."),
    "Redis": (90, "Data stores should not be exposed without strong controls."),
    "MSSQL": (75, "Database exposure requires access control and patch review."),
    "MySQL": (75, "Database exposure requires access control and patch review."),
    "PostgreSQL": (75, "Database exposure requires access control and patch review."),
    "NFS": (75, "Network file systems require export and client restriction review."),
    "HTTP": (60, "Web services require application, header, and authentication review."),
    "HTTPS": (55, "TLS web services require application and certificate review."),
}


def parse_nmap(path: Path) -> list[ServiceFinding]:
    try:
        root = ET.parse(path).getroot()
    except FileNotFoundError:
        raise SystemExit(f"File not found: {path}")
    except ET.ParseError as error:
        raise SystemExit(f"Invalid XML: {error}")

    findings: list[ServiceFinding] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        address_node = host.find("address")
        address = address_node.get("addr", "") if address_node is not None else ""
        hostname = ", ".join(
            node.get("name", "") for node in host.findall("hostnames/hostname") if node.get("name")
        )

        for port_node in host.findall("ports/port"):
            state = port_node.find("state")
            if state is None or state.get("state") != "open":
                continue

            port = int(port_node.get("portid", "0"))
            protocol = port_node.get("protocol", "tcp")
            service_node = port_node.find("service")
            detected = service_node.get("name", "") if service_node is not None else ""
            product = service_node.get("product", "") if service_node is not None else ""
            version = service_node.get("version", "") if service_node is not None else ""

            mapped, category, questions = SERVICE_MAP.get(
                port,
                (detected.upper() or "UNKNOWN", "Unmapped service", ["Identify business owner", "Confirm exposure is required", "Review logs and patching"]),
            )
            risk_score, risk_reason = RISK_WEIGHTS.get(
                mapped,
                (40, "Unmapped service should be reviewed for business need and exposure."),
            )
            commands = [
                command.format(host=address, port=port)
                for command in SAFE_ENUM_COMMANDS.get(mapped, [f"nmap -sV --version-light -sC -p {port} {address}"])
            ]

            findings.append(
                ServiceFinding(
                    host=address,
                    hostname=hostname,
                    port=port,
                    protocol=protocol,
                    detected_service=detected,
                    mapped_service=mapped,
                    category=category,
                    product=product,
                    version=version,
                    review_questions=questions,
                    safe_first_steps=commands,
                    risk_score=risk_score,
                    risk_reason=risk_reason,
                )
            )
    return sorted(findings, key=lambda item: (item.risk_score, item.host, item.port), reverse=True)


def render_markdown(findings: list[ServiceFinding]) -> str:
    lines = [
        "# Nmap Enumeration Map",
        "",
        "Authorized first-step service mapping and defensive enumeration plan.",
        "",
        "## Service Map",
        "",
        "| Risk | Host | Port | Detected | Mapped | Category | Version |",
        "| ---: | --- | --- | --- | --- | --- | --- |",
    ]

    for item in findings:
        version = " ".join(part for part in [item.product, item.version] if part) or "-"
        lines.append(
            f"| {item.risk_score} | {item.host} | {item.port}/{item.protocol} | {item.detected_service or '-'} | "
            f"{item.mapped_service} | {item.category} | {version} |"
        )

    lines.extend(["", "## Prioritized First-Step Enumeration Plan", ""])
    for item in findings:
        lines.append(f"### Risk {item.risk_score} - {item.host}:{item.port}/{item.protocol} - {item.mapped_service}")
        if item.hostname:
            lines.append(f"- Hostname: `{item.hostname}`")
        lines.append(f"- Risk reason: {item.risk_reason}")
        lines.append("- Analyst questions:")
        for question in item.review_questions:
            lines.append(f"  - {question}")
        lines.append("- Safe first-step commands:")
        for command in item.safe_first_steps:
            lines.append(f"  - `{command}`")
        lines.append("")

    return "\n".join(lines)


def write_csv(path: Path, findings: list[ServiceFinding]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "host", "hostname", "port", "protocol", "detected_service", "mapped_service",
            "category", "product", "version", "review_questions", "safe_first_steps",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in findings:
            row = asdict(item)
            row["review_questions"] = " | ".join(item.review_questions)
            row["safe_first_steps"] = " | ".join(item.safe_first_steps)
            writer.writerow(row)


def main() -> None:
    parser = argparse.ArgumentParser(description="Map Nmap XML to first-step enumeration guidance.")
    parser.add_argument("xml_file", type=Path)
    parser.add_argument("--format", choices=["markdown", "json", "csv"], default="markdown")
    parser.add_argument("-o", "--output", type=Path, default=Path("enum-plan.md"))
    args = parser.parse_args()

    findings = parse_nmap(args.xml_file)

    if args.format == "json":
        args.output.write_text(json.dumps([asdict(item) for item in findings], indent=2), encoding="utf-8")
    elif args.format == "csv":
        write_csv(args.output, findings)
    else:
        args.output.write_text(render_markdown(findings), encoding="utf-8")

    print(f"[+] Wrote {args.format} enumeration map: {args.output}")


if __name__ == "__main__":
    main()

