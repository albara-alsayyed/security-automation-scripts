#!/usr/bin/env python3
"""
Nmap XML to Markdown report generator.

What it does:
- Reads Nmap XML output.
- Lists discovered hosts, open ports, services, and versions.
- Writes a simple Markdown report for documentation.

How to run:
    nmap -sV -oX scan.xml 192.168.56.0/24
    python python/nmap_xml_to_report.py scan.xml -o report.md

Safe lab disclaimer:
    Only scan networks and review scan data you are authorized to test.
"""

from __future__ import annotations

import argparse
import xml.etree.ElementTree as ET
from pathlib import Path


def get_text(value: str | None, fallback: str = "unknown") -> str:
    return value if value else fallback


def parse_nmap_xml(path: Path) -> list[dict[str, object]]:
    try:
        tree = ET.parse(path)
    except FileNotFoundError:
        raise SystemExit(f"File not found: {path}")
    except ET.ParseError as error:
        raise SystemExit(f"Invalid XML file: {error}")

    hosts: list[dict[str, object]] = []
    for host in tree.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        address_node = host.find("address")
        address = get_text(address_node.get("addr") if address_node is not None else None)

        hostname_nodes = host.findall("hostnames/hostname")
        hostnames = [node.get("name") for node in hostname_nodes if node.get("name")]

        ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")
            ports.append(
                {
                    "port": port.get("portid", "unknown"),
                    "protocol": port.get("protocol", "tcp"),
                    "service": get_text(service.get("name") if service is not None else None),
                    "product": get_text(service.get("product") if service is not None else None, ""),
                    "version": get_text(service.get("version") if service is not None else None, ""),
                }
            )

        hosts.append({"address": address, "hostnames": hostnames, "ports": ports})
    return hosts


def build_report(hosts: list[dict[str, object]]) -> str:
    lines = [
        "# Nmap Scan Report",
        "",
        "Generated from Nmap XML output.",
        "",
        "## Summary",
        "",
        f"- Hosts up: {len(hosts)}",
        f"- Hosts with open ports: {sum(1 for host in hosts if host['ports'])}",
        "",
    ]

    for host in hosts:
        hostnames = ", ".join(host["hostnames"]) if host["hostnames"] else "None"
        lines.extend(
            [
                f"## Host: {host['address']}",
                "",
                f"- Hostnames: {hostnames}",
                "",
                "| Port | Protocol | Service | Version |",
                "| --- | --- | --- | --- |",
            ]
        )

        ports = host["ports"]
        if not ports:
            lines.append("| No open ports found | - | - | - |")
        else:
            for port in ports:
                version = " ".join(
                    part for part in [port["product"], port["version"]] if part
                ) or "unknown"
                lines.append(
                    f"| {port['port']} | {port['protocol']} | {port['service']} | {version} |"
                )
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert Nmap XML to Markdown.")
    parser.add_argument("xml_file", type=Path, help="Nmap XML file")
    parser.add_argument("-o", "--output", type=Path, default=Path("nmap-report.md"))
    args = parser.parse_args()

    hosts = parse_nmap_xml(args.xml_file)
    report = build_report(hosts)
    args.output.write_text(report, encoding="utf-8")
    print(f"[+] Wrote report: {args.output}")


if __name__ == "__main__":
    main()
