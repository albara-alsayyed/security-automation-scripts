#!/usr/bin/env python3
"""
Attack feasibility auditor for authorized security research.

What it does:
- Reviews evidence from AD audit CSVs, Nmap XML, and BloodHound JSON exports.
- Reports whether common AD/network attack techniques appear possible.
- Provides evidence, confidence, safe validation notes, detections, and remediation.
- Does not execute attacks, collect credentials, exploit systems, or run tools.

How to run:
    python python/attack_feasibility_auditor.py --ad-dir ad-audit --nmap scan.xml -o feasibility-report.md
    python python/attack_feasibility_auditor.py --bloodhound bloodhound-export/ --format json -o feasibility-report.json

Safe lab disclaimer:
    Use only with data from environments you own or are authorized to assess.
"""

from __future__ import annotations

import argparse
import csv
import json
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


UAC_DONT_REQ_PREAUTH = 0x400000


@dataclass
class Assessment:
    technique: str
    status: str
    confidence: str
    evidence: list[str]
    safe_validation: list[str]
    detection: list[str]
    remediation: list[str]


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        return list(csv.DictReader(handle))


def load_ad_dir(path: Path | None) -> dict[str, list[dict[str, str]]]:
    if not path:
        return {}
    return {
        "users": read_csv(path / "users.csv"),
        "spn_users": read_csv(path / "spn-users.csv"),
        "privileged_groups": read_csv(path / "privileged-groups.csv"),
        "computers": read_csv(path / "computers.csv"),
        "shares": read_csv(path / "shares.csv"),
    }


def parse_nmap_ports(path: Path | None) -> set[int]:
    if not path or not path.exists():
        return set()
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return set()

    ports: set[int] = set()
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is not None and state.get("state") == "open":
            ports.add(int(port.get("portid", "0")))
    return ports


def load_json_documents(path: Path | None) -> list[Any]:
    if not path or not path.exists():
        return []
    files = sorted(path.rglob("*.json")) if path.is_dir() else [path]
    docs = []
    for file in files:
        try:
            docs.append(json.loads(file.read_text(encoding="utf-8", errors="replace")))
        except json.JSONDecodeError:
            continue
    return docs


def walk(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def bloodhound_edges(documents: list[Any]) -> set[str]:
    edges = set()
    keys = ["label", "kind", "relationship", "edge_type", "EdgeType", "type"]
    known = {
        "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "AddMember",
        "ForceChangePassword", "AllExtendedRights", "DCSync", "AdminTo",
        "CanRDP", "CanPSRemote", "ExecuteDCOM", "HasSession",
        "AllowedToDelegate", "AddAllowedToAct", "ReadLAPSPassword", "Owns",
    }
    for node in documents:
        for item in walk(node):
            for key in keys:
                value = item.get(key)
                if isinstance(value, str) and value in known:
                    edges.add(value)
    return edges


def truthy(value: str | None) -> bool:
    return str(value or "").lower() in {"true", "1", "yes"}


def user_has_preauth_disabled(user: dict[str, str]) -> bool:
    if truthy(user.get("DoesNotRequirePreAuth")):
        return True
    raw_uac = user.get("useraccountcontrol") or user.get("UserAccountControl")
    try:
        return bool(int(raw_uac) & UAC_DONT_REQ_PREAUTH) if raw_uac else False
    except ValueError:
        return False


def assess(ad: dict[str, list[dict[str, str]]], ports: set[int], edges: set[str]) -> list[Assessment]:
    users = ad.get("users", [])
    spn_users = ad.get("spn_users", [])
    privileged_groups = ad.get("privileged_groups", [])
    shares = ad.get("shares", [])

    results: list[Assessment] = []

    def add(technique: str, status: str, confidence: str, evidence: list[str], validation: list[str], detection: list[str], remediation: list[str]) -> None:
        results.append(Assessment(technique, status, confidence, evidence, validation, detection, remediation))

    add(
        "Kerberoasting",
        "possible" if spn_users else "not enough evidence",
        "high" if spn_users else "low",
        [f"SPN-bearing accounts found: {len(spn_users)}"] if spn_users else ["No spn-users.csv evidence provided or no SPN users found."],
        ["Review SPN accounts and password age; do not request or crack tickets in production."],
        ["Monitor Security Event ID 4769 for unusual TGS volume and RC4 usage."],
        ["Use gMSA where possible, rotate old service account passwords, prefer AES, reduce service account privilege."],
    )

    asrep_users = [user for user in users if user_has_preauth_disabled(user)]
    add(
        "AS-REP Roasting",
        "possible" if asrep_users else "not enough evidence",
        "high" if asrep_users else "low",
        [f"Accounts with pre-auth disabled: {len(asrep_users)}"] if asrep_users else ["No accounts with pre-auth disabled found in provided CSVs."],
        ["Confirm the account flag through AD admin tools; do not request roastable material."],
        ["Monitor Event ID 4768 for AS-REQ activity without pre-auth."],
        ["Require Kerberos pre-auth on all users unless a documented exception exists."],
    )

    smb_open = bool({139, 445} & ports)
    ldap_open = bool({389, 636} & ports)
    add(
        "NTLM Relay / SMB Relay",
        "needs validation" if smb_open or ldap_open else "not enough evidence",
        "medium" if smb_open or ldap_open else "low",
        [f"SMB open: {smb_open}", f"LDAP/LDAPS open: {ldap_open}"],
        ["Validate SMB signing, LDAP signing, channel binding, and EPA through approved configuration checks."],
        ["Look for NTLM authentication to unexpected hosts and 4624 type 3 anomalies."],
        ["Require SMB signing where appropriate, enforce LDAP signing/channel binding, disable LLMNR/NBNS."],
    )

    add(
        "Pass-the-Hash / Pass-the-Ticket",
        "needs validation" if {"AdminTo", "HasSession"} & edges or privileged_groups else "not enough evidence",
        "medium" if {"AdminTo", "HasSession"} & edges or privileged_groups else "low",
        [f"BloodHound edges: {sorted({'AdminTo', 'HasSession'} & edges)}", f"Privileged groups exported: {len(privileged_groups)}"],
        ["Review admin tiering, local admin paths, and session exposure from BloodHound data."],
        ["Monitor admin logons, 4624 type 3/10, Kerberos ticket anomalies, and lateral admin patterns."],
        ["Deploy Windows LAPS, Credential Guard, tiered admin model, and privileged access workstations."],
    )

    add(
        "LLMNR/NBNS Poisoning",
        "needs validation",
        "medium",
        ["Requires network configuration evidence; static AD/Nmap evidence is not enough."],
        ["Check endpoint/network policy for LLMNR, NBNS, and WPAD behavior."],
        ["Monitor LLMNR/NBNS traffic and rogue name-response behavior."],
        ["Disable LLMNR/NBNS, configure DNS suffixes, and control WPAD."],
    )

    add(
        "LDAP / SMB / RPC Enumeration",
        "possible" if ({135, 139, 389, 445, 636} & ports) else "not enough evidence",
        "high" if ({135, 139, 389, 445, 636} & ports) else "low",
        [f"Relevant open ports: {sorted({135, 139, 389, 445, 636} & ports)}"],
        ["Validate anonymous access and least-privilege directory/share visibility using approved read-only checks."],
        ["Monitor high-volume LDAP queries, share listing, and RPC endpoint enumeration patterns."],
        ["Disable anonymous/guest access, restrict directory reads, and segment management services."],
    )

    add(
        "DNS Zone Transfer",
        "needs validation" if 53 in ports else "not enough evidence",
        "medium" if 53 in ports else "low",
        ["DNS service open on target scope."] if 53 in ports else ["No DNS service evidence in Nmap data."],
        ["Validate AXFR policy only against authorized DNS servers."],
        ["Monitor AXFR requests and full-zone read attempts."],
        ["Restrict zone transfers to approved secondary DNS servers."],
    )

    add(
        "NFS Abuse",
        "needs validation" if 2049 in ports or shares else "not enough evidence",
        "medium" if 2049 in ports or shares else "low",
        [f"NFS port open: {2049 in ports}", f"Share records exported: {len(shares)}"],
        ["Review exports and permissions without writing to shares unless explicitly approved."],
        ["Monitor mount activity and unexpected file access from new clients."],
        ["Use root_squash, strict client allowlists, read-only exports where possible."],
    )

    add(
        "Remote Command Execution / Lateral Movement",
        "needs validation" if ({3389, 5985, 5986, 445, 135} & ports) or ({"CanRDP", "CanPSRemote", "ExecuteDCOM", "AdminTo"} & edges) else "not enough evidence",
        "medium" if ({3389, 5985, 5986, 445, 135} & ports) or ({"CanRDP", "CanPSRemote", "ExecuteDCOM", "AdminTo"} & edges) else "low",
        [f"Remote admin ports: {sorted({3389, 5985, 5986, 445, 135} & ports)}", f"Relevant BloodHound edges: {sorted({'CanRDP', 'CanPSRemote', 'ExecuteDCOM', 'AdminTo'} & edges)}"],
        ["Validate admin rights and remote management exposure through approved inventory and configuration review."],
        ["Monitor PowerShell 4104, service creation, scheduled tasks, WinRM, RDP, and admin logon events."],
        ["Segment admin protocols, enforce MFA/VPN, restrict local admins, and apply tiered administration."],
    )

    add(
        "Reverse Shell / Egress Abuse",
        "needs validation",
        "low",
        ["Requires egress firewall, proxy, EDR, or DNS telemetry; not provable from static AD/Nmap evidence alone."],
        ["Review egress policy and alert coverage for unusual outbound connections from servers."],
        ["Monitor process-to-network events, suspicious parent/child processes, and outbound connections to rare destinations."],
        ["Apply egress filtering, proxy controls, application allowlisting, and EDR detections."],
    )

    return results


def render_markdown(results: list[Assessment]) -> str:
    lines = [
        "# Attack Feasibility Audit Report",
        "",
        "Authorized security research report. This report assesses whether common techniques appear possible from provided evidence. It does not execute attacks.",
        "",
        "| Status | Confidence | Technique | Evidence |",
        "| --- | --- | --- | --- |",
    ]
    for item in results:
        lines.append(f"| {item.status} | {item.confidence} | {item.technique} | {'; '.join(item.evidence)} |")

    lines.extend(["", "## Detailed Findings", ""])
    for item in results:
        lines.append(f"### {item.technique}")
        lines.append(f"- Status: `{item.status}`")
        lines.append(f"- Confidence: `{item.confidence}`")
        lines.append("- Evidence:")
        for entry in item.evidence:
            lines.append(f"  - {entry}")
        lines.append("- Safe validation:")
        for entry in item.safe_validation:
            lines.append(f"  - {entry}")
        lines.append("- Detection:")
        for entry in item.detection:
            lines.append(f"  - {entry}")
        lines.append("- Remediation:")
        for entry in item.remediation:
            lines.append(f"  - {entry}")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a defensive attack feasibility report.")
    parser.add_argument("--ad-dir", type=Path, help="Directory created by AD audit scripts")
    parser.add_argument("--nmap", type=Path, help="Authorized Nmap XML file")
    parser.add_argument("--bloodhound", type=Path, help="BloodHound JSON export file or directory")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("-o", "--output", type=Path, default=Path("attack-feasibility-report.md"))
    args = parser.parse_args()

    ad = load_ad_dir(args.ad_dir)
    ports = parse_nmap_ports(args.nmap)
    edges = bloodhound_edges(load_json_documents(args.bloodhound))
    results = assess(ad, ports, edges)

    if args.format == "json":
        args.output.write_text(json.dumps([asdict(item) for item in results], indent=2), encoding="utf-8")
    else:
        args.output.write_text(render_markdown(results), encoding="utf-8")

    print(f"[+] Wrote {args.format} feasibility report: {args.output}")


if __name__ == "__main__":
    main()
