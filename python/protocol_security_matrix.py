#!/usr/bin/env python3
"""
Protocol, technique, tool, detection, and hardening matrix.

What it does:
- Maps common Linux, Windows, AD, and network protocols to security review areas.
- Maps common attack techniques to detection and hardening guidance.
- Maps common tools to safe defensive use cases.
- Exports Markdown, JSON, or CSV for reports and research notes.

How to run:
    python python/protocol_security_matrix.py -o protocol-matrix.md
    python python/protocol_security_matrix.py --format json -o protocol-matrix.json

Safe lab disclaimer:
    This is a defensive research matrix. It does not automate attacks.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


PROTOCOLS = [
    {"name": "SSH", "ports": "22/tcp", "logs": "auth.log, secure, Windows OpenSSH logs", "review": "Root login, password auth, weak algorithms, exposed admin access", "hardening": "Disable root login, prefer keys/MFA, restrict source networks, monitor failed logons"},
    {"name": "SMB/CIFS", "ports": "445/tcp, 139/tcp", "logs": "Windows Security, SMBClient, Sysmon, Zeek", "review": "SMBv1, signing, share permissions, null sessions", "hardening": "Disable SMBv1, require signing where needed, least-privilege shares"},
    {"name": "LDAP/LDAPS", "ports": "389/tcp, 636/tcp", "logs": "Directory Service, Security 4662, LDAP diagnostics", "review": "Anonymous bind, sensitive attributes, insecure LDAP", "hardening": "Require signing/channel binding, prefer LDAPS, restrict anonymous reads"},
    {"name": "Kerberos", "ports": "88/tcp/udp, 464/tcp/udp", "logs": "Security 4768, 4769, 4771", "review": "Pre-auth disabled, weak service accounts, time sync", "hardening": "Strong service account passwords, gMSA, monitor TGS anomalies"},
    {"name": "RPC", "ports": "135/tcp, dynamic high ports", "logs": "Windows RPC, Security, firewall logs", "review": "Unnecessary exposure, remote admin surface", "hardening": "Restrict RPC to management networks, patch Windows hosts"},
    {"name": "NFS", "ports": "2049/tcp/udp", "logs": "syslog, auditd, mountd logs", "review": "Exports, no_root_squash, broad clients", "hardening": "Restrict exports, root_squash, read-only where possible"},
    {"name": "WinRM", "ports": "5985/tcp, 5986/tcp", "logs": "PowerShell Operational, WinRM, Security 4624", "review": "Remote admin exposure, HTTP listener, broad admins", "hardening": "Restrict source networks, prefer HTTPS, monitor remote commands"},
    {"name": "RDP", "ports": "3389/tcp", "logs": "Security 4624/4625, TerminalServices logs", "review": "Internet exposure, weak auth, no MFA", "hardening": "VPN/MFA, NLA, account lockout, source restrictions"},
    {"name": "FTP", "ports": "21/tcp", "logs": "FTP server logs, auth logs", "review": "Anonymous access, cleartext auth, writable dirs", "hardening": "Disable anonymous, use SFTP/FTPS, restrict write permissions"},
    {"name": "Telnet", "ports": "23/tcp", "logs": "auth logs, network IDS", "review": "Cleartext remote admin", "hardening": "Replace with SSH, block externally"},
    {"name": "SNMP", "ports": "161/udp", "logs": "SNMP daemon logs, network IDS", "review": "Default community strings, excessive info exposure", "hardening": "Use SNMPv3, strong auth, restrict sources"},
    {"name": "DNS", "ports": "53/tcp/udp", "logs": "DNS server logs, Zeek dns.log", "review": "Zone transfers, recursion, exposed records", "hardening": "Restrict AXFR, control recursion, monitor tunneling patterns"},
    {"name": "SMTP", "ports": "25/tcp, 587/tcp", "logs": "mail logs, M365, gateway logs", "review": "Open relay, spoofing controls, TLS", "hardening": "SPF/DKIM/DMARC, relay restrictions, TLS"},
    {"name": "IMAP/POP3", "ports": "143/993, 110/995", "logs": "mail auth logs, M365 sign-in logs", "review": "Legacy auth, brute force, no MFA", "hardening": "Disable legacy auth, require MFA, monitor impossible travel"},
    {"name": "Redis", "ports": "6379/tcp", "logs": "Redis logs, firewall logs", "review": "Unauthenticated exposure, dangerous commands", "hardening": "Bind localhost/private, require auth, disable risky commands"},
    {"name": "VNC", "ports": "5900+/tcp", "logs": "VNC server logs, auth logs", "review": "Weak passwords, no encryption, broad exposure", "hardening": "VPN only, strong auth, encrypted transport"},
    {"name": "X11", "ports": "6000+/tcp", "logs": "Xorg logs, network IDS", "review": "Remote display exposure", "hardening": "Disable TCP listening, use SSH forwarding safely"},
    {"name": "DHCP", "ports": "67/68 udp", "logs": "DHCP server logs", "review": "Rogue DHCP, scope exhaustion", "hardening": "DHCP snooping, authorized servers, monitoring"},
    {"name": "TFTP", "ports": "69/udp", "logs": "TFTP logs, network IDS", "review": "Unauthenticated file access", "hardening": "Restrict to provisioning networks, read-only, monitor"},
    {"name": "SIP", "ports": "5060/5061", "logs": "PBX/SIP logs", "review": "Extension enumeration, toll fraud risk", "hardening": "Strong auth, rate limits, ACLs, TLS/SRTP"},
    {"name": "mDNS", "ports": "5353/udp", "logs": "Endpoint/network telemetry", "review": "Local service discovery leakage", "hardening": "Limit to trusted segments, disable where unnecessary"},
    {"name": "NTP", "ports": "123/udp", "logs": "NTP logs, network IDS", "review": "Amplification, time tampering", "hardening": "Disable monlist, restrict peers, authenticated NTP where needed"},
]


TECHNIQUES = [
    {"name": "Kerberoasting", "signals": "Unusual 4769 volume, RC4 requests, service account TGS spikes", "hardening": "gMSA, long random service passwords, AES-only where possible"},
    {"name": "AS-REP Roasting", "signals": "4768 without pre-auth for accounts with DONT_REQ_PREAUTH", "hardening": "Require Kerberos pre-auth on all users"},
    {"name": "NTLM Relay / SMB Relay", "signals": "NTLM auth to unexpected hosts, SMB signing disabled, 4624 type 3 anomalies", "hardening": "Require SMB signing, EPA, LDAP signing/channel binding"},
    {"name": "Pass-the-Hash", "signals": "4624 type 3 with NTLM, admin logons from unusual hosts", "hardening": "Local admin tiering, LAPS/Windows LAPS, Credential Guard"},
    {"name": "Pass-the-Ticket", "signals": "Kerberos tickets from unusual hosts, abnormal 4769/4624 combinations", "hardening": "Tiered admin model, privileged access workstations"},
    {"name": "LLMNR/NBNS Poisoning", "signals": "Responder-like name query patterns, WPAD/LLMNR traffic", "hardening": "Disable LLMNR/NBNS, enforce DNS hygiene"},
    {"name": "SSH Pivoting / Agent Hijacking", "signals": "Unexpected SSH forwarding, agent socket access, unusual auth chains", "hardening": "Disable agent forwarding where not needed, monitor SSH options"},
    {"name": "NFS Abuse", "signals": "Unexpected mounts, writes to exports, UID/GID mismatch", "hardening": "root_squash, strict client lists, least privilege exports"},
    {"name": "LDAP/SMB/RPC Enumeration", "signals": "High-volume directory/share/RPC queries from one host", "hardening": "Least privilege directory reads, restrict anonymous/guest access"},
    {"name": "DNS Zone Transfer", "signals": "AXFR requests, full zone reads", "hardening": "Restrict zone transfers to approved secondaries"},
    {"name": "Password Spraying / Credential Stuffing", "signals": "Many users, few attempts each, 4625/4771 spikes", "hardening": "MFA, lockout policy, conditional access, breached password checks"},
    {"name": "Remote Command Execution", "signals": "4688 process creation, PowerShell 4104, WinRM logs", "hardening": "Application control, constrained admin, script block logging"},
    {"name": "Privilege Escalation", "signals": "New services, token privilege use, suspicious scheduled tasks", "hardening": "Patch, remove local admin, harden services"},
    {"name": "Lateral Movement", "signals": "Admin logons across hosts, remote service creation, PsExec-like patterns", "hardening": "Tiering, segmentation, admin workstation model"},
    {"name": "MITM Attacks", "signals": "ARP anomalies, rogue DHCP, certificate warnings, name poisoning", "hardening": "DHCP snooping, ARP inspection, TLS validation"},
    {"name": "Reverse Shells", "signals": "Unusual outbound connections from servers, shell parent/child process anomalies", "hardening": "Egress filtering, EDR, application allowlisting"},
]


TOOLS = [
    {"name": "Nmap", "safe_use": "Authorized service discovery, version mapping, script-based defensive checks"},
    {"name": "NetExec / CrackMapExec", "safe_use": "Authorized configuration validation and exposure review only"},
    {"name": "Impacket", "safe_use": "Protocol research and lab validation; avoid unauthorized credential or relay workflows"},
    {"name": "enum4linux-ng", "safe_use": "Authorized SMB inventory and null-session validation"},
    {"name": "ldapsearch", "safe_use": "Authorized LDAP query validation and directory exposure review"},
    {"name": "Kerbrute", "safe_use": "Lab-only Kerberos behavior testing; do not spray real users"},
    {"name": "BloodHound", "safe_use": "Authorized AD attack-path analysis and remediation planning"},
    {"name": "Responder", "safe_use": "Lab-only name poisoning detection validation; do not run on production networks"},
    {"name": "ntlmrelayx", "safe_use": "Lab-only relay control validation; do not relay production authentication"},
    {"name": "Hydra", "safe_use": "Lab-only password policy testing; do not attack real accounts"},
    {"name": "Metasploit", "safe_use": "Authorized lab validation and patch verification only"},
    {"name": "searchsploit", "safe_use": "Research public advisories and version risk, not exploitation"},
    {"name": "linPEAS / WinPEAS", "safe_use": "Authorized local host posture review and privilege-risk discovery"},
]


def render_markdown() -> str:
    lines = [
        "# Protocol Security Research Matrix",
        "",
        "Defensive mapping for authorized labs, assessments, and security research.",
        "",
        "## Protocols and Services",
        "",
        "| Protocol | Ports | Logs / Telemetry | Review Focus | Hardening |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in PROTOCOLS:
        lines.append(f"| {item['name']} | {item['ports']} | {item['logs']} | {item['review']} | {item['hardening']} |")

    lines.extend(["", "## Techniques: Detection and Hardening", "", "| Technique | Detection Signals | Hardening |", "| --- | --- | --- |"])
    for item in TECHNIQUES:
        lines.append(f"| {item['name']} | {item['signals']} | {item['hardening']} |")

    lines.extend(["", "## Tools: Safe Defensive Use", "", "| Tool | Safe Use |", "| --- | --- |"])
    for item in TOOLS:
        lines.append(f"| {item['name']} | {item['safe_use']} |")

    return "\n".join(lines)


def write_csv(path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["section", "name", "field_1", "field_2", "field_3"])
        writer.writeheader()
        for item in PROTOCOLS:
            writer.writerow({"section": "protocol", "name": item["name"], "field_1": item["ports"], "field_2": item["review"], "field_3": item["hardening"]})
        for item in TECHNIQUES:
            writer.writerow({"section": "technique", "name": item["name"], "field_1": item["signals"], "field_2": item["hardening"], "field_3": ""})
        for item in TOOLS:
            writer.writerow({"section": "tool", "name": item["name"], "field_1": item["safe_use"], "field_2": "", "field_3": ""})


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a defensive protocol security matrix.")
    parser.add_argument("--format", choices=["markdown", "json", "csv"], default="markdown")
    parser.add_argument("-o", "--output", type=Path, default=Path("protocol-security-matrix.md"))
    args = parser.parse_args()

    if args.format == "json":
        args.output.write_text(json.dumps({"protocols": PROTOCOLS, "techniques": TECHNIQUES, "tools": TOOLS}, indent=2), encoding="utf-8")
    elif args.format == "csv":
        write_csv(args.output)
    else:
        args.output.write_text(render_markdown(), encoding="utf-8")
    print(f"[+] Wrote {args.format} matrix: {args.output}")


if __name__ == "__main__":
    main()
