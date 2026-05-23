# Security Automation Scripts

Senior defensive security research toolkit for authorized assessment work. The repo focuses on evidence analysis, attack feasibility reporting, protocol mapping, BloodHound remediation, AD auditing, Nmap service mapping, log analysis, IOC extraction, and hardening review.

These scripts are built for environments you own, operate, or have written permission to assess. They do not include exploit code, malware, credential theft, persistence, stealth, evasion, relay execution, spraying, cracking, reverse shells, or unauthorized access workflows.

## Low-Impact Audit Position

This toolkit is not designed for stealth or evasion. It is designed for authorized, low-impact, audit-friendly security research:

- Passive-first: most scripts analyze existing logs, Nmap XML, BloodHound exports, and AD audit CSVs.
- No credential attacks: no spraying, stuffing, cracking, relay execution, or password collection.
- No exploit execution: reports feasibility and remediation instead of running attacks.
- Scoped review: run only against approved assets and document the testing window.
- SOC-friendly: outputs clear reports so defenders can understand what was checked.
- Conservative Nmap guidance: first-step commands use targeted scripts and `--version-light` where applicable.

## Repository Structure

```text
security-automation-scripts/
|-- README.md
|-- LICENSE
|-- python/
|   |-- log_parser.py
|   |-- ioc_extractor.py
|   |-- nmap_xml_to_report.py
|   |-- nmap_enum_mapper.py
|   |-- attack_surface_mapper.py
|   |-- protocol_security_matrix.py
|   |-- bloodhound_risk_mapper.py
|   `-- attack_feasibility_auditor.py
|-- bash/
|   |-- linux_enum_basic.sh
|   `-- hardening_check.sh
|-- powershell/
|   |-- windows_event_checker.ps1
|   |-- ad_user_audit.ps1
|   `-- powerview_ad_audit.ps1
`-- screenshots/
```

## Professional Workflow

1. Collect authorized evidence: Nmap XML, BloodHound exports, AD audit CSVs, Windows events, Linux logs, or web logs.
2. Build maps: service map, attack-surface map, protocol matrix, BloodHound risk map.
3. Run feasibility audit: identify which techniques may be possible from evidence.
4. Report defensively: document evidence, confidence, detection ideas, and remediation.
5. Validate only through approved, low-impact checks.

## Scripts

| Script | Purpose |
| --- | --- |
| `python/log_parser.py` | Professional web log analyzer with suspicious pattern rules, risk filtering, and text/JSON/CSV/Markdown exports. |
| `python/ioc_extractor.py` | IOC extractor with defang/refang support, context capture, private IP filtering, and text/JSON/CSV exports. |
| `python/nmap_xml_to_report.py` | Converts Nmap XML into Markdown/JSON/CSV service reports with defensive review notes. |
| `python/nmap_enum_mapper.py` | Maps Nmap XML to services, risk scores, review questions, and safe first-step enumeration commands. |
| `python/attack_surface_mapper.py` | Builds host/service prioritization, security-domain grouping, risk scoring, and Mermaid graph output from Nmap XML. |
| `python/protocol_security_matrix.py` | Generates a protocol, technique, tool, detection, and hardening matrix for security research. |
| `python/bloodhound_risk_mapper.py` | Maps BloodHound-style JSON edges to defensive remediation priorities. |
| `python/attack_feasibility_auditor.py` | Checks AD/Nmap/BloodHound evidence and reports whether attack techniques may be possible. |
| `bash/linux_enum_basic.sh` | Local Linux inventory for authorized host review. |
| `bash/hardening_check.sh` | Linux hardening checklist for firewall, SSH, password age, and filesystem posture. |
| `powershell/windows_event_checker.ps1` | Windows event triage for failed logons, successful logons, user changes, group changes, and service creation. |
| `powershell/ad_user_audit.ps1` | AD user hygiene audit with stale users, password flags, SPN users, privileged history, and risk notes. |
| `powershell/powerview_ad_audit.ps1` | PowerView-assisted or native AD audit exporting domain, users, computers, privileged groups, SPNs, GPOs, and optional shares. |

## Nmap Research Mapping

```bash
nmap -sV -sC -oX scan.xml 192.168.56.0/24
python python/nmap_xml_to_report.py scan.xml -o nmap-report.md
python python/nmap_enum_mapper.py scan.xml -o enum-plan.md
python python/attack_surface_mapper.py scan.xml -o attack-surface.md
python python/attack_surface_mapper.py scan.xml --format mermaid -o attack-surface.mmd
```

The Nmap mapper covers SSH, SMB/CIFS, LDAP, Kerberos, RPC, NFS, WinRM, RDP, FTP, Telnet, SNMP, DNS, SMTP, IMAP/POP3, Redis, VNC, X11, DHCP, TFTP, SIP, mDNS, NTP, and additional mapped services.

## AD and BloodHound Research Mapping

```powershell
. .\PowerView.ps1
powershell -ExecutionPolicy Bypass -File .\powershell\powerview_ad_audit.ps1 -OutputDirectory .\ad-audit
powershell -ExecutionPolicy Bypass -File .\powershell\ad_user_audit.ps1 -OutputCsv .\ad-users.csv
```

```bash
python python/bloodhound_risk_mapper.py bloodhound-export/ -o bloodhound-risk.md
python python/attack_feasibility_auditor.py --ad-dir ad-audit --nmap scan.xml --bloodhound bloodhound-export/ -o attack-feasibility-report.md
```

The feasibility auditor checks evidence for Kerberoasting, AS-REP Roasting, relay risk, Pass-the-Hash / Pass-the-Ticket conditions, LLMNR/NBNS poisoning exposure, LDAP/SMB/RPC enumeration exposure, DNS zone-transfer risk, NFS abuse risk, remote command execution/lateral movement exposure, and reverse-shell/egress abuse coverage gaps.

## Protocol, Technique, and Tool Matrix

```bash
python python/protocol_security_matrix.py -o protocol-security-matrix.md
python python/protocol_security_matrix.py --format json -o protocol-security-matrix.json
```

The matrix maps common protocols, techniques, tools, defensive signals, and hardening guidance. Tools are documented for safe defensive use only, including Nmap, NetExec, CrackMapExec, Impacket, enum4linux-ng, ldapsearch, Kerbrute, BloodHound, Responder, ntlmrelayx, Hydra, Metasploit, searchsploit, linPEAS, and WinPEAS.

## Example Outputs

```text
[+] Wrote markdown enumeration map: enum-plan.md
[+] Wrote markdown attack surface map: attack-surface.md
[+] Wrote markdown BloodHound risk map: bloodhound-risk.md
[+] Wrote markdown feasibility report: attack-feasibility-report.md
```

## Screenshots

Screenshot-style examples are stored under `screenshots/` as SVG files so they render directly on GitHub.

## Safe Lab Disclaimer

Use these scripts only for defensive security, authorized administration, learning labs, CTF environments, and approved security research. Always get written permission before auditing systems, collecting directory data, scanning networks, reviewing logs, or handling client evidence.

## License

MIT License.
