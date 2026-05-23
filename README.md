# Security Automation Scripts

Defensive, beginner-friendly security automation scripts for log review, IOC extraction, Nmap reporting, Linux hardening checks, Windows event checks, and Active Directory user auditing.

These scripts are built for authorized environments only: your own machine, your own lab, CTF/lab systems, or systems where you have written permission. They do not include exploit code, malware, credential theft, persistence, stealth, or unauthorized access workflows.

## Repository Structure

```text
security-automation-scripts/
├── README.md
├── python/
│   ├── log_parser.py
│   ├── ioc_extractor.py
│   └── nmap_xml_to_report.py
├── bash/
│   ├── linux_enum_basic.sh
│   └── hardening_check.sh
├── powershell/
│   ├── windows_event_checker.ps1
│   └── ad_user_audit.ps1
└── screenshots/
```

## Scripts

| Script | What it does | How to run |
| --- | --- | --- |
| `python/log_parser.py` | Summarizes web/server logs, IP frequency, status codes, and suspicious keywords. | `python python/log_parser.py sample.log` |
| `python/ioc_extractor.py` | Extracts IPs, domains, URLs, emails, and common hash types from text files. | `python python/ioc_extractor.py incident.txt --json` |
| `python/nmap_xml_to_report.py` | Converts Nmap XML output into a readable Markdown report. | `python python/nmap_xml_to_report.py scan.xml -o report.md` |
| `bash/linux_enum_basic.sh` | Collects basic local Linux system inventory for defensive review. | `bash bash/linux_enum_basic.sh` |
| `bash/hardening_check.sh` | Checks common Linux hardening items such as SSH root login and firewall status. | `bash bash/hardening_check.sh` |
| `powershell/windows_event_checker.ps1` | Reviews common Windows Security/System event IDs for defensive triage. | `powershell -ExecutionPolicy Bypass -File powershell/windows_event_checker.ps1` |
| `powershell/ad_user_audit.ps1` | Audits Active Directory user hygiene in an authorized domain lab. | `powershell -ExecutionPolicy Bypass -File powershell/ad_user_audit.ps1` |

## Script Details

### `python/log_parser.py`

What it does: Parses web/server logs, counts source IPs, summarizes HTTP status codes, and flags suspicious keywords.

How to run:

```bash
python python/log_parser.py sample.log --top 10
```

Example output:

```text
[+] Parsed 1,248 log lines
[+] Top IPs
    192.168.56.10      84 requests
    10.0.0.22          41 requests

[+] Status codes
    200                1,034
    404                109
    401                38

[!] Suspicious keywords
    /wp-login.php      14 hits
    /admin             8 hits
```

Screenshot: `screenshots/log-parser-example.svg`

Safe lab disclaimer: Use only on logs you own or are authorized to review.

### `python/ioc_extractor.py`

What it does: Extracts IPv4 addresses, URLs, domains, emails, MD5, SHA1, and SHA256 hashes from incident notes or logs.

How to run:

```bash
python python/ioc_extractor.py incident.txt --json
```

Example output:

```json
{
  "ipv4": ["192.168.56.10"],
  "url": ["https://example.com/login"],
  "email": ["analyst@example.com"],
  "sha256": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
}
```

Screenshot: `screenshots/ioc-extractor-example.svg`

Safe lab disclaimer: Use only on files and investigation notes you own or are authorized to review.

### `python/nmap_xml_to_report.py`

What it does: Converts authorized Nmap XML scan output into a Markdown report with hosts, open ports, services, and versions.

How to run:

```bash
nmap -sV -oX scan.xml 192.168.56.0/24
python python/nmap_xml_to_report.py scan.xml -o report.md
```

Example output:

```text
[+] Wrote report: report.md
```

Screenshot: `screenshots/nmap-report-example.svg`

Safe lab disclaimer: Only scan networks and review scan data you are authorized to test.

### `bash/linux_enum_basic.sh`

What it does: Collects local Linux inventory such as OS, kernel, current user, interfaces, listening ports, top processes, enabled services, and recent auth logs.

How to run:

```bash
bash bash/linux_enum_basic.sh
```

Example output:

```text
==== System ====
Kernel: Linux lab 6.8.0 x86_64

==== Listening Ports ====
tcp LISTEN 0 128 0.0.0.0:22
```

Screenshot: `screenshots/linux-enum-basic-example.svg`

Safe lab disclaimer: Run only on systems you own or administer with permission.

### `bash/hardening_check.sh`

What it does: Checks common Linux hardening items, including firewall state, SSH root login, SSH password authentication, password maximum age, and `/tmp` mount options.

How to run:

```bash
bash bash/hardening_check.sh
```

Example output:

```text
Linux Hardening Check
[PASS] SSH root login is disabled.
[WARN] SSH password authentication is not explicitly disabled.
```

Screenshot: `screenshots/linux-hardening-check-example.svg`

Safe lab disclaimer: Run only on Linux systems you own or are authorized to assess.

### `powershell/windows_event_checker.ps1`

What it does: Reviews common Windows Security/System event IDs used in defensive triage, including failed logons, successful logons, user creation/deletion, group membership changes, and service installation.

How to run:

```powershell
powershell -ExecutionPolicy Bypass -File .\powershell\windows_event_checker.ps1 -Hours 24
```

Example output:

```text
==== Failed logon [Security:4625] ====
TimeCreated           ProviderName Id   Message
-----------           ------------ --   -------
2026-05-24 10:14:22   Microsoft... 4625 An account failed to log on.
```

Screenshot: `screenshots/windows-event-checker-example.svg`

Safe lab disclaimer: Run only on Windows systems you own or administer with permission.

### `powershell/ad_user_audit.ps1`

What it does: Audits Active Directory user hygiene in an authorized domain lab, including enabled users, locked users, inactive users, and accounts with passwords set to never expire.

How to run:

```powershell
powershell -ExecutionPolicy Bypass -File .\powershell\ad_user_audit.ps1 -InactiveDays 90
```

Example output:

```text
==== Summary ====
TotalUsers           : 42
EnabledUsers         : 38
LockedUsers          : 2
InactiveUsers        : 7
PasswordNeverExpires : 3
```

Screenshot: `screenshots/ad-user-audit-example.svg`

Safe lab disclaimer: Run only in domains where you have permission to audit users. This script does not collect passwords.

## Screenshots

Add screenshots under `screenshots/` after running each script in your lab. Good screenshot ideas:

- `screenshots/log-parser-example.svg`
- `screenshots/ioc-extractor-example.svg`
- `screenshots/nmap-report-example.svg`
- `screenshots/windows-event-checker-example.svg`
- `screenshots/linux-hardening-check-example.svg`

## Safe Lab Disclaimer

Use these scripts only for defensive security, authorized administration, learning labs, and CTF environments. Always get permission before collecting logs, auditing systems, or scanning output from networks you do not own.

## License

MIT License is recommended for open-source release. Add a `LICENSE` file before publishing if you want formal licensing.
