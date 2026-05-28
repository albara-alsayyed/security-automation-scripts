#!/usr/bin/env python3
"""
Web and API security posture auditor for authorized assessments.

The script performs low-impact HTTP checks and reports missing security headers,
cookie weaknesses, risky HTTP methods, TLS certificate metadata, and common
well-known security files. It also performs passive WAF/CDN signal detection,
CORS review, and low-impact exposure checks. It does not exploit
vulnerabilities or bypass access controls.
"""

from __future__ import annotations

import argparse
import csv
import json
import socket
import ssl
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http.client import HTTPResponse
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


SECURITY_HEADERS = {
    "strict-transport-security": {
        "severity": "High",
        "why": "Missing HSTS allows downgrade and SSL-stripping risk on HTTPS sites.",
        "fix": "Send Strict-Transport-Security with a tested max-age and includeSubDomains when safe.",
    },
    "content-security-policy": {
        "severity": "Medium",
        "why": "Missing CSP reduces browser-side protection against XSS and data injection.",
        "fix": "Add a restrictive Content-Security-Policy and tune it with report-only testing first.",
    },
    "x-content-type-options": {
        "severity": "Low",
        "why": "Missing nosniff allows MIME sniffing in some browser paths.",
        "fix": "Send X-Content-Type-Options: nosniff.",
    },
    "x-frame-options": {
        "severity": "Medium",
        "why": "Missing clickjacking protection can allow UI redress attacks.",
        "fix": "Send frame-ancestors in CSP, or X-Frame-Options: DENY/SAMEORIGIN for legacy support.",
    },
    "referrer-policy": {
        "severity": "Low",
        "why": "Missing referrer policy may leak URLs or sensitive path data to other origins.",
        "fix": "Send Referrer-Policy: strict-origin-when-cross-origin or stricter.",
    },
    "permissions-policy": {
        "severity": "Low",
        "why": "Missing permissions policy leaves browser features available by default.",
        "fix": "Disable unused browser features with a least-privilege Permissions-Policy.",
    },
}

RISKY_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}
SEVERITY_ORDER = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}

WAF_HEADER_SIGNATURES = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-akamai-transformed": "Akamai",
    "x-azure-ref": "Azure Front Door / WAF",
    "x-amz-cf-id": "AWS CloudFront",
    "x-iinfo": "Imperva Incapsula",
    "x-cdn": "CDN/WAF provider",
    "x-mod-security": "ModSecurity",
}

WAF_VALUE_SIGNATURES = {
    "cloudflare": "Cloudflare",
    "sucuri": "Sucuri",
    "akamai": "Akamai",
    "incapsula": "Imperva Incapsula",
    "imperva": "Imperva",
    "barracuda": "Barracuda",
    "f5": "F5 BIG-IP / Advanced WAF",
    "cloudfront": "AWS CloudFront",
    "awselb": "AWS Load Balancer / WAF edge",
}

WAF_COOKIE_SIGNATURES = {
    "__cf_bm": "Cloudflare Bot Management",
    "cf_clearance": "Cloudflare",
    "incap_ses": "Imperva Incapsula",
    "visid_incap": "Imperva Incapsula",
    "ak_bmsc": "Akamai Bot Manager",
    "bm_sv": "Akamai Bot Manager",
    "awsalb": "AWS load balancer edge",
}

EXPOSURE_CHECKS = {
    "/.git/HEAD": ("High", "Exposed Git metadata", "Block access to .git paths at the web server or reverse proxy."),
    "/.env": ("Critical", "Possible exposed environment file", "Remove the file from web root and rotate any exposed secrets."),
    "/server-status": ("Medium", "Possible exposed server status page", "Restrict status endpoints to trusted admin networks."),
    "/swagger.json": ("Info", "Swagger/OpenAPI document exposed", "Confirm API documentation is intended to be public."),
    "/openapi.json": ("Info", "OpenAPI document exposed", "Confirm API documentation is intended to be public."),
    "/api-docs": ("Info", "API documentation endpoint exposed", "Confirm API documentation is intended to be public."),
}


@dataclass
class Finding:
    target: str
    severity: str
    category: str
    title: str
    evidence: str
    recommendation: str


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("empty URL")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"unsupported URL: {raw}")
    return raw.rstrip("/")


def request_url(url: str, method: str = "GET", timeout: int = 8) -> HTTPResponse:
    request = Request(url, method=method, headers={"User-Agent": "CyberShield-WebSecurityAuditor/1.0"})
    return urlopen(request, timeout=timeout)  # nosec: authorized assessment tool


def response_headers(response: HTTPResponse) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in response.headers.items():
        lower_key = key.lower()
        if lower_key in headers:
            headers[lower_key] = f"{headers[lower_key]}\n{value}"
        else:
            headers[lower_key] = value
    return headers


def add_finding(findings: list[Finding], target: str, severity: str, category: str, title: str, evidence: str, recommendation: str) -> None:
    findings.append(Finding(target, severity, category, title, evidence, recommendation))


def audit_headers(url: str, headers: dict[str, str], findings: list[Finding]) -> None:
    for header, meta in SECURITY_HEADERS.items():
        if header not in headers:
            add_finding(
                findings,
                url,
                meta["severity"],
                "Security Headers",
                f"Missing {header}",
                "Header not present in HTTP response.",
                meta["fix"],
            )

    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    if server:
        add_finding(findings, url, "Info", "Information Disclosure", "Server banner exposed", server, "Reduce banner detail where possible.")
    if powered_by:
        add_finding(findings, url, "Low", "Information Disclosure", "Technology header exposed", powered_by, "Remove X-Powered-By in production.")

    csp = headers.get("content-security-policy", "")
    if csp:
        weak_tokens = [token for token in ("'unsafe-inline'", "'unsafe-eval'", "*") if token in csp]
        if weak_tokens:
            add_finding(findings, url, "Medium", "Security Headers", "Weak CSP directive", ", ".join(weak_tokens), "Avoid wildcards, unsafe-inline, and unsafe-eval where practical.")
        for directive in ("default-src", "object-src", "frame-ancestors", "base-uri"):
            if directive not in csp:
                add_finding(findings, url, "Low", "Security Headers", f"CSP missing {directive}", csp, f"Add a deliberate {directive} directive to reduce browser attack surface.")

    hsts = headers.get("strict-transport-security", "")
    if hsts:
        max_age = parse_hsts_max_age(hsts)
        if max_age is not None and max_age < 15552000:
            add_finding(findings, url, "Low", "Security Headers", "HSTS max-age is short", hsts, "Use at least 15552000 seconds after testing HTTPS readiness.")
        if "includesubdomains" not in hsts.lower():
            add_finding(findings, url, "Info", "Security Headers", "HSTS does not include subdomains", hsts, "Consider includeSubDomains only after all subdomains are HTTPS-ready.")


def parse_hsts_max_age(hsts: str) -> int | None:
    for part in hsts.split(";"):
        name, _, value = part.strip().partition("=")
        if name.lower() == "max-age" and value.isdigit():
            return int(value)
    return None


def audit_cookies(url: str, headers: dict[str, str], findings: list[Finding]) -> None:
    cookies = []
    for key, value in headers.items():
        if key == "set-cookie":
            cookies.extend(value.splitlines())
    for cookie in cookies:
        lower = cookie.lower()
        name = cookie.split("=", 1)[0]
        if "secure" not in lower and url.startswith("https://"):
            add_finding(findings, url, "Medium", "Cookies", f"Cookie {name} missing Secure", cookie, "Add the Secure flag to HTTPS cookies.")
        if "httponly" not in lower:
            add_finding(findings, url, "Medium", "Cookies", f"Cookie {name} missing HttpOnly", cookie, "Add HttpOnly to session cookies.")
        if "samesite" not in lower:
            add_finding(findings, url, "Low", "Cookies", f"Cookie {name} missing SameSite", cookie, "Set SameSite=Lax or Strict unless cross-site use is required.")


def audit_waf(url: str, headers: dict[str, str], findings: list[Finding]) -> None:
    detected: list[str] = []

    for header, provider in WAF_HEADER_SIGNATURES.items():
        if header in headers:
            detected.append(f"{provider} header: {header}")

    for header in ("server", "via", "x-cache", "x-cdn", "set-cookie"):
        value = headers.get(header, "").lower()
        for signature, provider in WAF_VALUE_SIGNATURES.items():
            if signature in value:
                detected.append(f"{provider} signal in {header}")

    cookie_header = headers.get("set-cookie", "").lower()
    for cookie_name, provider in WAF_COOKIE_SIGNATURES.items():
        if cookie_name in cookie_header:
            detected.append(f"{provider} cookie: {cookie_name}")

    if detected:
        add_finding(
            findings,
            url,
            "Info",
            "WAF/CDN",
            "WAF or edge protection signal detected",
            "; ".join(sorted(set(detected))),
            "Confirm the WAF policy is enabled, logging is active, and alert routing is tested.",
        )
    else:
        add_finding(
            findings,
            url,
            "Medium",
            "WAF/CDN",
            "No passive WAF signal detected",
            "No common WAF/CDN headers or cookies were observed.",
            "If this is internet-facing, consider WAF or reverse-proxy protection and verify with approved configuration access.",
        )


def audit_cors(url: str, headers: dict[str, str], findings: list[Finding]) -> None:
    origin = headers.get("access-control-allow-origin", "")
    credentials = headers.get("access-control-allow-credentials", "").lower()
    methods = headers.get("access-control-allow-methods", "")

    if origin == "*" and credentials == "true":
        add_finding(
            findings,
            url,
            "High",
            "CORS",
            "Wildcard CORS with credentials",
            "Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true",
            "Use an explicit allowlist of trusted origins and avoid credentialed wildcard CORS.",
        )
    elif origin == "*":
        add_finding(findings, url, "Medium", "CORS", "Wildcard CORS origin", origin, "Use a narrow origin allowlist for sensitive APIs.")

    if methods:
        enabled = {method.strip().upper() for method in methods.split(",") if method.strip()}
        risky = sorted(enabled & RISKY_METHODS)
        if risky:
            add_finding(findings, url, "Medium", "CORS", "CORS allows risky methods", ", ".join(risky), "Allow only the methods required by trusted clients.")


def audit_methods(url: str, timeout: int, findings: list[Finding]) -> None:
    try:
        response = request_url(url, "OPTIONS", timeout)
        allow = response.headers.get("Allow", "")
    except HTTPError as error:
        allow = error.headers.get("Allow", "")
    except (URLError, TimeoutError, OSError):
        return

    enabled = {method.strip().upper() for method in allow.split(",") if method.strip()}
    risky = sorted(enabled & RISKY_METHODS)
    if risky:
        add_finding(
            findings,
            url,
            "High",
            "HTTP Methods",
            "Risky HTTP methods advertised",
            ", ".join(risky),
            "Disable unused methods at the app, reverse proxy, or web server layer.",
        )


def audit_well_known(url: str, timeout: int, findings: list[Finding]) -> None:
    for path in ("/.well-known/security.txt", "/robots.txt"):
        check_url = urljoin(url + "/", path.lstrip("/"))
        try:
            response = request_url(check_url, "GET", timeout)
            status = getattr(response, "status", 0)
        except HTTPError as error:
            status = error.code
        except (URLError, TimeoutError, OSError):
            continue
        if path.endswith("security.txt") and status == 404:
            add_finding(findings, url, "Info", "Security Program", "security.txt not found", check_url, "Consider publishing security contact details.")


def audit_exposure(url: str, timeout: int, findings: list[Finding]) -> None:
    for path, (severity, title, recommendation) in EXPOSURE_CHECKS.items():
        check_url = urljoin(url + "/", path.lstrip("/"))
        try:
            response = request_url(check_url, "GET", timeout)
            status = getattr(response, "status", 0)
            content_type = response.headers.get("Content-Type", "unknown")
        except HTTPError as error:
            status = error.code
            content_type = error.headers.get("Content-Type", "unknown")
        except (URLError, TimeoutError, OSError):
            continue

        if status == 200:
            add_finding(
                findings,
                url,
                severity,
                "Exposure",
                title,
                f"{check_url} returned HTTP 200 with Content-Type: {content_type}",
                recommendation,
            )


def audit_tls(url: str, timeout: int, findings: list[Finding]) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        add_finding(findings, url, "High", "TLS", "Plain HTTP target", url, "Use HTTPS and redirect HTTP to HTTPS.")
        return

    hostname = parsed.hostname
    port = parsed.port or 443
    if not hostname:
        return

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as wrapped:
                cert = wrapped.getpeercert()
                protocol = wrapped.version() or "unknown"
    except (ssl.SSLError, OSError, TimeoutError) as error:
        add_finding(findings, url, "High", "TLS", "TLS validation failed", str(error), "Fix certificate trust, hostname, or protocol configuration.")
        return

    not_after = cert.get("notAfter")
    if not_after:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days
        if days_left < 30:
            add_finding(findings, url, "High", "TLS", "TLS certificate expires soon", f"{days_left} days left", "Renew and monitor certificate expiry.")
    if protocol in {"TLSv1", "TLSv1.1"}:
        add_finding(findings, url, "High", "TLS", "Legacy TLS protocol negotiated", protocol, "Disable TLS 1.0 and TLS 1.1.")


def audit_target(url: str, timeout: int) -> list[Finding]:
    findings: list[Finding] = []
    try:
        response = request_url(url, "GET", timeout)
        headers = response_headers(response)
        status = getattr(response, "status", 0)
        if 300 <= status < 400:
            add_finding(findings, url, "Info", "Routing", "Redirect observed", str(status), "Confirm redirect target and HTTPS enforcement.")
    except HTTPError as error:
        headers = response_headers(error)
        add_finding(findings, url, "Info", "HTTP", "HTTP error response", str(error.code), "Review whether this is expected for the tested path.")
    except (URLError, TimeoutError, OSError) as error:
        return [Finding(url, "High", "Availability", "Target request failed", str(error), "Confirm DNS, network path, and target availability.")]

    audit_headers(url, headers, findings)
    audit_cookies(url, headers, findings)
    audit_waf(url, headers, findings)
    audit_cors(url, headers, findings)
    audit_methods(url, timeout, findings)
    audit_well_known(url, timeout, findings)
    audit_exposure(url, timeout, findings)
    audit_tls(url, timeout, findings)
    return findings


def read_targets(args: argparse.Namespace) -> list[str]:
    targets = list(args.urls or [])
    if args.input:
        targets.extend(Path(args.input).read_text(encoding="utf-8").splitlines())
    return [normalize_url(target) for target in targets if target.strip()]


def write_json(findings: list[Finding], output: Path) -> None:
    output.write_text(json.dumps([asdict(item) for item in findings], indent=2), encoding="utf-8")


def write_csv(findings: list[Finding], output: Path) -> None:
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(findings[0]).keys()) if findings else list(Finding.__annotations__.keys()))
        writer.writeheader()
        for finding in findings:
            writer.writerow(asdict(finding))


def write_markdown(findings: list[Finding], output: Path) -> None:
    lines = ["# Web Security Audit Report", ""]
    if not findings:
        lines.append("No findings recorded.")
    else:
        lines.extend(["## Summary", ""])
        for severity, count in severity_counts(findings).items():
            lines.append(f"- {severity}: {count}")
        lines.extend(["", "## Findings", ""])
    for finding in findings:
        lines.extend(
            [
                f"## [{finding.severity}] {finding.title}",
                "",
                f"- Target: `{finding.target}`",
                f"- Category: {finding.category}",
                f"- Evidence: {finding.evidence}",
                f"- Recommendation: {finding.recommendation}",
                "",
            ]
        )
    output.write_text("\n".join(lines), encoding="utf-8")


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return {severity: counts[severity] for severity in SEVERITY_ORDER if counts.get(severity)}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda item: (item.target, -SEVERITY_ORDER.get(item.severity, 0), item.category, item.title))


def write_output(findings: list[Finding], fmt: str, output: str | None) -> None:
    findings = sort_findings(findings)
    if not output:
        counts = severity_counts(findings)
        if counts:
            print("[+] Summary: " + ", ".join(f"{severity}={count}" for severity, count in counts.items()))
        for finding in findings:
            print(f"[{finding.severity}] {finding.target} - {finding.title}: {finding.recommendation}")
        return

    output_path = Path(output)
    if fmt == "json":
        write_json(findings, output_path)
    elif fmt == "csv":
        write_csv(findings, output_path)
    else:
        write_markdown(findings, output_path)
    print(f"[+] Wrote {fmt} report: {output_path}")


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Low-impact web/API security posture auditor for authorized targets.")
    parser.add_argument("urls", nargs="*", help="Target URLs or hostnames. Hostnames default to https://")
    parser.add_argument("-i", "--input", help="File containing one target URL per line.")
    parser.add_argument("-o", "--output", help="Output report path.")
    parser.add_argument("--format", choices=["markdown", "json", "csv"], default="markdown", help="Report format.")
    parser.add_argument("--timeout", type=int, default=8, help="Network timeout in seconds.")
    return parser.parse_args(list(argv))


def main(argv: Iterable[str] = sys.argv[1:]) -> int:
    args = parse_args(argv)
    try:
        targets = read_targets(args)
    except ValueError as error:
        print(f"[-] {error}", file=sys.stderr)
        return 2

    if not targets:
        print("[-] Provide at least one URL or --input file.", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    for target in targets:
        findings.extend(audit_target(target, args.timeout))

    write_output(findings, args.format, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
