```python
#!/usr/bin/env python3
"""
NEXUS - AI Security Research Agent
Pentest (conservative, report-focused) + CTF/LAB (local/lab-only) modes.

Run: python3 main.py
"""

import os
import re
import sys
import ssl
import json
import time
import socket
import shutil
import hashlib
import zipfile
import tarfile
import mimetypes
import subprocess
import http.client
import urllib.request
import urllib.parse
import urllib.error
from html.parser import HTMLParser
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

# ============================================================
# UI / TERMINAL LAYER
# ============================================================

def supports_ansi() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        return os.environ.get("ANSICON") is not None or "WT_SESSION" in os.environ
    return True

ANSI = supports_ansi()

class C:
    RESET = "\033[0m" if ANSI else ""
    BOLD = "\033[1m" if ANSI else ""
    DIM = "\033[2m" if ANSI else ""
    RED = "\033[31m" if ANSI else ""
    GREEN = "\033[32m" if ANSI else ""
    YELLOW = "\033[33m" if ANSI else ""
    BLUE = "\033[34m" if ANSI else ""
    MAGENTA = "\033[35m" if ANSI else ""
    CYAN = "\033[36m" if ANSI else ""
    WHITE = "\033[37m" if ANSI else ""

def term_width() -> int:
    try:
        w = shutil.get_terminal_size(fallback=(80, 24)).columns
    except Exception:
        w = 80
    return max(60, min(w, 100))

def hr(char="─"):
    print(C.DIM + char * term_width() + C.RESET)

def box(lines: List[str], title: str = ""):
    w = term_width()
    inner = w - 2
    print(C.CYAN + "╔" + "═" * inner + "╗" + C.RESET)
    if title:
        pad = inner - len(title)
        left = pad // 2
        right = pad - left
        print(C.CYAN + "║" + C.RESET + " " * left + C.BOLD + title + C.RESET + " " * right + C.CYAN + "║" + C.RESET)
        print(C.CYAN + "╠" + "═" * inner + "╣" + C.RESET)
    for line in lines:
        visible_len = len(re.sub(r"\033\[[0-9;]*m", "", line))
        pad = inner - visible_len - 1
        pad = max(pad, 0)
        print(C.CYAN + "║ " + C.RESET + line + " " * pad + C.CYAN + "║" + C.RESET)
    print(C.CYAN + "╚" + "═" * inner + "╝" + C.RESET)

def banner():
    lines = [
        "",
        C.BOLD + C.WHITE + "N E X U S".center(term_width() - 4) + C.RESET,
        "",
        C.DIM + "AI SECURITY RESEARCH AGENT".center(term_width() - 4) + C.RESET,
        "",
    ]
    box(lines)

def status(tag: str, msg: str):
    colors = {
        "INFO": C.BLUE,
        "OBSERVATION": C.CYAN,
        "POTENTIAL FINDING": C.YELLOW,
        "VERIFIED IN LAB": C.MAGENTA,
        "ERROR": C.RED,
        "OK": C.GREEN,
    }
    col = colors.get(tag, C.WHITE)
    print(f"{col}[{tag}]{C.RESET} {msg}")

def section(title: str):
    print()
    print(C.BOLD + C.WHITE + title + C.RESET)
    hr()

def progress(msg: str):
    print(f"{C.DIM}...{C.RESET} {msg}")

def prompt(msg: str) -> str:
    try:
        return input(f"{C.BOLD}{msg}{C.RESET} ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return "__INTERRUPT__"

def confirm_authorization() -> bool:
    section("AUTHORIZATION REQUIRED")
    print("You must confirm you are explicitly authorized to test this target.")
    print("Unauthorized scanning of systems you do not own or have written")
    print("permission to test may be illegal in your jurisdiction.")
    print()
    ans = prompt("Type YES to confirm authorization, or anything else to cancel:")
    return ans.strip().lower() in ("y", "yes")

def pause():
    prompt(f"{C.DIM}Press Enter to continue...{C.RESET}")


# ============================================================
# SESSION DATA STRUCTURES
# ============================================================

@dataclass
class Target:
    raw_input: str = ""
    hostname: str = ""
    scheme: str = "https"
    normalized_url: str = ""
    resolved_ips: List[str] = field(default_factory=list)
    final_url: str = ""
    http_status: Optional[int] = None
    is_ip_target: bool = False

@dataclass
class ServiceResult:
    port: int
    protocol: str
    service_name: str
    reachable: bool
    timestamp: str

@dataclass
class WebMapResult:
    final_url: str = ""
    status_code: Optional[int] = None
    title: Optional[str] = None
    discovered_paths: List[str] = field(default_factory=list)
    forms_found: int = 0
    pages_visited: int = 0

@dataclass
class TLSResult:
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    hostname_valid: Optional[bool] = None
    expiring_soon: Optional[bool] = None
    error: Optional[str] = None

@dataclass
class Finding:
    title: str
    tag: str  # INFO / OBSERVATION / POTENTIAL FINDING / VERIFIED IN LAB
    severity: str
    location: str
    evidence: str
    why_it_matters: str
    status: str
    next_step: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

@dataclass
class CTFArtifact:
    path: str
    size: int
    extension: str
    file_type: Optional[str] = None
    sha256: Optional[str] = None
    is_archive: bool = False
    is_text: bool = False
    is_binary: bool = False
    is_image: bool = False

@dataclass
class CTFAnalysisResult:
    category_guess: Optional[str] = None
    clues: List[str] = field(default_factory=list)
    recommended_steps: List[str] = field(default_factory=list)

@dataclass
class CTFURLArtifact:
    original_url: str
    final_url: str = ""
    hostname: str = ""
    status_code: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    title: Optional[str] = None
    response_size: int = 0
    links: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    cookies: List[str] = field(default_factory=list)
    observations: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ============================================================
# REPORTS DIRECTORY
# ============================================================

REPORTS_DIR = "reports"

def ensure_reports_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)

def safe_filename(base: str, ext: str = "md") -> str:
    base = re.sub(r"[^a-zA-Z0-9._-]", "_", base)[:80]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(REPORTS_DIR, f"{base}_{ts}.{ext}")


# ============================================================
# PENTEST ASSESSMENT ENGINE (conservative, report-focused)
# ============================================================

COMMON_PORTS = [
    (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"),
    (53, "dns"), (80, "http"), (110, "pop3"), (143, "imap"),
    (443, "https"), (445, "smb"), (3306, "mysql"), (3389, "rdp"),
    (5432, "postgresql"), (8080, "http-alt"), (8443, "https-alt"),
]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.forms = 0
        self.title = None
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        attrs_d = dict(attrs)
        if tag == "a" and "href" in attrs_d:
            self.links.append(attrs_d["href"])
        if tag == "form":
            self.forms += 1
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title = (self.title or "") + data

class PentestAssessmentEngine:
    def __init__(self):
        self.target = Target()
        self.services: List[ServiceResult] = []
        self.webmap = WebMapResult()
        self.tls = TLSResult()
        self.findings: List[Finding] = []
        self.errors: List[str] = []
        self.modules_completed: List[str] = []
        self.modules_failed: List[str] = []

    # ---------- helpers ----------

    def add_finding(self, title, tag, severity, location, evidence, why, status, next_step):
        f = Finding(title, tag, severity, location, evidence, why, status, next_step)
        self.findings.append(f)
        status(tag, f"{title} @ {location}") if False else None
        return f

    def _log_finding(self, f: Finding):
        colors_tag = f.tag
        print_status = status
        print_status(colors_tag, f"{f.title} — {f.location}")

    def normalize_target(self, raw: str, is_ip: bool):
        raw = raw.strip()
        self.target.raw_input = raw
        self.target.is_ip_target = is_ip
        if is_ip:
            self.target.hostname = raw
            self.target.normalized_url = f"http://{raw}"
        else:
            if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
                raw = "https://" + raw
            parsed = urllib.parse.urlparse(raw)
            self.target.hostname = parsed.hostname or raw
            self.target.scheme = parsed.scheme or "https"
            self.target.normalized_url = raw

    # ---------- 1. Target Information ----------

    def target_information(self):
        section("TARGET INFORMATION")
        try:
            host = self.target.hostname
            status("INFO", f"Resolving DNS for {host}")
            try:
                infos = socket.getaddrinfo(host, None)
                ips = sorted(set(i[4][0] for i in infos))
                self.target.resolved_ips = ips
                for ip in ips:
                    status("OK", f"Resolved IP: {ip}")
            except socket.gaierror as e:
                status("ERROR", f"DNS resolution failed: {e}")
                self.errors.append(f"DNS resolution failed: {e}")
                self.modules_failed.append("Target Information")
                return

            if not self.target.is_ip_target:
                try:
                    req = urllib.request.Request(self.target.normalized_url, method="GET",
                                                  headers={"User-Agent": "NEXUS-Assessment/1.0"})
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        self.target.final_url = resp.geturl()
                        self.target.http_status = resp.status
                        status("OK", f"Final URL after redirects: {self.target.final_url}")
                        status("OK", f"HTTP status: {self.target.http_status}")
                except urllib.error.HTTPError as e:
                    self.target.final_url = e.geturl() if hasattr(e, "geturl") else self.target.normalized_url
                    self.target.http_status = e.code
                    status("OBSERVATION", f"HTTP error response: {e.code}")
                except urllib.error.URLError as e:
                    status("ERROR", f"HTTP request failed: {e.reason}")
                    self.errors.append(f"HTTP request failed: {e.reason}")
                except Exception as e:
                    status("ERROR", f"Unexpected error during HTTP probe: {e}")
                    self.errors.append(str(e))

            self.modules_completed.append("Target Information")
        except Exception as e:
            status("ERROR", f"Target information module failed: {e}")
            self.modules_failed.append("Target Information")

    # ---------- 2. Service Inventory ----------

    def service_inventory(self, delay: float = 0.05, timeout: float = 1.5):
        section("SERVICE INVENTORY")
        if not self.target.resolved_ips:
            status("ERROR", "No resolved IP available. Run Target Information first.")
            self.modules_failed.append("Service Inventory")
            return
        ip = self.target.resolved_ips[0]
        status("INFO", f"Probing {len(COMMON_PORTS)} common ports on {ip} (conservative profile)")
        for port, name in COMMON_PORTS:
            reachable = False
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((ip, port))
                    reachable = (result == 0)
            except Exception:
                reachable = False
            ts = datetime.now(timezone.utc).isoformat()
            self.services.append(ServiceResult(port, "tcp", name, reachable, ts))
            tag = "OK" if reachable else "INFO"
            label = "reachable" if reachable else "not reachable"
            print(f"  {C.DIM}port {port:<6}{C.RESET} {name:<12} {C.GREEN if reachable else C.DIM}{label}{C.RESET}")
            time.sleep(delay)
        self.modules_completed.append("Service Inventory")
        status("INFO", "Service inventory complete. Open ports are not vulnerabilities by themselves.")

    # ---------- 3. Web Application Map ----------

    def web_application_map(self, max_pages: int = 15):
        section("WEB APPLICATION MAP")
        if self.target.is_ip_target:
            base = self.target.normalized_url
        else:
            base = self.target.final_url or self.target.normalized_url
        if not base:
            status("ERROR", "No base URL available.")
            self.modules_failed.append("Web Application Map")
            return

        parsed_base = urllib.parse.urlparse(base)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        visited = set()
        queue = [base]
        discovered_paths = set()
        total_forms = 0
        title = None
        final_status = None
        final_url = base

        try:
            while queue and len(visited) < max_pages:
                url = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "NEXUS-Assessment/1.0"})
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        final_url = resp.geturl()
                        final_status = resp.status
                        raw = resp.read(500_000)
                        try:
                            html = raw.decode(resp.headers.get_content_charset() or "utf-8", errors="ignore")
                        except Exception:
                            html = raw.decode("utf-8", errors="ignore")
                except Exception as e:
                    status("OBSERVATION", f"Could not fetch {url}: {e}")
                    continue

                parser = LinkExtractor()
                try:
                    parser.feed(html)
                except Exception:
                    pass

                if title is None and parser.title:
                    title = parser.title.strip()
                total_forms += parser.forms

                for link in parser.links:
                    absolute = urllib.parse.urljoin(url, link)
                    p = urllib.parse.urlparse(absolute)
                    if p.netloc != parsed_base.netloc:
                        continue  # same-origin only
                    clean = p._replace(fragment="").geturl()
                    if clean not in discovered_paths:
                        discovered_paths.add(clean)
                        if clean not in visited and len(queue) + len(visited) < max_pages:
                            queue.append(clean)

                progress(f"Visited {url} [{final_status}]")

            self.webmap.final_url = final_url
            self.webmap.status_code = final_status
            self.webmap.title = title
            self.webmap.discovered_paths = sorted(discovered_paths)
            self.webmap.forms_found = total_forms
            self.webmap.pages_visited = len(visited)

            status("OK", f"Pages visited: {len(visited)}")
            status("OK", f"Same-origin links discovered: {len(discovered_paths)}")
            if total_forms:
                status("OBSERVATION", f"{total_forms} form(s) detected (not submitted).")
            self.modules_completed.append("Web Application Map")
        except Exception as e:
            status("ERROR", f"Web mapping failed: {e}")
            self.modules_failed.append("Web Application Map")

    # ---------- 4. HTTP Security Review ----------

    def http_security_review(self):
        section("HTTP SECURITY REVIEW")
        url = self.target.final_url or self.webmap.final_url or self.target.normalized_url
        if not url:
            status("ERROR", "No URL available for review.")
            self.modules_failed.append("HTTP Security Review")
            return
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NEXUS-Assessment/1.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                headers = dict(resp.headers.items())
                used_https = resp.geturl().startswith("https://")

            for h in SECURITY_HEADERS:
                present = h in headers
                if present:
                    status("OK", f"{h}: {headers[h][:80]}")
                else:
                    f = Finding(
                        title=f"Missing {h} header",
                        tag="OBSERVATION",
                        severity="Informational",
                        location=url,
                        evidence=f"Response headers did not include '{h}'.",
                        why_it_matters=self._header_rationale(h),
                        status="Unverified",
                        next_step=f"Manually confirm whether {h} is set on other routes/environments and whether its absence is intentional.",
                    )
                    self.findings.append(f)
                    status("OBSERVATION", f"Missing header: {h}")

            if not used_https:
                f = Finding(
                    title="Site served without HTTPS",
                    tag="POTENTIAL FINDING",
                    severity="Medium (informational — needs verification)",
                    location=url,
                    evidence="Final response URL used http:// rather than https://.",
                    why_it_matters="Traffic may be transmitted without transport encryption, risking interception or tampering.",
                    status="Unverified",
                    next_step="Confirm whether an HTTPS endpoint exists and whether HTTP is meant to redirect.",
                )
                self.findings.append(f)
                status("POTENTIAL FINDING", "Site not served over HTTPS")

            set_cookie = headers.get("Set-Cookie")
            if set_cookie:
                missing_attrs = []
                for attr in ("Secure", "HttpOnly", "SameSite"):
                    if attr.lower() not in set_cookie.lower():
                        missing_attrs.append(attr)
                if missing_attrs:
                    f = Finding(
                        title="Cookie missing recommended attributes",
                        tag="OBSERVATION",
                        severity="Informational",
                        location=url,
                        evidence=f"Set-Cookie header observed without: {', '.join(missing_attrs)}.",
                        why_it_matters="Missing cookie flags can increase exposure to XSS-based theft or cross-site transmission, depending on context.",
                        status="Unverified",
                        next_step="Review cookie attributes for all session cookies specifically, not just the first response.",
                    )
                    self.findings.append(f)
                    status("OBSERVATION", f"Cookie missing attributes: {', '.join(missing_attrs)}")

            self.modules_completed.append("HTTP Security Review")
        except Exception as e:
            status("ERROR", f"HTTP security review failed: {e}")
            self.modules_failed.append("HTTP Security Review")

    @staticmethod
    def _header_rationale(header: str) -> str:
        table = {
            "Content-Security-Policy": "Without CSP, the browser has no extra restriction on script/resource sources, which can broaden the impact of an XSS bug if one exists elsewhere.",
            "Strict-Transport-Security": "Without HSTS, browsers may not enforce HTTPS on subsequent visits, leaving a window for downgrade attacks on some networks.",
            "X-Content-Type-Options": "Without this header, some browsers may MIME-sniff responses, which can contribute to content-type confusion issues in specific scenarios.",
            "X-Frame-Options": "Without this (or an equivalent CSP frame-ancestors directive), the page may be embeddable in a frame, which is a precondition for some clickjacking scenarios.",
            "Referrer-Policy": "Without an explicit policy, more of the URL may be leaked via the Referer header to third parties than necessary.",
            "Permissions-Policy": "Without this header, browser feature access (camera, geolocation, etc.) is not explicitly restricted at the HTTP layer.",
        }
        return table.get(header, "This header contributes to defense-in-depth; its absence alone is not a vulnerability.")

    # ---------- 5. TLS / Certificate Review ----------

    def tls_review(self):
        section("TLS / CERTIFICATE REVIEW")
        host = self.target.hostname
        if self.target.is_ip_target:
            status("INFO", "IP-based target: certificate hostname validation is not applicable in the usual sense.")
        port = 443
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    self.tls.tls_version = ssock.version()
                    cipher = ssock.cipher()
                    self.tls.cipher = cipher[0] if cipher else None
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    self.tls.subject = subject.get("commonName")
                    self.tls.issuer = issuer.get("commonName")
                    self.tls.not_before = cert.get("notBefore")
                    self.tls.not_after = cert.get("notAfter")
                    self.tls.hostname_valid = True  # wrap_socket raised if invalid

                    try:
                        not_after_dt = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        days_left = (not_after_dt - datetime.utcnow()).days
                        self.tls.expiring_soon = days_left < 30
                        if self.tls.expiring_soon:
                            status("OBSERVATION", f"Certificate expires in {days_left} day(s)")
                        else:
                            status("OK", f"Certificate valid, {days_left} day(s) remaining")
                    except Exception:
                        pass

                    status("OK", f"TLS version: {self.tls.tls_version}")
                    status("OK", f"Cipher: {self.tls.cipher}")
                    status("OK", f"Subject CN: {self.tls.subject}")
                    status("OK", f"Issuer CN: {self.tls.issuer}")

            self.modules_completed.append("TLS Review")
        except ssl.SSLCertVerificationError as e:
            self.tls.error = str(e)
            self.tls.hostname_valid = False
            status("POTENTIAL FINDING", f"TLS certificate verification failed: {e}")
            f = Finding(
                title="TLS certificate verification failed",
                tag="POTENTIAL FINDING",
                severity="High (needs verification)",
                location=f"{host}:{port}",
                evidence=str(e),
                why_it_matters="A failing certificate chain or hostname mismatch can indicate misconfiguration or expose users to MITM risk.",
                status="Unverified",
                next_step="Manually inspect the certificate chain with openssl s_client and confirm this is not a transient/test-environment issue.",
            )
            self.findings.append(f)
            self.modules_completed.append("TLS Review")
        except socket.timeout:
            status("ERROR", "TLS connection timed out.")
            self.errors.append("TLS connection timeout")
            self.modules_failed.append("TLS Review")
        except Exception as e:
            status("ERROR", f"TLS review failed: {e}")
            self.errors.append(str(e))
            self.modules_failed.append("TLS Review")

    # ---------- 6. Findings ----------

    def show_findings(self, filter_tag: Optional[str] = None):
        section("FINDINGS")
        items = self.findings if not filter_tag else [f for f in self.findings if f.tag == filter_tag]
        if not items:
            status("INFO", "No findings match the current filter.")
            return
        for i, f in enumerate(items, 1):
            print()
            print(f"{C.BOLD}{i}. {f.title}{C.RESET}  [{f.tag} — {f.severity}]")
            print(f"   Location : {f.location}")
            print(f"   Evidence : {f.evidence}")
            print(f"   Matters  : {f.why_it_matters}")
            print(f"   Status   : {f.status}")
            print(f"   Next     : {f.next_step}")

    # ---------- 7. AI Overview (local rule-based, pluggable) ----------

    def ai_overview(self) -> str:
        section("AI OVERVIEW")
        backend = os.environ.get("NEXUS_LLM_BACKEND")
        if backend:
            status("INFO", f"External LLM backend configured ({backend}) — plug-in path active.")
            # Plug-in point: external backend integration would go here.
            # Falls through to local engine if not implemented for this backend.
        overview = self._rule_based_overview()
        print(overview)
        return overview

    def _rule_based_overview(self) -> str:
        lines = []
        lines.append(f"Target: {self.target.hostname or 'unknown'}")
        lines.append(f"Resolved IPs: {', '.join(self.target.resolved_ips) or 'none'}")
        lines.append("")
        lines.append("What NEXUS discovered:")
        if self.target.final_url:
            lines.append(f"  - Reachable web endpoint at {self.target.final_url} (status {self.target.http_status}).")
        open_ports = [s for s in self.services if s.reachable]
        if open_ports:
            lines.append(f"  - {len(open_ports)} of {len(self.services)} probed ports responded: " +
                         ", ".join(f"{s.port}/{s.service_name}" for s in open_ports))
        if self.webmap.pages_visited:
            lines.append(f"  - Mapped {self.webmap.pages_visited} page(s), {len(self.webmap.discovered_paths)} same-origin link(s).")
        if self.tls.tls_version:
            lines.append(f"  - TLS negotiated: {self.tls.tls_version} with cipher {self.tls.cipher}.")

        lines.append("")
        lines.append("Most important observations:")
        pf = [f for f in self.findings if f.tag == "POTENTIAL FINDING"]
        ob = [f for f in self.findings if f.tag == "OBSERVATION"]
        if pf:
            for f in pf:
                lines.append(f"  - [POTENTIAL FINDING] {f.title} ({f.location})")
        else:
            lines.append("  - No potential findings were raised this session.")

        lines.append("")
        lines.append("Deserving manual verification:")
        if pf or ob:
            for f in (pf + ob):
                lines.append(f"  - {f.title}: {f.next_step}")
        else:
            lines.append("  - Nothing flagged.")

        lines.append("")
        lines.append("What is NOT proven:")
        lines.append("  - No exploitation, credential testing, or intrusive attacks were performed.")
        lines.append("  - Open ports and missing headers are not confirmed vulnerabilities by themselves.")
        if self.tls.hostname_valid is False:
            lines.append("  - TLS failure is recorded but root cause (misconfig vs. transient) is not confirmed.")

        lines.append("")
        lines.append("Recommended next inspection:")
        if pf:
            lines.append("  - Prioritize manual verification of listed POTENTIAL FINDINGs.")
        else:
            lines.append("  - Consider deeper manual review of authentication and business logic, which NEXUS does not automate.")

        if self.errors:
            lines.append("")
            lines.append("Errors encountered:")
            for e in self.errors:
                lines.append(f"  - {e}")

        return "\n".join(lines)

    # ---------- 8. Full Assessment ----------

    def full_assessment(self):
        section("FULL ASSESSMENT")
        steps = [
            ("Target Information", self.target_information),
            ("Service Inventory", self.service_inventory),
            ("Web Application Map", self.web_application_map),
            ("HTTP Security Review", self.http_security_review),
            ("TLS Review", self.tls_review),
        ]
        for name, fn in steps:
            try:
                progress(f"Running: {name}")
                fn()
            except Exception as e:
                status("ERROR", f"{name} raised an unexpected error: {e}")
                self.modules_failed.append(name)
                self.errors.append(f"{name}: {e}")

        self.ai_overview()

        section("ASSESSMENT SUMMARY")
        status("OK", f"Modules completed: {len(self.modules_completed)} — {', '.join(self.modules_completed) or 'none'}")
        if self.modules_failed:
            status("ERROR", f"Modules failed: {', '.join(self.modules_failed)}")
        pf_count = len([f for f in self.findings if f.tag == "POTENTIAL FINDING"])
        ob_count = len([f for f in self.findings if f.tag == "OBSERVATION"])
        status("INFO", f"Potential findings: {pf_count} | Observations: {ob_count}")
        status("INFO", "Use [9] GENERATE REPORT to save a Markdown report.")

    # ---------- 9. Generate Report ----------

    def generate_report(self) -> str:
        ensure_reports_dir()
        path = safe_filename(f"pentest_{self.target.hostname or 'target'}")
        overview = self._rule_based_overview()
        lines = []
        lines.append("# NEXUS Security Assessment Report")
        lines.append("")
        lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
        lines.append("")
        lines.append("## Executive Summary")
        pf_count = len([f for f in self.findings if f.tag == "POTENTIAL FINDING"])
        ob_count = len([f for f in self.findings if f.tag == "OBSERVATION"])
        lines.append(f"This report covers a conservative, non-intrusive assessment of "
                     f"`{self.target.hostname}`. {pf_count} potential finding(s) and "
                     f"{ob_count} observation(s) were recorded. No exploitation, credential "
                     f"testing, or denial-of-service activity was performed.")
        lines.append("")
        lines.append("## Target")
        lines.append(f"- Input: `{self.target.raw_input}`")
        lines.append(f"- Hostname: `{self.target.hostname}`")
        lines.append(f"- Resolved IPs: {', '.join(self.target.resolved_ips) or 'N/A'}")
        lines.append(f"- Final URL: {self.target.final_url or 'N/A'}")
        lines.append("")
        lines.append("## Assessment Scope")
        lines.append("Passive/conservative reconnaissance: DNS resolution, limited port reachability "
                     "checks, same-origin web crawl, HTTP header review, and TLS/certificate inspection.")
        lines.append("")
        lines.append("## Methodology")
        lines.append("Standard-library HTTP/TLS/socket probing with fixed timeouts and no aggressive "
                     "or high-volume requests. Findings are evidence-based and explicitly labeled by "
                     "confidence level.")
        lines.append("")
        lines.append("## Target Information")
        lines.append(f"- HTTP status: {self.target.http_status}")
        lines.append("")
        lines.append("## Service Inventory")
        if self.services:
            lines.append("| Port | Service | Reachable |")
            lines.append("|------|---------|-----------|")
            for s in self.services:
                lines.append(f"| {s.port} | {s.service_name} | {'Yes' if s.reachable else 'No'} |")
        else:
            lines.append("Not run.")
        lines.append("")
        lines.append("## Web Application Map")
        lines.append(f"- Pages visited: {self.webmap.pages_visited}")
        lines.append(f"- Title: {self.webmap.title or 'N/A'}")
        lines.append(f"- Forms detected (not submitted): {self.webmap.forms_found}")
        if self.webmap.discovered_paths:
            lines.append("- Discovered paths:")
            for p in self.webmap.discovered_paths[:50]:
                lines.append(f"  - {p}")
        lines.append("")
        lines.append("## HTTP Security Review")
        lines.append("See Findings section for header-related items.")
        lines.append("")
        lines.append("## TLS Review")
        lines.append(f"- TLS version: {self.tls.tls_version or 'N/A'}")
        lines.append(f"- Cipher: {self.tls.cipher or 'N/A'}")
        lines.append(f"- Subject CN: {self.tls.subject or 'N/A'}")
        lines.append(f"- Issuer CN: {self.tls.issuer or 'N/A'}")
        lines.append(f"- Valid: {self.tls.not_before} to {self.tls.not_after}")
        if self.tls.error:
            lines.append(f"- Error: {self.tls.error}")
        lines.append("")
        lines.append("## Findings")
        if self.findings:
            for i, f in enumerate(self.findings, 1):
                lines.append(f"### {i}. {f.title} [{f.tag} — {f.severity}]")
                lines.append(f"- Location: {f.location}")
                lines.append(f"- Evidence: {f.evidence}")
                lines.append(f"- Why it matters: {f.why_it_matters}")
                lines.append(f"- Status: {f.status}")
                lines.append(f"- Recommended next verification: {f.next_step}")
                lines.append("")
        else:
            lines.append("No findings recorded.")
        lines.append("")
        lines.append("## Evidence")
        lines.append("Raw evidence strings are embedded per-finding above.")
        lines.append("")
        lines.append("## AI Overview")
        lines.append("```")
        lines.append(overview)
        lines.append("```")
        lines.append("")
        lines.append("## Limitations")
        lines.append("- No exploitation, brute forcing, credential attacks, or denial-of-service testing was performed.")
        lines.append("- Port reachability does not imply vulnerability.")
        lines.append("- Missing headers do not imply exploitability without further context.")
        lines.append("")
        lines.append("## Recommended Manual Verification")
        if pf_count:
            lines.append("Review each POTENTIAL FINDING above and follow its recommended next step.")
        else:
            lines.append("No high-confidence items require immediate manual verification, but periodic re-assessment is recommended.")
        lines.append("")
        lines.append("## Conclusion")
        lines.append("This automated pass provides a conservative baseline. It is not a substitute for a full manual penetration test.")

        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        status("OK", f"Report saved: {path}")
        return path

# ============================================================
# LAB / CTF ENGINE (local files / localhost / designated lab only)
# ============================================================

LAB_ALLOWED_HOSTS = ("localhost", "127.0.0.1", "::1")

class CTFURLParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self.comments: List[str] = []
        self.title: Optional[str] = None
        self._in_title = False
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag, attrs):
        attrs_d = dict(attrs)
        if tag == "a" and attrs_d.get("href"):
            self.links.append(attrs_d["href"])
        elif tag == "form":
            self._current_form = {
                "method": (attrs_d.get("method") or "GET").upper(),
                "action": attrs_d.get("action") or "",
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attrs_d.get("name") or "",
                "type": attrs_d.get("type") or tag,
            })
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title = (self.title or "") + data

    def handle_comment(self, data):
        cleaned = data.strip()
        if cleaned:
            self.comments.append(cleaned)

class LabCTFEngine:
    def __init__(self):
        self.artifacts: List[CTFArtifact] = []
        self.analysis: Optional[CTFAnalysisResult] = None
        self.description_text: str = ""
        self.lab_mode_confirmed = False
        self.url_artifact: Optional[CTFURLArtifact] = None

    # ---------- target validation ----------

    @staticmethod
    def is_lab_target(host: str) -> bool:
        return host.strip().lower() in LAB_ALLOWED_HOSTS

    def confirm_lab_mode(self, explicit_target: str) -> bool:
        section("LAB MODE CONFIRMATION")
        print("Advanced analysis is restricted to:")
        print("  - local files")
        print("  - localhost / 127.0.0.1")
        print("  - a private lab/CTF environment YOU explicitly designate")
        print()
        print(f"Target you provided: {explicit_target}")
        ans = prompt("Type YES to confirm this is a designated lab/CTF environment you are authorized to test:")
        self.lab_mode_confirmed = ans.strip().lower() in ("y", "yes")
        return self.lab_mode_confirmed

    # ---------- 1. Analyze File ----------

    def analyze_file(self, path: str) -> Optional[CTFArtifact]:
        section("ANALYZE FILE")
        if not os.path.isfile(path):
            status("ERROR", f"File not found: {path}")
            return None

        size = os.path.getsize(path)
        ext = os.path.splitext(path)[1].lower()
        status("OK", f"Size: {size} bytes")
        status("OK", f"Extension: {ext or '(none)'}")

        mime, _ = mimetypes.guess_type(path)
        status("INFO", f"Guessed MIME type: {mime or 'unknown'}")

        file_type = None
        if shutil.which("file"):
            try:
                out = subprocess.run(["file", "-b", path], capture_output=True, text=True, timeout=5)
                file_type = out.stdout.strip()
                status("OK", f"file(1) output: {file_type}")
            except Exception as e:
                status("OBSERVATION", f"'file' command failed: {e}")
        else:
            status("INFO", "'file' utility not available — skipping magic-byte identification.")

        sha256 = self._hash_file(path)
        status("OK", f"SHA-256: {sha256}")

        is_archive = zipfile.is_zipfile(path) or tarfile.is_tarfile(path) or ext in (".zip", ".tar", ".gz", ".7z", ".rar")
        is_text = self._looks_like_text(path)
        is_image = ext in (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp") or (mime and mime.startswith("image/"))
        is_binary = not is_text and not is_image

        artifact = CTFArtifact(path=path, size=size, extension=ext, file_type=file_type,
                                sha256=sha256, is_archive=is_archive, is_text=is_text,
                                is_binary=is_binary, is_image=is_image)
        self.artifacts.append(artifact)

        if is_archive:
            status("OBSERVATION", "Archive detected — listing contents (no extraction).")
            self._list_archive_safe(path)

        if is_image:
            status("OBSERVATION", "Image file detected.")
            self._inspect_image_metadata(path)

        if is_text:
            status("OBSERVATION", "Text-like file — showing preview.")
            self._text_preview(path)

        if is_binary and not is_archive:
            status("OBSERVATION", "Binary file. NEXUS will not execute it automatically.")

        self._recommend_for_type(artifact)
        return artifact

    @staticmethod
    def _hash_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _looks_like_text(path: str, sample_size: int = 2048) -> bool:
        try:
            with open(path, "rb") as fh:
                sample = fh.read(sample_size)
            if b"\x00" in sample:
                return False
            try:
                sample.decode("utf-8")
                return True
            except UnicodeDecodeError:
                return False
        except Exception:
            return False

    def _list_archive_safe(self, path: str):
        try:
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as z:
                    names = z.namelist()[:30]
                    for n in names:
                        print(f"    {n}")
                    if len(z.namelist()) > 30:
                        print(f"    ... and {len(z.namelist()) - 30} more")
            elif tarfile.is_tarfile(path):
                with tarfile.open(path) as t:
                    names = t.getnames()[:30]
                    for n in names:
                        print(f"    {n}")
                    if len(t.getnames()) > 30:
                        print(f"    ... and {len(t.getnames()) - 30} more")
            else:
                status("INFO", "Archive format not natively listable by stdlib (e.g. 7z/rar).")
        except Exception as e:
            status("ERROR", f"Archive listing failed: {e}")

    def _inspect_image_metadata(self, path: str):
        try:
            with open(path, "rb") as fh:
                header = fh.read(32)
            status("INFO", f"Header bytes: {header[:16].hex()}")
            if header.startswith(b"\x89PNG"):
                status("OK", "Confirmed PNG signature.")
            elif header[:2] == b"\xff\xd8":
                status("OK", "Confirmed JPEG signature.")
            elif header[:6] in (b"GIF87a", b"GIF89a"):
                status("OK", "Confirmed GIF signature.")
        except Exception as e:
            status("OBSERVATION", f"Could not read image header: {e}")

    def _text_preview(self, path: str, limit: int = 500):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                data = fh.read(limit)
            print(C.DIM + "  --- preview (first {} chars) ---".format(limit) + C.RESET)
            for line in data.splitlines()[:15]:
                print("   " + line)
            print(C.DIM + "  --- end preview ---" + C.RESET)
        except Exception as e:
            status("OBSERVATION", f"Could not preview file: {e}")

    def _recommend_for_type(self, a: CTFArtifact):
        recs = []
        if a.is_archive:
            recs.append("Inspect archive listing for suspicious filenames or nested archives before extracting.")
        if a.is_image:
            recs.append("Check for steganography tools appropriate to the format; inspect EXIF/metadata.")
        if a.is_text:
            recs.append("Search for flag-format strings, encoded blobs, or comments.")
        if a.is_binary and not a.is_archive:
            recs.append("Identify architecture/format before running in a controlled sandbox — never execute directly.")
        if not recs:
            recs.append("No specific pattern matched; proceed with manual inspection.")
        status("INFO", "Recommendations:")
        for r in recs:
            print(f"    - {r}")

    # ---------- 2. Analyze Folder ----------

    def analyze_folder(self, path: str, max_depth: int = 4):
        section("ANALYZE FOLDER")
        if not os.path.isdir(path):
            status("ERROR", f"Folder not found: {path}")
            return

        file_count = 0
        total_size = 0
        ext_counts: Dict[str, int] = {}
        interesting = []
        archives = []

        base_depth = path.rstrip(os.sep).count(os.sep)
        for root, dirs, files in os.walk(path):
            depth = root.rstrip(os.sep).count(os.sep) - base_depth
            if depth >= max_depth:
                dirs[:] = []
                continue
            for name in files:
                full = os.path.join(root, name)
                try:
                    size = os.path.getsize(full)
                except OSError:
                    continue
                file_count += 1
                total_size += size
                ext = os.path.splitext(name)[1].lower() or "(none)"
                ext_counts[ext] = ext_counts.get(ext, 0) + 1
                if ext in (".zip", ".tar", ".gz", ".7z", ".rar"):
                    archives.append(full)
                if re.search(r"flag|key|secret|password|\.pem$|\.key$", name, re.IGNORECASE):
                    interesting.append(full)

        status("OK", f"Files: {file_count}")
        status("OK", f"Total size: {total_size} bytes")
        status("INFO", "Extension breakdown:")
        for ext, count in sorted(ext_counts.items(), key=lambda x: -x[1]):
            print(f"    {ext:<12} {count}")

        if archives:
            status("OBSERVATION", f"{len(archives)} archive(s) found:")
            for a in archives[:20]:
                print(f"    {a}")

        if interesting:
            status("OBSERVATION", f"{len(interesting)} filename(s) matched interesting patterns:")
            for i in interesting[:20]:
                print(f"    {i}")
        else:
            status("INFO", "No filenames matched common flag/secret patterns.")

    # ---------- 3. Analyze Text / Description ----------

    def analyze_text(self, text: str) -> CTFAnalysisResult:
        section("ANALYZE TEXT / DESCRIPTION")
        self.description_text = text
        lower = text.lower()

        categories = {
            "web": ["sql", "xss", "http", "cookie", "login", "website", "url", "api"],
            "crypto": ["cipher", "encrypt", "decrypt", "rsa", "aes", "xor", "hash", "key"],
            "forensics": ["pcap", "memory dump", "image file", "steg", "metadata", "disk image"],
            "reverse engineering": ["binary", "reverse", "disassemble", "elf", "exe", "ida", "ghidra"],
            "pwn": ["buffer overflow", "shellcode", "stack", "heap", "exploit", "nc ", "netcat"],
            "osint": ["social media", "public information", "search engine", "username"],
        }
        scores = {}
        clues = []
        for cat, kws in categories.items():
            hits = [kw for kw in kws if kw in lower]
            if hits:
                scores[cat] = len(hits)
                clues.extend(hits)

        best_cat = max(scores, key=scores.get) if scores else None

        formats = []
        if re.search(r"\.pcap\b", lower):
            formats.append("pcap")
        if re.search(r"\.zip\b", lower):
            formats.append("zip")
        if re.search(r"\.png|\.jpg|\.jpeg|\.gif", lower):
            formats.append("image")
        if re.search(r"\.pem|\.key|\.crt", lower):
            formats.append("key/cert material")

        steps = []
        if best_cat:
            steps.append(f"Start by treating this as a likely '{best_cat}' challenge based on keyword matches.")
        if formats:
            steps.append(f"Inspect provided file(s) matching detected format(s): {', '.join(formats)}.")
        steps.append("Use ANALYZE FILE / ANALYZE FOLDER on any provided artifacts before guessing.")
        steps.append("Re-read the description for any embedded hints (usernames, URLs, encoded text).")

        result = CTFAnalysisResult(category_guess=best_cat, clues=clues, recommended_steps=steps)
        self.analysis = result

        status("OK", f"Likely category: {best_cat or 'undetermined'}")
        if clues:
            status("INFO", f"Matched clue keywords: {', '.join(sorted(set(clues)))}")
        if formats:
            status("INFO", f"Possible file formats referenced: {', '.join(formats)}")
        status("INFO", "No flag is fabricated or guessed by NEXUS.")
        return result

    # ---------- 4. Analyze CTF URL ----------

    @staticmethod
    def _normalize_ctf_url(raw: str) -> Optional[str]:
        raw = raw.strip()
        if not raw:
            return None
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
            raw = "http://" + raw
        parsed = urllib.parse.urlparse(raw)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return None
        return raw

    def analyze_ctf_url(self, raw_url: str, max_links: int = 25) -> Optional[CTFURLArtifact]:
        section("ANALYZE CTF URL")
        url = self._normalize_ctf_url(raw_url)
        if not url:
            status("ERROR", "Invalid URL. Use http:// or https:// with a hostname.")
            return None

        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        if not self.is_lab_target(host):
            if not self.confirm_lab_mode(url):
                status("INFO", "LAB MODE not confirmed. URL analysis cancelled.")
                return None
        else:
            status("OK", "Local lab target detected.")

        artifact = CTFURLArtifact(original_url=url, hostname=host)
        section("CTF URL ANALYSIS")
        status("INFO", f"Original URL: {url}")
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "NEXUS-CTF-Lab/1.0", "Accept": "text/html,*/*;q=0.8"},
                method="GET",
            )
            try:
                response = urllib.request.urlopen(req, timeout=8)
            except urllib.error.HTTPError as e:
                response = e

            with response as resp:
                artifact.final_url = resp.geturl()
                artifact.status_code = getattr(resp, "status", None) or getattr(resp, "code", None)
                artifact.headers = dict(resp.headers.items()) if resp.headers else {}
                raw = resp.read(500_000)
                artifact.response_size = len(raw)
                charset = "utf-8"
                try:
                    charset = resp.headers.get_content_charset() or "utf-8"
                except Exception:
                    pass
                html = raw.decode(charset, errors="ignore")

            status("OK", f"Final URL: {artifact.final_url}")
            status("OK", f"HTTP status: {artifact.status_code}")
            status("OK", f"Response size: {artifact.response_size} bytes")

            parser = CTFURLParser()
            try:
                parser.feed(html)
                parser.close()
            except Exception as e:
                artifact.errors.append(f"HTML parsing failed: {e}")
                status("OBSERVATION", f"HTML parsing issue: {e}")

            artifact.title = parser.title.strip() if parser.title else None
            if artifact.title:
                status("OK", f"Title: {artifact.title}")

            final_parsed = urllib.parse.urlparse(artifact.final_url or url)
            same_origin = f"{final_parsed.scheme}://{final_parsed.netloc}"
            seen = set()
            for link in parser.links:
                absolute = urllib.parse.urljoin(artifact.final_url or url, link)
                lp = urllib.parse.urlparse(absolute)
                if lp.scheme not in ("http", "https") or lp.netloc != final_parsed.netloc:
                    continue
                clean = lp._replace(fragment="").geturl()
                if clean not in seen:
                    seen.add(clean)
                    artifact.links.append(clean)
                if len(artifact.links) >= max_links:
                    break

            artifact.forms = parser.forms
            artifact.comments = parser.comments[:10]
            artifact.cookies = [v for k, v in artifact.headers.items() if k.lower() == "set-cookie"]

            server = next((v for k, v in artifact.headers.items() if k.lower() == "server"), None)
            powered = next((v for k, v in artifact.headers.items() if k.lower() == "x-powered-by"), None)
            if server:
                artifact.observations.append(f"Server header observed: {server}")
            if powered:
                artifact.observations.append(f"X-Powered-By observed: {powered}")
            if artifact.comments:
                artifact.observations.append(f"{len(artifact.comments)} HTML comment(s) discovered")
            if artifact.forms:
                artifact.observations.append(f"{len(artifact.forms)} form(s) discovered without submission")

            print()
            print("DISCOVERED LINKS")
            hr()
            if artifact.links:
                for i, link in enumerate(artifact.links, 1):
                    print(f"[{i}] {link}")
            else:
                status("INFO", "No same-origin links discovered.")

            print()
            print("FORMS")
            hr()
            if artifact.forms:
                for i, form in enumerate(artifact.forms, 1):
                    print(f"Form {i}")
                    print(f"  Method: {form['method']}")
                    print(f"  Action: {urllib.parse.urljoin(artifact.final_url or url, form['action']) if form['action'] else artifact.final_url or url}")
                    if form["inputs"]:
                        print("  Inputs:")
                        for inp in form["inputs"][:30]:
                            print(f"    {inp['name'] or '(unnamed)'} [{inp['type']}]")
                    else:
                        print("  Inputs: none detected")
            else:
                status("INFO", "No forms discovered.")

            print()
            print("CLUES / COMMENTS")
            hr()
            if artifact.comments:
                for i, comment in enumerate(artifact.comments, 1):
                    preview = comment[:300] + ("..." if len(comment) > 300 else "")
                    print(f"[{i}] {preview}")
            else:
                status("INFO", "No HTML comments discovered.")

            # Conservative optional resource checks: two standard CTF/web resources only.
            for resource in ("robots.txt", "favicon.ico"):
                candidate = urllib.parse.urljoin(same_origin + "/", resource)
                try:
                    r = urllib.request.Request(candidate, headers={"User-Agent": "NEXUS-CTF-Lab/1.0"}, method="GET")
                    with urllib.request.urlopen(r, timeout=5) as resp:
                        code = resp.status
                        if code < 400:
                            artifact.observations.append(f"Resource available: {candidate} ({code})")
                            status("OBSERVATION", f"Available: {candidate} [{code}]")
                except urllib.error.HTTPError:
                    pass
                except Exception as e:
                    artifact.errors.append(f"{resource} check: {e}")

            print()
            print("OBSERVATIONS")
            hr()
            if artifact.observations:
                for item in artifact.observations:
                    status("OBSERVATION", item)
            else:
                status("INFO", "No additional observations.")

            self.url_artifact = artifact
            return artifact

        except urllib.error.URLError as e:
            artifact.errors.append(f"Connection failed: {e.reason}")
            status("ERROR", f"Connection failed: {e.reason}")
        except socket.timeout:
            artifact.errors.append("Request timed out")
            status("ERROR", "Request timed out.")
        except ssl.SSLError as e:
            artifact.errors.append(f"TLS error: {e}")
            status("ERROR", f"TLS error: {e}")
        except Exception as e:
            artifact.errors.append(str(e))
            status("ERROR", f"URL analysis failed: {e}")
        self.url_artifact = artifact
        return None

    # ---------- 4. Analysis Plan ----------

    def analysis_plan(self):
        section("ANALYSIS PLAN")
        if not self.artifacts and not self.analysis and not self.url_artifact:
            status("ERROR", "No artifacts, description, or CTF URL analyzed yet. Run option 1-4 first.")
            return

        step_num = 1
        print(f"STEP {step_num} — Identify challenge artifacts")
        print("Evidence:")
        if self.artifacts:
            for a in self.artifacts:
                print(f"  - {a.path} ({a.file_type or a.extension}, {a.size} bytes, sha256={a.sha256[:16]}...)")
        else:
            print("  - No files analyzed yet.")
        if self.url_artifact:
            print(f"  - URL: {self.url_artifact.final_url or self.url_artifact.original_url} (status {self.url_artifact.status_code})")
            print(f"  - Links: {len(self.url_artifact.links)} | Forms: {len(self.url_artifact.forms)} | Comments: {len(self.url_artifact.comments)}")
        print()
        step_num += 1

        if self.url_artifact:
            print(f"STEP {step_num} — Review application response and discovered resources")
            print("Evidence:")
            print(f"  - {len(self.url_artifact.links)} same-origin link(s) and {len(self.url_artifact.forms)} form(s) were collected without submission.")
            if self.url_artifact.comments:
                print(f"  - {len(self.url_artifact.comments)} HTML comment clue(s) were collected.")
            print("Objective:")
            print("  - Understand the challenge structure and inspect evidence-backed resources manually within the CTF/LAB environment.")
            print()
            step_num += 1

        print(f"STEP {step_num} — Inspect metadata")
        print("Reason:")
        img = [a for a in self.artifacts if a.is_image]
        arc = [a for a in self.artifacts if a.is_archive]
        if img:
            print(f"  - {len(img)} image file(s) detected; metadata/steganography inspection is warranted.")
        if arc:
            print(f"  - {len(arc)} archive(s) detected; contents were listed without extraction.")
        if not img and not arc:
            print("  - No image or archive artifacts detected yet.")
        print()
        step_num += 1

        print(f"STEP {step_num} — Analyze relevant structures")
        print("Reason:")
        if self.analysis and self.analysis.category_guess:
            print(f"  - Description matched '{self.analysis.category_guess}' keywords: {', '.join(self.analysis.clues[:8])}")
            for s in self.analysis.recommended_steps:
                print(f"  - {s}")
        else:
            print("  - No text description analyzed yet, or no category could be inferred.")

    # ---------- 5. AI Overview ----------

    def ai_overview(self) -> str:
        section("AI OVERVIEW")
        lines = []
        lines.append(f"Artifacts analyzed: {len(self.artifacts)}")
        lines.append(f"Detected category (from description): {self.analysis.category_guess if self.analysis else 'N/A'}")
        if self.url_artifact:
            lines.append(f"CTF URL: {self.url_artifact.final_url or self.url_artifact.original_url}")
            lines.append(f"HTTP status: {self.url_artifact.status_code}")
            lines.append(f"Links: {len(self.url_artifact.links)} | Forms: {len(self.url_artifact.forms)} | Comments: {len(self.url_artifact.comments)}")
        lines.append("")
        lines.append("Strongest clues:")
        if self.analysis and self.analysis.clues:
            for c in sorted(set(self.analysis.clues)):
                lines.append(f"  - {c}")
        else:
            lines.append("  - None identified yet.")
        lines.append("")
        lines.append("Completed analysis:")
        for a in self.artifacts:
            lines.append(f"  - {a.path}: type={a.file_type or a.extension}, archive={a.is_archive}, image={a.is_image}, text={a.is_text}")
        if not self.artifacts:
            lines.append("  - No files analyzed.")
        if self.url_artifact:
            lines.append(f"  - URL response: {self.url_artifact.final_url or self.url_artifact.original_url} [{self.url_artifact.status_code}]")
            if self.url_artifact.observations:
                for item in self.url_artifact.observations:
                    lines.append(f"  - {item}")
        lines.append("")
        lines.append("Remaining unknowns:")
        lines.append("  - No flag has been located or fabricated.")
        lines.append("  - Deeper structural analysis (disassembly, packet reconstruction, decryption) is not automated by NEXUS.")
        lines.append("")
        lines.append("Recommended next actions:")
        if self.url_artifact:
            lines.append("  - Review discovered same-origin links and standard CTF resources that were actually available.")
            if self.url_artifact.forms:
                lines.append("  - Inspect form behavior manually; forms were not submitted by NEXUS.")
            if self.url_artifact.comments:
                lines.append("  - Review collected HTML comments as challenge clues.")
        if self.analysis:
            for s in self.analysis.recommended_steps:
                lines.append(f"  - {s}")
        elif not self.url_artifact:
            lines.append("  - Provide a description, URL, or artifact for more specific guidance.")
        out = "\n".join(lines)
        print(out)
        return out

    # ---------- 6. Generate Report ----------

    def generate_report(self) -> str:
        ensure_reports_dir()
        path = safe_filename("ctf_lab")
        overview = self.ai_overview()
        lines = []
        lines.append("# NEXUS CTF / LAB REPORT")
        lines.append("")
        lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
        lines.append("")
        lines.append("## Challenge Source")
        lines.append(self.description_text[:500] if self.description_text else "No description provided.")
        lines.append("")
        lines.append("## Initial Evidence")
        for a in self.artifacts:
            lines.append(f"- `{a.path}` — {a.size} bytes, sha256=`{a.sha256}`")
        if not self.artifacts:
            lines.append("No artifacts provided.")
        lines.append("")
        lines.append("## Artifact Analysis")
        for a in self.artifacts:
            lines.append(f"### {a.path}")
            lines.append(f"- Type: {a.file_type or 'unknown'}")
            lines.append(f"- Extension: {a.extension}")
            lines.append(f"- Archive: {a.is_archive} | Image: {a.is_image} | Text: {a.is_text} | Binary: {a.is_binary}")
        lines.append("")
        lines.append("## Detected Types")
        types = sorted(set((a.file_type or a.extension or "unknown") for a in self.artifacts))
        lines.append(", ".join(types) if types else "N/A")
        lines.append("")
        lines.append("## Analysis Steps")
        if self.analysis:
            for s in self.analysis.recommended_steps:
                lines.append(f"- {s}")
        else:
            lines.append("No description analyzed.")
        lines.append("")
        if self.url_artifact:
            u = self.url_artifact
            lines.append("## CTF URL Analysis")
            lines.append(f"- Original URL: {u.original_url}")
            lines.append(f"- Final URL: {u.final_url or 'N/A'}")
            lines.append(f"- Hostname: {u.hostname}")
            lines.append(f"- HTTP Status: {u.status_code}")
            lines.append(f"- Page Title: {u.title or 'N/A'}")
            lines.append(f"- Response Size: {u.response_size} bytes")
            lines.append("")
            lines.append("### Response Headers Summary")
            if u.headers:
                for k, v in list(u.headers.items())[:50]:
                    lines.append(f"- {k}: {v}")
            else:
                lines.append("No headers collected.")
            lines.append("")
            lines.append("### Discovered Links")
            if u.links:
                for link in u.links:
                    lines.append(f"- {link}")
            else:
                lines.append("None.")
            lines.append("")
            lines.append("### Forms")
            if u.forms:
                for i, form in enumerate(u.forms, 1):
                    lines.append(f"#### Form {i}")
                    lines.append(f"- Method: {form['method']}")
                    lines.append(f"- Action: {form['action'] or '(same page)'}")
                    lines.append("- Inputs: " + (", ".join(f"{x['name'] or '(unnamed)'} [{x['type']}]" for x in form['inputs']) or "none detected"))
            else:
                lines.append("None.")
            lines.append("")
            lines.append("### HTML Comments / Clues")
            if u.comments:
                for c in u.comments:
                    lines.append(f"- {c[:500]}")
            else:
                lines.append("None.")
            lines.append("")
            lines.append("### Cookies Observed")
            lines.extend([f"- {c}" for c in u.cookies] or ["None."])
            lines.append("")
            lines.append("### Observations")
            lines.extend([f"- {o}" for o in u.observations] or ["None."])
            lines.append("")
            lines.append("### Errors")
            lines.extend([f"- {e}" for e in u.errors] or ["None."])
            lines.append("")
            lines.append("### Recommended Next Actions")
            lines.append("- Review collected links, forms, comments, and available challenge resources manually within the authorized CTF/LAB environment.")
            lines.append("- Do not treat observations as a solved challenge or vulnerability without evidence.")
            lines.append("")

        lines.append("## AI Overview")
        lines.append("```")
        lines.append(overview)
        lines.append("```")
        lines.append("")
        lines.append("## Findings / Clues")
        if self.analysis and self.analysis.clues:
            for c in sorted(set(self.analysis.clues)):
                lines.append(f"- {c}")
        else:
            lines.append("None recorded.")
        lines.append("")
        lines.append("## Recommended Next Actions")
        if self.analysis:
            for s in self.analysis.recommended_steps:
                lines.append(f"- {s}")
        lines.append("")
        lines.append("## Limitations")
        lines.append("- No flag was fabricated or guessed.")
        lines.append("- No automated exploitation was performed.")

        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        status("OK", f"Report saved: {path}")
        return path

# ============================================================
# MENU FLOW (main.py entry point) — no recursive menu calls
# ============================================================

def environment_check():
    section("NEXUS ENVIRONMENT CHECK")
    status("OK", f"Python: {sys.version.split()[0]}")
    if shutil.which("file"):
        status("OK", "file utility: AVAILABLE")
    else:
        status("INFO", "file utility: OPTIONAL (not found — some identification will be skipped)")
    ensure_reports_dir()
    status("OK", "Report directory: READY")
    pause()

# ============================================================
# SQL Injection Module
# ============================================================

class SQLInjectionDetector:
    @staticmethod
    def detect_sql_injection(url, payloads):
        for payload in payloads:
            test_url = f"{url}?id={payload}"
            try:
                response = urllib.request.urlopen(test_url, timeout=5)
                if "error" in response.read().decode('utf-8', errors='ignore').lower():
                    return True, payload
            except Exception:
                continue
        return False, None

    @staticmethod
    def exploit_sql_injection(url, payload):
        test_url = f"{url}?id={payload}"
        try:
            response = urllib.request.urlopen(test_url, timeout=5)
            return response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            return str(e)

# ============================================================
# Cross-Site Scripting (XSS) Module
# ============================================================

class XSSDetector:
    @staticmethod
    def detect_xss(url, payloads):
        for payload in payloads:
            test_url = f"{url}?query={payload}"
            try:
                response = urllib.request.urlopen(test_url, timeout=5)
                if payload in response.read().decode('utf-8', errors='ignore'):
                    return True, payload
            except Exception:
                continue
        return False, None

    @staticmethod
    def exploit_xss(url, payload):
        test_url = f"{url}?query={payload}"
        try:
            response = urllib.request.urlopen(test_url, timeout=5)
            return response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            return str(e)

# ============================================================
# Cross-Site Request Forgery (CSRF) Module
# ============================================================

class CSRFDetector:
    @staticmethod
    def detect_csrf(url, payloads):
        for payload in payloads:
            test_url = f"{url}?csrf={payload}"
            try:
                response = urllib.request.urlopen(test_url, timeout=5)
                if "csrf" in response.read().decode('utf-8', errors='ignore').lower():
                    return True, payload
            except Exception:
                continue
        return False, None

    @staticmethod
    def exploit_csrf(url, payload):
        test_url = f"{url}?csrf={payload}"
        try:
            response = urllib.request.urlopen(test_url, timeout=5)
            return response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            return str(e)

# ============================================================
# Directory Traversal Module
# ============================================================

class DirectoryTraversalDetector:
    @staticmethod
    def detect_directory_traversal(url, payloads):
        for payload in payloads:
            test_url = f"{url}?file={payload}"
            try:
                response = urllib.request.urlopen(test_url, timeout=5)
                if "root" in response.read().decode('utf-8', errors='ignore').lower():
                    return True, payload
            except Exception:
                continue
        return False, None

    @staticmethod
    def exploit_directory_traversal(url, payload):
        test_url = f"{url}?file={payload}"
        try:
            response = urllib.request.urlopen(test_url, timeout=5)
            return response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            return str(e)

# ============================================================
# Command Injection Module
# ============================================================

class CommandInjectionDetector:
    @staticmethod
    def detect_command_injection(url, payloads):
        for payload in payloads:
            test_url = f"{url}?cmd={payload}"
            try:
                response = urllib.request.urlopen(test_url, timeout=5)
                if "command" in response.read().decode('utf-8', errors='ignore').lower():
                    return True, payload
            except Exception:
                continue
        return False, None

    @staticmethod
    def exploit_command_injection(url, payload):
        test_url = f"{url}?cmd={payload}"
        try:
            response = urllib.request.urlopen(test_url, timeout=5)
            return response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            return str(e)

# ============================================================
# Updated Pentest Menu
# ============================================================

def pentest_menu(engine: PentestAssessmentEngine):
    while True:
        lines = [
            "",
            "  [1]  TARGET INFORMATION",
            "  [2]  SERVICE INVENTORY",
            "  [3]  WEB APPLICATION MAP",
            "  [4]  HTTP SECURITY REVIEW",
            "  [5]  TLS / CERTIFICATE REVIEW",
            "  [6]  FINDINGS",
            "  [7]  AI OVERVIEW",
            "  [8]  FULL ASSESSMENT",
            "  [9]  GENERATE REPORT",
            "  [10] SQL INJECTION",
            "  [11] XSS",
            "  [12] CSRF",
            "  [13] DIRECTORY TRAVERSAL",
            "  [14] COMMAND INJECTION",
            "",
            "  [B]  BACK",
            "",
        ]
        box(lines, title="NEXUS • PENTEST")
        choice = prompt(">")
        if choice == "__INTERRUPT__":
            return
        choice = choice.strip().lower()

        if choice == "1":
            engine.target_information(); pause()
        elif choice == "2":
            engine.service_inventory(); pause()
        elif choice == "3":
            engine.web_application_map(); pause()
        elif choice == "4":
            engine.http_security_review(); pause()
        elif choice == "5":
            engine.tls_review(); pause()
        elif choice == "6":
            sub = prompt("Filter by (info/observation/finding/all):").strip().lower()
            tag_map = {"info": "INFO", "observation": "OBSERVATION", "finding": "POTENTIAL FINDING"}
            engine.show_findings(tag_map.get(sub))
            pause()
        elif choice == "7":
            engine.ai_overview(); pause()
        elif choice == "8":
            engine.full_assessment(); pause()
        elif choice == "9":
            engine.generate_report(); pause()
        elif choice == "10":
            url = prompt("Enter the URL to test for SQL Injection:")
            sql_payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #"]
            detected, payload = SQLInjectionDetector.detect_sql_injection(url, sql_payloads)
            if detected:
                print(f"SQL Injection detected with payload: {payload}")
                result = SQLInjectionDetector.exploit_sql_injection(url, payload)
                print(f"Exploitation result: {result}")
            pause()
        elif choice == "11":
            url = prompt("Enter the URL to test for XSS:")
            xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
            detected, payload = XSSDetector.detect_xss(url, xss_payloads)
            if detected:
                print(f"XSS detected with payload: {payload}")
                result = XSSDetector.exploit_xss(url, payload)
                print(f"Exploitation result: {result}")
            pause()
        elif choice == "12":
            url = prompt("Enter the URL to test for CSRF:")
            csrf_payloads = ["<script>alert('CSRF')</script>", "<img src=x onerror=alert('CSRF')>"]
            detected, payload = CSRFDetector.detect_csrf(url, csrf_payloads)
            if detected:
                print(f"CSRF detected with payload: {payload}")
                result = CSRFDetector.exploit_csrf(url, payload)
                print(f"Exploitation result: {result}")
            pause()
        elif choice == "13":
            url = prompt("Enter the URL to test for Directory Traversal:")
            dt_payloads = ["../../../../etc/passwd", "../../../../etc/shadow"]
            detected, payload = DirectoryTraversalDetector.detect_directory_traversal(url, dt_payloads)
            if detected:
                print(f"Directory Traversal detected with payload: {payload}")
                result = DirectoryTraversalDetector.exploit_directory_traversal(url, payload)
                print(f"Exploitation result: {result}")
            pause()
        elif choice == "14":
            url = prompt("Enter the URL to test for Command Injection:")
            ci_payloads = ["; ls -la", "; cat /etc/passwd"]
            detected, payload = CommandInjectionDetector.detect_command_injection(url, ci_payloads)
            if detected:
                print(f"Command Injection detected with payload: {payload}")
                result = CommandInjectionDetector.exploit_command_injection(url, payload)
                print(f"Exploitation result: {result}")
            pause()
        elif choice == "b":
            return
        else:
            status("ERROR", "Invalid selection.")
            time.sleep(0.8)

# ============================================================
# Main Menu and Entry Point
# ============================================================

def run_pentest_mode():
    while True:
        lines = [
            "",
            "  [1]  Website / Domain",
            "  [2]  IP Address",
            "",
            "  [B]  Back",
            "",
        ]
        box(lines, title="NEXUS • PENTEST • SELECT TARGET TYPE")
        choice = prompt(">")
        if choice == "__INTERRUPT__":
            return
        choice = choice.strip().lower()

        if choice == "b":
            return
        if choice not in ("1", "2"):
            status("ERROR", "Invalid selection.")
            time.sleep(0.8)
            continue

        is_ip = (choice == "2")
        raw = prompt("Enter target (domain or IP):")
        if raw == "__INTERRUPT__" or not raw:
            continue

        if not confirm_authorization():
            status("INFO", "Authorization not confirmed. Returning to menu.")
            time.sleep(1)
            continue

        engine = PentestAssessmentEngine()
        engine.normalize_target(raw, is_ip)
        pentest_menu(engine)
        return  # return to main menu after finishing this target's session

def lab_ctf_menu(lab: LabCTFEngine):
    while True:
        lines = [
            "",
            "  [1]  ANALYZE FILE",
            "  [2]  ANALYZE FOLDER",
            "  [3]  ANALYZE TEXT / DESCRIPTION",
            "  [4]  ANALYZE CTF URL",
            "  [5]  ANALYSIS PLAN",
            "  [6]  AI OVERVIEW",
            "  [7]  GENERATE REPORT",
            "",
            "  [B]  BACK",
            "",
        ]
        box(lines, title="NEXUS • CTF / LAB")
        choice = prompt(">")
        if choice == "__INTERRUPT__":
            return
        choice = choice.strip().lower()

        if choice == "1":
            p = prompt("Path to file:")
            if p and p != "__INTERRUPT__":
                lab.analyze_file(p)
            pause()
        elif choice == "2":
            p = prompt("Path to folder:")
            if p and p != "__INTERRUPT__":
                lab.analyze_folder(p)
            pause()
        elif choice == "3":
            print("Paste challenge description (single line):")
            t = prompt(">")
            if t and t != "__INTERRUPT__":
                lab.analyze_text(t)
            pause()
        elif choice == "4":
            u = prompt("CTF / LAB URL:")
            if u and u != "__INTERRUPT__":
                lab.analyze_ctf_url(u)
            pause()
        elif choice == "5":
            lab.analysis_plan(); pause()
        elif choice == "6":
            lab.ai_overview(); pause()
        elif choice == "7":
            lab.generate_report(); pause()
        elif choice == "b":
            return
        else:
            status("ERROR", "Invalid selection.")
            time.sleep(0.8)

def run_ctf_lab_mode():
    lab = LabCTFEngine()
    lab_ctf_menu(lab)

def main_menu():
    while True:
        lines = [
            "",
            "  [1]  PENTEST",
            "       Authorized security assessment",
            "",
            "  [2]  CTF / LAB",
            "       Challenge solving and lab analysis",
            "",
            "  [Q]  EXIT",
            "",
        ]
        banner()
        box(lines)
        choice = prompt(">")
        if choice == "__INTERRUPT__":
            print()
            status("INFO", "Exiting NEXUS.")
            return
        choice = choice.strip().lower()

        if choice == "1":
            run_pentest_mode()
        elif choice == "2":
            run_ctf_lab_mode()
        elif choice == "q":
            status("INFO", "Exiting NEXUS.")
            return
        else:
            status("ERROR", "Invalid selection.")
            time.sleep(0.8)

def main():
    try:
        ensure_reports_dir()
        environment_check()
        main_menu()
    except KeyboardInterrupt:
        print()
        status("INFO", "Interrupted. Exiting NEXUS cleanly.")
        sys.exit(0)
    except Exception as e:
        print()
        status("ERROR", f"Unhandled top-level error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```
