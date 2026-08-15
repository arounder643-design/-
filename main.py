#!/usr/bin/env python3

import os
import socket
import subprocess
import urllib.request
import urllib.error
import ssl
from urllib.parse import urljoin, urlparse
from datetime import datetime


# =========================================================
# NEXUS V5
# AI SECURITY RESEARCH AGENT
# =========================================================

REPORT_DIR = "reports"

findings = []
ctf_steps = []


# =========================================================
# UI
# =========================================================

def clear_screen():
    os.system("clear")


def pause():
    input("\nPress Enter to continue...")


def line():
    print("═" * 58)


def title(text):
    print()
    line()
    print(f"  {text}")
    line()


def banner():
    clear_screen()

    print(r"""
╔════════════════════════════════════════════════════════╗
║                                                        ║
║                       N E X U S                        ║
║                                                        ║
║              AI SECURITY RESEARCH AGENT                ║
║                                                        ║
╠════════════════════════════════════════════════════════╣
║                                                        ║
║   [1]  PENTEST                                         ║
║        Authorized security assessment                  ║
║                                                        ║
║   [2]  CTF                                             ║
║        Challenge analysis and investigation            ║
║                                                        ║
║   [Q]  EXIT                                            ║
║                                                        ║
╚════════════════════════════════════════════════════════╝
""")


# =========================================================
# REPORT HELPERS
# =========================================================

def ensure_report_dir():
    os.makedirs(REPORT_DIR, exist_ok=True)


def safe_filename(value):
    cleaned = []

    for char in value:
        if char.isalnum() or char in "-_":
            cleaned.append(char)
        else:
            cleaned.append("_")

    return "".join(cleaned)


def add_finding(title_text, location, evidence, status="Potential Finding"):
    finding = {
        "title": title_text,
        "location": location,
        "evidence": evidence,
        "status": status
    }

    findings.append(finding)


# =========================================================
# AUTHORIZATION
# =========================================================

def confirm_authorization(target):

    title("AUTHORIZATION CHECK")

    print(f"Target: {target}")
    print()
    print("Continue only when the target is explicitly authorized")
    print("for your security assessment or is within the applicable scope.")

    answer = input("\nDo you confirm authorization? [y/n]: ").strip().lower()

    return answer in ("y", "yes")


# =========================================================
# TARGET NORMALIZATION
# =========================================================

def get_hostname(target):

    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target

    return target.split("/")[0]


def get_url(target):

    if target.startswith("http://") or target.startswith("https://"):
        return target

    return "https://" + target


# =========================================================
# PENTEST - TARGET INFORMATION
# =========================================================

def target_information(target):

    title("TARGET INFORMATION")

    hostname = get_hostname(target)

    print(f"[+] Target: {target}")

    try:
        ip = socket.gethostbyname(hostname)

        print(f"[+] Hostname: {hostname}")
        print(f"[+] Resolved IP: {ip}")

        return {
            "hostname": hostname,
            "ip": ip
        }

    except socket.gaierror:

        print("[-] Could not resolve target.")

        return {
            "hostname": hostname,
            "ip": None
        }


# =========================================================
# PENTEST - LIMITED SERVICE INVENTORY
# =========================================================

def service_inventory(target):

    title("SERVICE INVENTORY")

    hostname = get_hostname(target)

    ports = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        8080: "HTTP Alternate"
    }

    try:
        ip = socket.gethostbyname(hostname)

    except socket.gaierror:

        print("[-] Could not resolve target.")
        return []

    print(f"[*] Checking limited predefined services on {ip}")
    print()

    open_services = []

    for port, service in ports.items():

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        try:
            result = sock.connect_ex((ip, port))

            if result == 0:

                print(f"[+] OPEN  {port}/tcp  {service}")

                open_services.append({
                    "port": port,
                    "service": service
                })

        finally:
            sock.close()

    if not open_services:
        print("[-] No reachable services detected in this limited check.")

    return open_services


# =========================================================
# PENTEST - HTTP REQUEST
# =========================================================

def fetch_page(url):

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "NEXUS-Security-Research/5.0"
        }
    )

    with urllib.request.urlopen(
        request,
        timeout=10
    ) as response:

        body = response.read(
            500000
        ).decode(
            "utf-8",
            errors="replace"
        )

        return {
            "url": response.geturl(),
            "status": response.status,
            "headers": dict(response.headers.items()),
            "body": body
        }


# =========================================================
# PENTEST - WEB APPLICATION MAPPING
# =========================================================

def web_application_mapping(target):

    title("WEB APPLICATION MAP")

    url = get_url(target)

    try:

        page = fetch_page(url)

        print(f"[+] Final URL: {page['url']}")
        print(f"[+] HTTP Status: {page['status']}")

        body = page["body"]

        links = []

        position = 0

        while True:

            position = body.find("href=", position)

            if position == -1:
                break

            quote_position = position + 5

            if quote_position >= len(body):
                break

            quote = body[quote_position]

            if quote not in ("'", '"'):
                position += 5
                continue

            end = body.find(
                quote,
                quote_position + 1
            )

            if end == -1:
                break

            link = body[
                quote_position + 1:end
            ]

            position = end + 1

            if link.startswith("#"):
                continue

            full_url = urljoin(
                page["url"],
                link
            )

            if full_url not in links:
                links.append(full_url)

            if len(links) >= 25:
                break

        print(f"\n[+] Discovered {len(links)} link(s):\n")

        for link in links:
            print(f"    {link}")

        return {
            "url": page["url"],
            "status": page["status"],
            "links": links
        }

    except Exception as error:

        print(f"[-] Web mapping failed: {error}")

        return None


# =========================================================
# PENTEST - SECURITY HEADERS
# =========================================================

def security_headers(target):

    title("SECURITY HEADER REVIEW")

    url = get_url(target)

    expected = {
        "Content-Security-Policy":
            "Controls allowed content sources",

        "Strict-Transport-Security":
            "Encourages HTTPS-only connections",

        "X-Content-Type-Options":
            "Reduces MIME type sniffing",

        "X-Frame-Options":
            "Helps control framing",

        "Referrer-Policy":
            "Controls referrer information",

        "Permissions-Policy":
            "Controls browser feature access"
    }

    try:

        page = fetch_page(url)

        headers = page["headers"]

        print(f"[+] URL: {page['url']}")
        print(f"[+] Status: {page['status']}\n")

        results = []

        for header, explanation in expected.items():

            present = any(
                key.lower() == header.lower()
                for key in headers
            )

            if present:

                print(f"[+] PRESENT  {header}")

            else:

                print(f"[-] MISSING  {header}")

                add_finding(
                    f"Missing {header}",
                    page["url"],
                    f"Response did not include {header}. "
                    f"Context: {explanation}",
                    "Observation"
                )

            results.append({
                "header": header,
                "present": present
            })

        return results

    except Exception as error:

        print(f"[-] Header review failed: {error}")

        return []


# =========================================================
# PENTEST - TLS REVIEW
# =========================================================

def tls_review(target):

    title("TLS REVIEW")

    hostname = get_hostname(target)

    context = ssl.create_default_context()

    try:

        with socket.create_connection(
            (hostname, 443),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_socket:

                certificate = secure_socket.getpeercert()

                print(
                    f"[+] TLS version: "
                    f"{secure_socket.version()}"
                )

                print(
                    f"[+] Cipher: "
                    f"{secure_socket.cipher()[0]}"
                )

                print(
                    f"[+] Subject: "
                    f"{certificate.get('subject')}"
                )

                print(
                    f"[+] Issuer: "
                    f"{certificate.get('issuer')}"
                )

                print(
                    f"[+] Valid from: "
                    f"{certificate.get('notBefore')}"
                )

                print(
                    f"[+] Valid until: "
                    f"{certificate.get('notAfter')}"
                )

                return certificate

    except Exception as error:

        print(f"[-] TLS review failed: {error}")

        return None


# =========================================================
# PENTEST - AI OVERVIEW
# =========================================================

def pentest_ai_overview(target, services):

    title("NEXUS AI OVERVIEW")

    print(
        "NEXUS analyzed the available assessment results "
        "and generated the following summary:\n"
    )

    if services:

        service_names = ", ".join(
            service["service"]
            for service in services
        )

        print(
            f"[+] Reachable services observed: "
            f"{service_names}."
        )

    else:

        print(
            "[*] No services were detected by the limited "
            "service inventory."
        )

    if findings:

        print(
            f"[+] {len(findings)} security observation(s) "
            "were recorded."
        )

        print(
            "[*] These observations are not automatically "
            "confirmed vulnerabilities."
        )

        print(
            "[*] Manual verification and program-specific "
            "impact analysis are required."
        )

    else:

        print(
            "[+] No security observations were recorded "
            "by the implemented checks."
        )

    print()
    print(
        "Assessment coverage currently includes target "
        "resolution, limited service discovery, web mapping, "
        "HTTP response/header review, and TLS inspection."
    )


# =========================================================
# PENTEST - FULL REPORT
# =========================================================

def generate_pentest_report(
    target,
    target_info,
    services,
    web_map
):

    ensure_report_dir()

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        f"{safe_filename(target)}"
        f"_pentest_{timestamp}.md"
    )

    path = os.path.join(
        REPORT_DIR,
        filename
    )

    lines = []

    lines.append("# NEXUS Security Assessment Report")
    lines.append("")

    lines.append(
        f"**Generated:** "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    lines.append(f"**Target:** `{target}`")
    lines.append("")

    lines.append("## AI Overview")
    lines.append("")

    lines.append(
        "NEXUS performed a conservative automated assessment "
        "using the enabled modules. Results below should be "
        "reviewed manually before being considered vulnerabilities."
    )

    lines.append("")

    lines.append("## Target Information")
    lines.append("")

    lines.append(
        f"- Hostname: `{target_info.get('hostname')}`"
    )

    lines.append(
        f"- Resolved IP: `{target_info.get('ip')}`"
    )

    lines.append("")

    lines.append("## Reachable Services")
    lines.append("")

    if services:

        for service in services:

            lines.append(
                f"- `{service['port']}/tcp` — "
                f"{service['service']}"
            )

    else:

        lines.append(
            "- No services detected by the limited inventory."
        )

    lines.append("")

    lines.append("## Web Application Map")
    lines.append("")

    if web_map:

        lines.append(
            f"- Final URL: `{web_map['url']}`"
        )

        lines.append(
            f"- HTTP status: `{web_map['status']}`"
        )

        lines.append("")

        for link in web_map["links"]:

            lines.append(f"- `{link}`")

    else:

        lines.append(
            "- Web mapping was unavailable or unsuccessful."
        )

    lines.append("")

    lines.append("## Security Observations")
    lines.append("")

    if findings:

        for index, finding in enumerate(
            findings,
            start=1
        ):

            lines.append(
                f"### {index}. {finding['title']}"
            )

            lines.append("")
            lines.append(
                f"**Status:** {finding['status']}"
            )

            lines.append(
                f"**Location:** `{finding['location']}`"
            )

            lines.append(
                f"**Evidence:** {finding['evidence']}"
            )

            lines.append("")

    else:

        lines.append(
            "No observations were recorded by the enabled checks."
        )

        lines.append("")

    lines.append("## Methodology")
    lines.append("")

    lines.append(
        "The assessment used conservative automated checks "
        "for target resolution, a limited predefined service "
        "inventory, web application mapping, HTTP security "
        "header review, and TLS certificate inspection."
    )

    lines.append("")

    lines.append("## Important Note")
    lines.append("")

    lines.append(
        "An observation produced by automated tooling is not "
        "automatically a confirmed vulnerability. Findings require "
        "manual verification, impact analysis, and confirmation "
        "against the applicable testing rules."
    )

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as report:

        report.write("\n".join(lines))

    print()
    print(f"[+] Report saved: {path}")

    return path


# =========================================================
# CTF - FILE IDENTIFICATION
# =========================================================

def identify_file(path):

    try:

        result = subprocess.run(
            ["file", "-b", path],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:

            return result.stdout.strip()

        return "Unknown"

    except Exception as error:

        return f"Could not identify: {error}"


def preview_text(path):

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:

            content = file.read(1000)

        return content

    except Exception:

        return None


def ctf_analyze_file(path):

    global ctf_steps

    ctf_steps = []

    title("CTF FILE ANALYSIS")

    filename = os.path.basename(path)
    size = os.path.getsize(path)
    extension = os.path.splitext(filename)[1]

    file_type = identify_file(path)

    print(f"[+] Name: {filename}")
    print(f"[+] Size: {size} bytes")
    print(f"[+] Extension: {extension or 'None'}")
    print(f"[+] Detected type: {file_type}")

    ctf_steps.append(
        "Verified that the supplied challenge file exists."
    )

    ctf_steps.append(
        f"Detected file type: {file_type}"
    )

    if "Zip archive" in file_type or \
       "archive" in file_type.lower():

        print()
        print(
            "[*] Archive detected. A useful next step is to "
            "inspect its contents without blindly executing files."
        )

        ctf_steps.append(
            "Archive detected; inspect contained files and metadata."
        )

    elif "image" in file_type.lower():

        print()
        print(
            "[*] Image detected. Potential analysis areas include "
            "metadata, embedded data, and file structure."
        )

        ctf_steps.append(
            "Image detected; inspect metadata and embedded data."
        )

    elif "text" in file_type.lower():

        preview = preview_text(path)

        if preview:

            print("\n──────── TEXT PREVIEW ────────")
            print(preview[:1000])

            ctf_steps.append(
                "Read a limited preview of the text content."
            )

    else:

        print()
        print(
            "[*] NEXUS identified the file and recorded "
            "candidate analysis directions."
        )

        ctf_steps.append(
            "Recorded the detected format for category-specific analysis."
        )


# =========================================================
# CTF - FOLDER ANALYSIS
# =========================================================

def ctf_analyze_folder(path):

    global ctf_steps

    ctf_steps = []

    title("CTF FOLDER ANALYSIS")

    try:

        items = os.listdir(path)

        print(f"[+] Path: {os.path.abspath(path)}")
        print(f"[+] Items: {len(items)}\n")

        ctf_steps.append(
            "Enumerated the supplied challenge folder."
        )

        for item in items:

            item_path = os.path.join(
                path,
                item
            )

            if os.path.isdir(item_path):

                print(f"[DIR]  {item}")

            else:

                size = os.path.getsize(
                    item_path
                )

                file_type = identify_file(
                    item_path
                )

                print(
                    f"[FILE] {item}"
                )

                print(
                    f"       {size} bytes | "
                    f"{file_type}"
                )

        ctf_steps.append(
            "Identified the available files and their detected formats."
        )

    except Exception as error:

        print(f"[-] Folder analysis failed: {error}")


# =========================================================
# CTF - OVERVIEW
# =========================================================

def ctf_overview():

    title("NEXUS AI OVERVIEW")

    if not ctf_steps:

        print(
            "No CTF analysis steps have been recorded yet."
        )

        return

    print(
        "NEXUS has organized the completed analysis into "
        "the following investigation path:\n"
    )

    for index, step in enumerate(
        ctf_steps,
        start=1
    ):

        print(f"{index}. {step}")


# =========================================================
# CTF - REPORT
# =========================================================

def generate_ctf_report(source):

    ensure_report_dir()

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        f"{safe_filename(os.path.basename(source))}"
        f"_ctf_{timestamp}.md"
    )

    path = os.path.join(
        REPORT_DIR,
        filename
    )

    lines = [
        "# NEXUS CTF Analysis Report",
        "",
        f"**Source:** `{source}`",
        (
            f"**Generated:** "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        ),
        "",
        "## AI Overview",
        "",
        (
            "NEXUS performed an initial structured analysis "
            "and recorded the following steps."
        ),
        "",
        "## Analysis Steps",
        ""
    ]

    if ctf_steps:

        for index, step in enumerate(
            ctf_steps,
            start=1
        ):

            lines.append(
                f"{index}. {step}"
            )

    else:

        lines.append(
            "No analysis steps were recorded."
        )

    lines.extend([
        "",
        "## Suggested Next Stage",
        "",
        (
            "Use the detected challenge format and collected "
            "evidence to choose category-specific analysis. "
            "Do not execute unknown challenge files directly."
        )
    ])

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as report:

        report.write(
            "\n".join(lines)
        )

    print()
    print(f"[+] CTF report saved: {path}")


# =========================================================
# CTF MENU
# =========================================================

def ctf_mode():

    while True:

        clear_screen()

        print(r"""
╔════════════════════════════════════════════════════════╗
║                     NEXUS • CTF                        ║
╠════════════════════════════════════════════════════════╣
║                                                        ║
║   [1]  ANALYZE FILE                                    ║
║   [2]  ANALYZE FOLDER                                  ║
║   [3]  VIEW AI OVERVIEW                                ║
║   [4]  GENERATE REPORT                                 ║
║                                                        ║
║   [B]  BACK                                            ║
╚════════════════════════════════════════════════════════╝
""")

        choice = input(
            "Select option: "
        ).strip().lower()

        if choice == "1":

            path = input(
                "\nChallenge file: "
            ).strip()

            if os.path.isfile(path):

                ctf_analyze_file(path)

                pause()

            else:

                print("\n[-] File not found.")
                pause()

        elif choice == "2":

            path = input(
                "\nChallenge folder: "
            ).strip()

            if os.path.isdir(path):

                ctf_analyze_folder(path)

                pause()

            else:

                print("\n[-] Folder not found.")
                pause()

        elif choice == "3":

            ctf_overview()
            pause()

        elif choice == "4":

            source = input(
                "\nOriginal challenge file/folder: "
            ).strip()

            generate_ctf_report(source)
            pause()

        elif choice == "b":

            break

        else:

            print("\n[-] Invalid option.")
            pause()


# =========================================================
# PENTEST MENU
# =========================================================

def pentest_options(target):

    global findings

    findings = []

    if not confirm_authorization(target):

        print("\n[-] Authorization not confirmed.")
        pause()
        return

    target_info = None
    services = []
    web_map = None

    while True:

        clear_screen()

        print(r"""
╔════════════════════════════════════════════════════════╗
║                   NEXUS • PENTEST                      ║
╠════════════════════════════════════════════════════════╣
║                                                        ║
║   [1]  TARGET INFORMATION                              ║
║   [2]  SERVICE INVENTORY                               ║
║   [3]  WEB APPLICATION MAP                             ║
║   [4]  SECURITY HEADER REVIEW                          ║
║   [5]  TLS REVIEW                                      ║
║   [6]  AI OVERVIEW                                     ║
║   [7]  FULL ASSESSMENT                                 ║
║   [8]  GENERATE REPORT                                 ║
║                                                        ║
║   [B]  BACK                                            ║
╚════════════════════════════════════════════════════════╝
""")

        choice = input(
            "Select option: "
        ).strip().lower()

        if choice == "1":

            target_info = target_information(target)
            pause()

        elif choice == "2":

            services = service_inventory(target)
            pause()

        elif choice == "3":

            web_map = web_application_mapping(target)
            pause()

        elif choice == "4":

            security_headers(target)
            pause()

        elif choice == "5":

            tls_review(target)
            pause()

        elif choice == "6":

            pentest_ai_overview(
                target,
                services
            )

            pause()

        elif choice == "7":

            title("FULL ASSESSMENT")

            target_info = target_information(target)

            services = service_inventory(target)

            web_map = web_application_mapping(target)

            security_headers(target)

            tls_review(target)

            pentest_ai_overview(
                target,
                services
            )

            print("\n[+] Full assessment completed.")

            pause()

        elif choice == "8":

            if target_info is None:

                target_info = target_information(
                    target
                )

            generate_pentest_report(
                target,
                target_info,
                services,
                web_map
            )

            pause()

        elif choice == "b":

            break

        else:

            print("\n[-] Invalid option.")
            pause()


def pentest_mode():

    while True:

        clear_screen()

        print(r"""
╔════════════════════════════════════════════════════════╗
║                   NEXUS • PENTEST                      ║
╠════════════════════════════════════════════════════════╣
║                                                        ║
║   [1]  WEBSITE / DOMAIN                                ║
║   [2]  IP ADDRESS                                      ║
║                                                        ║
║   [B]  BACK                                            ║
╚════════════════════════════════════════════════════════╝
""")

        choice = input(
            "Select option: "
        ).strip().lower()

        if choice in ("1", "2"):

            target = input(
                "\nEnter authorized target: "
            ).strip()

            if target:

                pentest_options(target)

        elif choice == "b":

            break

        else:

            print("\n[-] Invalid option.")
            pause()


# =========================================================
# MAIN
# =========================================================

def main():

    while True:

        banner()

        choice = input(
            "Select mode [1/2/Q]: "
        ).strip().lower()

        if choice == "1":

            pentest_mode()

        elif choice == "2":

            ctf_mode()

        elif choice == "q":

            print("\n[+] NEXUS shutting down.")
            break

        else:

            print("\n[-] Invalid option.")
            pause()


if __name__ == "__main__":
    main()
