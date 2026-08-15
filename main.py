#!/usr/bin/env python3

import os
import socket
import subprocess
import urllib.request
import urllib.error


# ==========================================
# NEXUS V4
# AI SECURITY AGENT
# ==========================================


def clear_screen():
    os.system("clear")


def pause():
    input("\nPress Enter to continue...")


def banner():
    clear_screen()

    print(r"""
╔══════════════════════════════════════╗
║                NEXUS                 ║
║       AI SECURITY RESEARCH AGENT     ║
╠══════════════════════════════════════╣
║                                      ║
║   [1] PENTEST                        ║
║       Authorized security testing    ║
║                                      ║
║   [2] CTF                            ║
║       Challenge analysis mode        ║
║                                      ║
║   [Q] EXIT                           ║
║                                      ║
╚══════════════════════════════════════╝
""")


# ==========================================
# AUTHORIZATION
# ==========================================


def confirm_authorization(target):

    print("\n════════ AUTHORIZATION CHECK ════════")
    print(f"Target: {target}")
    print("\nOnly continue if you have explicit permission")
    print("or the target is within an authorized CTF/bug")
    print("bounty scope.")

    answer = input(
        "\nDo you confirm you are authorized? [yes/no]: "
    ).strip().lower()

    return answer == "yes"


# ==========================================
# CTF MODE
# ==========================================


def identify_file(path):

    print("\n════════ FILE IDENTIFICATION ════════")

    try:
        result = subprocess.run(
            ["file", "-b", path],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            print(f"[+] File type: {result.stdout.strip()}")
        else:
            print("[-] Could not identify file type.")

    except FileNotFoundError:
        print("[-] The 'file' utility is not installed.")

    except subprocess.TimeoutExpired:
        print("[-] File identification timed out.")


def analyze_file(path):

    print("\n══════════ FILE ANALYSIS ══════════")

    filename = os.path.basename(path)
    size = os.path.getsize(path)

    print(f"[+] Name: {filename}")
    print(f"[+] Path: {os.path.abspath(path)}")
    print(f"[+] Size: {size} bytes")

    extension = os.path.splitext(filename)[1]

    if extension:
        print(f"[+] Extension: {extension}")
    else:
        print("[+] Extension: None detected")

    identify_file(path)


def analyze_folder(path):

    print("\n═════════ FOLDER ANALYSIS ═════════")

    try:
        items = os.listdir(path)

        print(f"[+] Path: {os.path.abspath(path)}")
        print(f"[+] Found {len(items)} item(s):\n")

        for item in items:

            item_path = os.path.join(path, item)

            if os.path.isdir(item_path):
                print(f"    [DIR]  {item}")

            else:
                size = os.path.getsize(item_path)
                print(f"    [FILE] {item} ({size} bytes)")

    except PermissionError:
        print("[-] Permission denied.")


def ctf_file():

    path = input("\nEnter challenge file path: ").strip()

    if not os.path.isfile(path):
        print("\n[-] File not found.")
        return

    analyze_file(path)


def ctf_folder():

    path = input("\nEnter challenge folder path: ").strip()

    if not os.path.isdir(path):
        print("\n[-] Folder not found.")
        return

    analyze_folder(path)


def ctf_url():

    url = input("\nEnter challenge URL: ").strip()

    if not url:
        print("\n[-] No URL entered.")
        return

    print(f"\n[+] Challenge URL: {url}")
    print("[*] URL-specific CTF analysis is planned for V5.")


def ctf_description():

    description = input(
        "\nPaste challenge description: "
    ).strip()

    if not description:
        print("\n[-] No description entered.")
        return

    print("\n════════ CHALLENGE DESCRIPTION ════════")
    print(description)


def ctf_mode():

    while True:

        print(r"""
╔══════════════════════════════════════╗
║               CTF MODE               ║
╠══════════════════════════════════════╣
║   [1] Challenge File                 ║
║   [2] Challenge Folder               ║
║   [3] Challenge URL                  ║
║   [4] Challenge Description / Text   ║
║                                      ║
║   [B] Back                           ║
╚══════════════════════════════════════╝
""")

        choice = input(
            "Select option [1-4/B]: "
        ).strip().lower()

        if choice == "1":
            ctf_file()

        elif choice == "2":
            ctf_folder()

        elif choice == "3":
            ctf_url()

        elif choice == "4":
            ctf_description()

        elif choice == "b":
            break

        else:
            print("\n[-] Invalid option.")

        pause()


# ==========================================
# PENTEST: TARGET INFORMATION
# ==========================================


def target_information(target):

    print("\n════════ TARGET INFORMATION ════════")

    try:
        ip = socket.gethostbyname(target)

        print(f"[+] Target: {target}")
        print(f"[+] Resolved IP: {ip}")

    except socket.gaierror:
        print("[-] Could not resolve target.")


# ==========================================
# PENTEST: SERVICE INVENTORY
# ==========================================


def service_inventory(target):

    print("\n════════ SERVICE INVENTORY ════════")
    print("[*] Checking a small predefined set of ports...")
    print("[*] This may take a moment.\n")

    ports = {
        80: "HTTP",
        443: "HTTPS",
        22: "SSH",
        21: "FTP",
        25: "SMTP",
        53: "DNS",
        8080: "HTTP Alternate"
    }

    try:
        ip = socket.gethostbyname(target)

    except socket.gaierror:
        print("[-] Could not resolve target.")
        return

    open_services = []

    for port, name in ports.items():

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(1)

        result = sock.connect_ex((ip, port))

        if result == 0:
            print(
                f"[+] OPEN  {port}/tcp - {name}"
            )

            open_services.append(port)

        sock.close()

    if not open_services:
        print("[-] No services found in this limited check.")


# ==========================================
# PENTEST: SECURITY HEADERS
# ==========================================


def security_headers(target):

    print("\n════════ SECURITY HEADER REVIEW ════════")

    if not target.startswith("http://") and \
       not target.startswith("https://"):

        target = "https://" + target

    expected_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    try:

        request = urllib.request.Request(
            target,
            method="HEAD",
            headers={
                "User-Agent": "NEXUS-Security-Research"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=10
        ) as response:

            headers = response.headers

            print(
                f"[+] Response status: "
                f"{response.status}\n"
            )

            for header in expected_headers:

                if header in headers:
                    print(
                        f"[+] PRESENT: {header}"
                    )

                else:
                    print(
                        f"[-] NOT FOUND: {header}"
                    )

    except urllib.error.URLError as error:
        print(f"[-] Request failed: {error}")


# ==========================================
# PENTEST OPTIONS
# ==========================================


def pentest_options(target):

    if not confirm_authorization(target):
        print("\n[-] Authorization not confirmed.")
        return

    while True:

        print(r"""
╔══════════════════════════════════════╗
║           PENTEST OPTIONS            ║
╠══════════════════════════════════════╣
║   [1] Target Information             ║
║   [2] Service Inventory              ║
║   [3] Web Application Mapping        ║
║   [4] Security Header Review         ║
║   [5] TLS Configuration Review       ║
║   [6] Potential Finding Review       ║
║   [7] Full Assessment                ║
║                                      ║
║   [B] Back                           ║
╚══════════════════════════════════════╝
""")

        choice = input(
            "Select option [1-7/B]: "
        ).strip().lower()

        if choice == "1":
            target_information(target)

        elif choice == "2":
            service_inventory(target)

        elif choice == "3":
            print(
                "\n[*] Web mapping planned for a later version."
            )

        elif choice == "4":
            security_headers(target)

        elif choice == "5":
            print(
                "\n[*] TLS review planned for a later version."
            )

        elif choice == "6":
            print(
                "\n[*] Finding review planned for a later version."
            )

        elif choice == "7":

            print("\n════════ FULL ASSESSMENT ════════")

            target_information(target)
            service_inventory(target)

            print(
                "\n[*] Running security header review..."
            )

            security_headers(target)

            print(
                "\n[+] Limited authorized assessment complete."
            )

        elif choice == "b":
            break

        else:
            print("\n[-] Invalid option.")

        pause()


def pentest_mode():

    while True:

        print(r"""
╔══════════════════════════════════════╗
║             PENTEST MODE             ║
╠══════════════════════════════════════╣
║   [1] Website / Domain               ║
║   [2] IP Address                     ║
║                                      ║
║   [B] Back                           ║
╚══════════════════════════════════════╝
""")

        choice = input(
            "Select option [1/2/B]: "
        ).strip().lower()

        if choice == "1":

            target = input(
                "\nEnter authorized website/domain: "
            ).strip()

            if target:
                pentest_options(target)

        elif choice == "2":

            target = input(
                "\nEnter authorized IP address: "
            ).strip()

            if target:
                pentest_options(target)

        elif choice == "b":
            break

        else:
            print("\n[-] Invalid option.")

        pause()


# ==========================================
# MAIN
# ==========================================


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
            print("\n[+] Exiting NEXUS.")
            break

        else:
            print("\n[-] Invalid option.")

        pause()


if __name__ == "__main__":
    main()
