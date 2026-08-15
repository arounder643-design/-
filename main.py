#!/usr/bin/env python3

import os


# ==========================================
# NEXUS V3
# AI SECURITY AGENT
# ==========================================


def clear_screen():
    os.system("clear")


def banner():
    clear_screen()

    print(r"""
╔══════════════════════════════════════╗
║                NEXUS                 ║
║          AI SECURITY AGENT   V3      ║
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
# CTF MODE
# ==========================================


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


def analyze_folder(path):

    print("\n═════════ FOLDER ANALYSIS ═════════")

    print(f"[+] Path: {os.path.abspath(path)}")

    try:

        files = os.listdir(path)

        if not files:
            print("[-] Folder is empty.")
            return

        print(f"\n[+] Found {len(files)} item(s):\n")

        for item in files:

            item_path = os.path.join(path, item)

            if os.path.isdir(item_path):
                print(f"    [DIR]  {item}")

            else:
                size = os.path.getsize(item_path)
                print(f"    [FILE] {item} ({size} bytes)")

    except PermissionError:
        print("[-] Permission denied.")


def ctf_file():

    challenge = input(
        "\nEnter challenge file path: "
    ).strip()

    if not os.path.isfile(challenge):
        print("\n[-] File not found.")
        return

    analyze_file(challenge)


def ctf_folder():

    challenge = input(
        "\nEnter challenge folder path: "
    ).strip()

    if not os.path.isdir(challenge):
        print("\n[-] Folder not found.")
        return

    analyze_folder(challenge)


def ctf_url():

    url = input(
        "\nEnter challenge URL: "
    ).strip()

    if not url:
        print("\n[-] No URL entered.")
        return

    print(f"\n[*] Challenge URL loaded: {url}")
    print("[*] URL analysis will be added in a future version.")


def ctf_description():

    description = input(
        "\nPaste challenge description: "
    ).strip()

    if not description:
        print("\n[-] No description entered.")
        return

    print("\n════════ CHALLENGE DESCRIPTION ════════")
    print(description)

    print("\n[*] AI challenge reasoning will be added later.")


def ctf_mode():

    while True:

        print(r"""
╔══════════════════════════════════════╗
║               CTF MODE               ║
╠══════════════════════════════════════╣
║                                      ║
║   [1] Challenge File                 ║
║   [2] Challenge Folder               ║
║   [3] Challenge URL                  ║
║   [4] Challenge Description / Text   ║
║                                      ║
║   [B] Back                           ║
║                                      ║
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

        input("\nPress Enter to continue...")


# ==========================================
# PENTEST MODE
# ==========================================


def pentest_options(target):

    while True:

        print(r"""
╔══════════════════════════════════════╗
║           PENTEST OPTIONS            ║
╠══════════════════════════════════════╣
║                                      ║
║   [1] Target Information             ║
║   [2] Service Inventory              ║
║   [3] Web Application Mapping        ║
║   [4] Security Header Review         ║
║   [5] TLS Configuration Review       ║
║   [6] Potential Finding Review       ║
║   [7] Full Authorized Assessment     ║
║                                      ║
║   [B] Back                           ║
║                                      ║
╚══════════════════════════════════════╝
""")

        choice = input(
            "Select option [1-7/B]: "
        ).strip().lower()

        if choice == "b":
            break

        elif choice in [
            "1", "2", "3", "4",
            "5", "6", "7"
        ]:

            options = {
                "1": "Target Information",
                "2": "Service Inventory",
                "3": "Web Application Mapping",
                "4": "Security Header Review",
                "5": "TLS Configuration Review",
                "6": "Potential Finding Review",
                "7": "Full Authorized Assessment"
            }

            print(
                f"\n[*] Selected: {options[choice]}"
            )

            print(
                f"[*] Target: {target}"
            )

            print(
                "[*] This assessment module "
                "will be implemented in a future version."
            )

        else:
            print("\n[-] Invalid option.")

        input("\nPress Enter to continue...")


def pentest_mode():

    while True:

        print(r"""
╔══════════════════════════════════════╗
║             PENTEST MODE             ║
╠══════════════════════════════════════╣
║                                      ║
║   [1] Website / Domain               ║
║   [2] IP Address                     ║
║   [3] Import Scope Configuration     ║
║                                      ║
║   [B] Back                           ║
║                                      ║
╚══════════════════════════════════════╝
""")

        choice = input(
            "Select option [1-3/B]: "
        ).strip().lower()

        if choice == "b":
            break

        elif choice == "1":

            target = input(
                "\nEnter authorized website/domain: "
            ).strip()

            if target:
                pentest_options(target)

            else:
                print("\n[-] No target entered.")

        elif choice == "2":

            target = input(
                "\nEnter authorized IP address: "
            ).strip()

            if target:
                pentest_options(target)

            else:
                print("\n[-] No IP entered.")

        elif choice == "3":

            scope_file = input(
                "\nEnter scope configuration path: "
            ).strip()

            if os.path.isfile(scope_file):

                print(
                    f"\n[+] Scope file found: "
                    f"{scope_file}"
                )

                print(
                    "[*] Scope parsing will be "
                    "added in a future version."
                )

            else:
                print("\n[-] Scope file not found.")

        else:
            print("\n[-] Invalid option.")

        input("\nPress Enter to continue...")


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

        input("\nPress Enter to return to main menu...")


if __name__ == "__main__":
    main()
