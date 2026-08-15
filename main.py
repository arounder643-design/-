#!/usr/bin/env python3

import os


def banner():
    print(r"""
╔══════════════════════════════════════╗
║                NEXUS                 ║
║          AI SECURITY AGENT           ║
╠══════════════════════════════════════╣
║                                      ║
║   [1] PENTEST                        ║
║       Authorized security testing    ║
║                                      ║
║   [2] CTF                            ║
║       Challenge analysis mode        ║
║                                      ║
╚══════════════════════════════════════╝
""")


def pentest_mode():
    print("\n[+] Pentest Mode selected")
    print("[!] Only test targets you are explicitly authorized to test.")

    target = input("\nEnter in-scope target: ").strip()

    if not target:
        print("\n[-] No target entered.")
        return

    print(f"\n[*] Preparing authorized assessment for: {target}")
    print("[*] Pentest features coming in a future version.")


def analyze_file(path):
    """Display basic information about a CTF file."""

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
    """List files inside a CTF challenge folder."""

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


def ctf_mode():
    print("\n[+] CTF Mode selected")

    challenge = input(
        "\nEnter challenge file/folder path: "
    ).strip()

    if not challenge:
        print("\n[-] No challenge entered.")
        return

    if not os.path.exists(challenge):
        print(f"\n[-] Challenge not found: {challenge}")
        return

    print("\n[*] Loading CTF challenge...")

    if os.path.isfile(challenge):
        analyze_file(challenge)

    elif os.path.isdir(challenge):
        analyze_folder(challenge)

    print("\n[+] Initial analysis complete.")


def main():
    while True:
        banner()

        choice = input("Select mode [1/2/q]: ").strip().lower()

        if choice == "1":
            pentest_mode()

        elif choice == "2":
            ctf_mode()

        elif choice == "q":
            print("\n[+] Exiting NEXUS.")
            break

        else:
            print("\n[-] Invalid option.")

        input("\nPress Enter to return to the menu...")


if __name__ == "__main__":
    main()
