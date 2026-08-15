#!/usr/bin/env python3

def banner():
    print(r"""
╔══════════════════════════════════════╗
║                 NEXUS                ║
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
    print("[!] Only test targets you are authorized to test.")
    
    target = input("\nEnter in-scope target: ").strip()
    
    print(f"\n[*] Preparing authorized assessment for: {target}")
    # Pentest agent goes here


def ctf_mode():
    print("\n[+] CTF Mode selected")
    
    challenge = input("\nEnter challenge file/folder: ").strip()
    
    print(f"\n[*] Loading CTF challenge: {challenge}")
    # CTF agent goes here


def main():
    banner()

    choice = input("Select mode [1/2]: ").strip()

    if choice == "1":
        pentest_mode()
    elif choice == "2":
        ctf_mode()
    else:
        print("\n[-] Invalid option.")
        main()


if __name__ == "__main__":
    main()
