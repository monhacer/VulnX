#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import subprocess
import shutil
import requests

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
WHITE = "\033[97m"
RESET = "\033[0m"

def install_and_import(package):
    try:
        __import__(package)
    except ImportError:
        print(f"{GREEN}[i] Installing {package}...{RESET}")
        if shutil.which("pip3"):
            cmd = ["sudo", "pip3", "install", package]
        else:
            print(f"{YELLOW}[i] pip3 not found, installing python3-pip...{RESET}")
            subprocess.run(["sudo", "apt", "update"])
            subprocess.run(["sudo", "apt", "install", "-y", "python3-pip"])
            cmd = ["sudo", "pip3", "install", package]
        try:
            subprocess.check_call(cmd)
            print(f"{GREEN}[i] {package} installed successfully.{RESET}")
        except Exception as e:
            print(f"[!] Failed to install {package}: {e}")
            sys.exit(1)

def ensure_dependencies():
    install_and_import("requests")

def print_banner_and_menu():
    print(GREEN + "="*50)
    print("VulnX - Vulnerability Scanner    V1.0")
    print("GitHub: https://github.com/monhacer/VulnX")
    print("="*50 + RESET)
    print()
    print(GREEN + "Select tests to run:" + RESET)
    print(GREEN + "1) XSS" + RESET)
    print(GREEN + "2) SQL Injection" + RESET)
    print(GREEN + "3) Command Injection" + RESET)
    print(GREEN + "4) CSRF Token Check" + RESET)
    print(GREEN + "5) Open Redirect" + RESET)
    print(GREEN + "6) Security Headers" + RESET)
    print(GREEN + "7) Clickjacking" + RESET)
    print(GREEN + "8) Directory Listing" + RESET)
    print(GREEN + "9) Run all tests" + RESET)

def interactive_menu():
    print_banner_and_menu()
    choices = input(YELLOW + "Enter choices (comma separated, e.g. 1,3,5): " + RESET).strip()
    selected = set()
    for ch in choices.split(","):
        ch = ch.strip()
        if ch == "1":
            selected.add("xss")
        elif ch == "2":
            selected.add("sqli")
        elif ch == "3":
            selected.add("cmd")
        elif ch == "4":
            selected.add("csrf")
        elif ch == "5":
            selected.add("redirect")
        elif ch == "6":
            selected.add("headers")
        elif ch == "7":
            selected.add("clickjacking")
        elif ch == "8":
            selected.add("dirlist")
        elif ch == "9":
            return {"xss","sqli","cmd","csrf","redirect","headers","clickjacking","dirlist"}
    return selected

def scan_xss(url):
    print(f"{WHITE}[i] Starting XSS test...{RESET}")
    payload = "<script>alert('XSS')</script>"
    test_url = url
    if "?" not in test_url:
        test_url += "?q=" + payload
    else:
        test_url += "&q=" + payload
    try:
        r = requests.get(test_url, timeout=10)
        if payload in r.text:
            print(f"{RED}[!] Possible XSS vulnerability detected at: {test_url}{RESET}")
        else:
            print(f"{GREEN}[-] No XSS vulnerability detected.{RESET}")
    except Exception as e:
        print(f"[!] XSS test error: {e}")

def scan_sqli(url):
    print(f"{WHITE}[i] Starting SQL Injection test...{RESET}")
    payload = "' OR '1'='1"
    test_url = url
    if "?" not in test_url:
        test_url += "?id=" + payload
    else:
        test_url += "&id=" + payload
    try:
        r = requests.get(test_url, timeout=10)
        errors = ["sql syntax", "mysql", "syntax error", "sqlite", "pdoexception", "you have an error in your sql syntax"]
        if any(err.lower() in r.text.lower() for err in errors):
            print(f"{GREEN}[!] Possible SQL Injection vulnerability detected at: {test_url}{RESET}")
        else:
            print(f"{GREEN}[-] No SQL Injection vulnerability detected.{RESET}")
    except Exception as e:
        print(f"[!] SQL Injection test error: {e}")

def scan_cmd_injection(url):
    print(f"{WHITE}[i] Starting Command Injection test...{RESET}")
    payload = "| echo vulnXtest"
    test_url = url
    if "?" not in test_url:
        test_url += "?cmd=" + payload
    else:
        test_url += "&cmd=" + payload
    try:
        r = requests.get(test_url, timeout=10)
        if "vulnXtest" in r.text:
            print(f"{RED}[!] Possible Command Injection vulnerability detected at: {test_url}{RESET}")
        else:
            print(f"{GREEN}[-] No Command Injection vulnerability detected.{RESET}")
    except Exception as e:
        print(f"[!] Command Injection test error: {e}")

def scan_csrf(url):
    print(f"{WHITE}[i] Starting CSRF Token Check...{RESET}")
    try:
        r = requests.get(url, timeout=10)
        if "<input" in r.text.lower() and ("csrf" in r.text.lower() or "token" in r.text.lower()):
            print(f"{RED}[-] CSRF token found in forms.{RESET}")
        else:
            print(f"{GREEN}[!] CSRF token NOT found in forms. Potential vulnerability.{RESET}")
    except Exception as e:
        print(f"[!] CSRF test error: {e}")

def scan_open_redirect(url):
    print(f"{WHITE}[i] Starting Open Redirect test...{RESET}")
    redirect_test = "https://evil.com"
    test_url = url
    if "?" not in test_url:
        test_url += "?next=" + redirect_test
    else:
        test_url += "&next=" + redirect_test
    try:
        r = requests.get(test_url, allow_redirects=False, timeout=10)
        if "Location" in r.headers and redirect_test in r.headers["Location"]:
            print(f"{RED}[!] Possible Open Redirect vulnerability detected at: {test_url}{RESET}")
        else:
            print(f"{GREEN}[-] No Open Redirect vulnerability detected.{RESET}")
    except Exception as e:
        print(f"[!] Open Redirect test error: {e}")

def scan_security_headers(url):
    print(f"{WHITE}[i] Checking Security Headers...{RESET}")
    try:
        r = requests.get(url, timeout=10)
        headers = r.headers
        needed = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": ["DENY", "SAMEORIGIN"],
            "Content-Security-Policy": None,
            "Strict-Transport-Security": None,
            "Referrer-Policy": None
        }
        missing = []
        for h, val in needed.items():
            if h not in headers:
                missing.append(h)
            elif val and isinstance(val, list) and headers[h] not in val:
                missing.append(h)
        if missing:
            print(f"{RED}[!] Missing or weak security headers: {', '.join(missing)}{RESET}")
        else:
            print(f"{GREEN}[-] All important security headers are present.{RESET}")
    except Exception as e:
        print(f"[!] Security Headers test error: {e}")

def scan_clickjacking(url):
    print(f"{WHITE}[i] Checking Clickjacking protection...{RESET}")
    try:
        r = requests.get(url, timeout=10)
        if "X-Frame-Options" in r.headers or "Content-Security-Policy" in r.headers:
            print(f"{RED}[-] Clickjacking protection headers found.{RESET}")
        else:
            print(f"{GREEN}[!] Clickjacking protection headers NOT found.{RESET}")
    except Exception as e:
        print(f"[!] Clickjacking test error: {e}")

def scan_directory_listing(url):
    print(f"{WHITE}[i] Checking Directory Listing...{RESET}")
    if not url.endswith("/"):
        url += "/"
    try:
        r = requests.get(url, timeout=10)
        if "Index of /" in r.text or "<title>Directory listing for" in r.text.lower():
            print(f"{RED}[!] Possible Directory Listing enabled at: {url}{RESET}")
        else:
            print(f"{GREEN}[-] Directory Listing not detected.{RESET}")
    except Exception as e:
        print(f"[!] Directory Listing test error: {e}")

def main():
    ensure_dependencies()
    print(f"{GREEN}==== VulnX Vulnerability Scanner V1.0 ===={RESET}")
    url = input(f"{YELLOW}Enter target URL (e.g. http://example.com): {RESET}").strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        print("[!] Please enter a valid URL starting with http:// or https://")
        sys.exit(1)
    tests = interactive_menu()
    if not tests:
        print("[!] No tests selected. Exiting.")
        sys.exit(1)
    if "xss" in tests:
        scan_xss(url)
    if "sqli" in tests:
        scan_sqli(url)
    if "cmd" in tests:
        scan_cmd_injection(url)
    if "csrf" in tests:
        scan_csrf(url)
    if "redirect" in tests:
        scan_open_redirect(url)
    if "headers" in tests:
        scan_security_headers(url)
    if "clickjacking" in tests:
        scan_clickjacking(url)
    if "dirlist" in tests:
        scan_directory_listing(url)
    print(f"\n{GREEN}[✔] Scanning completed.{RESET}")

if __name__ == "__main__":
    main()
