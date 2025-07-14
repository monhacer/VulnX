# VulnX 🛡️

VulnX is a lightweight vulnerability scanner designed for debian-based systems, focusing on web security testing.  
This repository includes **two versions** to fit different user needs:

---

## ⚡ Version 1: Basic VulnX

- Single-file script  
- Tests common vulnerabilities: XSS, SQL Injection, Command Injection, CSRF, Open Redirect, Security Headers, Clickjacking, Directory Listing  
- Simple user input: target URL only  
- Easy and fast to run, perfect for beginners or quick checks  

---

## 🚀 Version 2: Advanced VulnX (GET/POST support)

- Extended functionality  
- Supports testing with **GET** and **POST** requests  
- Allows custom parameter name input for more accurate testing  
- Same vulnerability checks as Basic plus flexible request methods  
- Interactive menu with multiple test options  
- Auto-installs dependencies if needed  
- Ideal for deeper, more precise vulnerability analysis  

---
## 🖥️ Supported Operating Systems

VulnX is compatible with Debian-based Linux distributions, including:

- **Ubuntu**  
- **Kali Linux**  
- **Debian**  
- **Linux Mint**  

It should also work on any Linux system with Python 3 and the `requests` library installed.
---
## 🔧 How to Use

1. Choose the version that suits your needs.  
2. Run the script using Python 3:  
# For Basic version  
```
curl -O https://raw.githubusercontent.com/monhacer/VulnX/refs/heads/main/vulnX.py
python3 vulnX.py    
```
# For Advanced version  
```
curl -O https://raw.githubusercontent.com/monhacer/VulnX/refs/heads/main/vulnXpro.py
python3 vulnXpro.py 
```
---
Follow the interactive prompts.

3.📌 Notes

Make sure you have Python 3 installed on your Ubuntu system.

The advanced version requires the requests library, which will be installed automatically if missing.

Always have permission before scanning any website or server.

📂 Project Structure

| File / Folder         | Description                                 |
|-----------------------|---------------------------------------------|
| `vulnX_basic.py`      | Basic single-file scanner                   |
| `vulnX_advanced.py`   | Advanced scanner with GET/POST support      |
| `README.md`           | Project documentation                       |
| `requirements.txt`    | Dependencies (`requests` library)           |



---

## 🔗 GitHub

Visit the [VulnX GitHub repository](https://github.com/monhacer/VulnX) for source code and updates.

---

Made with ❤️ by aioexp  
