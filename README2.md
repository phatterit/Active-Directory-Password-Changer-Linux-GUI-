# AD Admin Toolkit (Linux GUI) 🔐

A highly secure, multi-language graphical interface (GUI) designed for Linux workstations (Ubuntu/Debian/Mint). It empowers SysAdmins and 1st-Line Helpdesk professionals to securely change Microsoft Active Directory passwords and diagnose domain connectivity issues without exposing credentials to terminal logs.

Built with Python, Tkinter, and strict **"Blue Team"** security standards.
<img width="700" height="752" alt="image" src="https://github.com/user-attachments/assets/7489bc09-3ccf-4258-b71e-bfc9d8275327" />
<img width="700" height="752" alt="image" src="https://github.com/user-attachments/assets/8e98aba9-45e2-474d-b7d3-e73286732300" />

## ✨ Key Features

* **🔌 Native LDAP Communication:** Interacts directly with Active Directory using the `ldap3` protocol instead of wrapping shell commands (like `smbpasswd`), preventing credential leakage in process trees.
* **🛡️ Smart Password Validator:** Features a real-time, dynamic visual indicator (Weak/Fair/Strong) and enforces a strict **Client-Side Hard Block**. It prevents weak passwords from ever reaching the Domain Controller, saving AD logs and eliminating unnecessary Account Lockouts.
* **🌍 Multi-Language Support (i18n):** Real-time language switching (English, Polish) without application restarts.
* **🔍 Auto-Discovery:** Intelligently detects the currently joined AD domain using `realm` (SSSD) or `dnsdomainname`.
* **🩺 Built-in Diagnostics Module:** * Test Kerberos ticket granting (`kinit` / `klist`) securely.
  * Manage SSSD (`sss_cache -E`, daemon restart, fetch live `journalctl` logs).
  * Manage Time Synchronization (`systemd-timesyncd`).

## 🔒 Extreme Security Architecture

This tool was designed to be safely deployed in strict, monitored enterprise environments (compatible with EDRs and `auditd`):
* **C-Level Memory Scrubbing (Zeroing):** Utilizes `ctypes.memset` to physically overwrite password strings in the RAM allocation block immediately after use. This bypasses standard Python Garbage Collection to protect against advanced RAM Dumping techniques.
* **Zero Command Injection:** All diagnostic subprocesses are explicitly called via secure lists (`shell=False` implicitly).
* **Process Hiding:** Passwords required for Kerberos (`kinit`) diagnostics are piped directly via `subprocess.PIPE` STDIN, ensuring they never appear in `ps aux` or `.bash_history`.

## 📦 Requirements

* Python 3.x
* `python3-tk` (for the GUI)
* `ldap3` (Python library for native AD communication)

**Installation (Ubuntu/Debian/Mint):**

    sudo apt update
    sudo apt install python3-tk python3-pip
    sudo apt install python3-ldap3
    
(If python3-ldap3 is not in your distro repos, use: pip3 install ldap3 --break-system-packages)

🚀 Installation & Usage

Clone the repository:

    git clone [https://github.com/phatterit/ad-admin-toolkit.git](https://github.com/phatterit/ad-admin-toolkit.git)
    cd ad-admin-toolkit

Make the script executable:

    chmod +x ad_admin_toolkit.py
    
Run the application:

  For standard password changes (User Mode):

    ./ad_admin_toolkit.py

For full diagnostic capabilities (Root Mode - Restarting SSSD, clearing cache):

    sudo ./ad_admin_toolkit.py

📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
