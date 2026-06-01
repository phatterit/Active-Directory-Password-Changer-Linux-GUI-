# Active Directory Password Changer (Linux GUI) 🔐

A secure, user-friendly, and multi-language graphical interface (GUI) for Linux workstations (Ubuntu/Debian) that allows users to seamlessly change their Microsoft Active Directory passwords without touching the terminal. 

Built with Python (OOP) and Tkinter, designed strictly with "Blue Team" security standards in mind.

## ✨ Features

* **🌍 Multi-Language Support (i18n):** Real-time, dynamic language switching without restarting the app. Currently supports **English, Polish, German, and Spanish**.
* **🔍 Auto-Discovery:** Automatically detects the joined AD domain via `realm` (SSSD) or `dnsdomainname`.
* **⚡ Pre-flight Connectivity Check:** Verifies Domain Controller reachability over the native LDAP port (389), bypassing strict ICMP (Ping) firewall drops.
* **🛡️ Client-Side Policy Validation:** Validates password complexity (length, uppercase, lowercase, numbers, special characters) before sending requests to the server, saving logs and AD resources.
* **🧠 Intelligent Error Handling:** Parses raw server errors (e.g., history constraints, account lockouts) into human-readable, translated messages.

## 🔒 Security Architecture

This tool was designed to be safely deployed in strict enterprise environments:
* **No `shell=True`:** Subprocesses are called via secure lists, entirely mitigating Command Injection risks.
* **Process Hiding:** Passwords are piped directly to the `smbpasswd` stdin via `subprocess.PIPE`. Passwords never appear in `ps aux` or bash history.
* **Aggressive Memory Management:** Uses `try...finally` blocks and explicit Python `del` statements to immediately scrub passwords from RAM allocation as soon as the AD transaction completes.

## 📦 Requirements

* Python 3.x
* `python3-tk` (for the GUI)
* `samba-common-bin` (provides the `smbpasswd` utility)

**Installation of dependencies (Ubuntu/Debian):**

    sudo apt update
    sudo apt install python3-tk samba-common-bin

## 🚀 Installation & Usage

  Clone the repository:
  
    git clone [https://github.com/phatterit/ad-password-changer-linux.git](https://github.com/phatterit/ad-password-changer-linux.git)
    cd ad-password-changer-linux


Make the script executable:

     chmod +x ad_password_changer.py
    

Run the application:

     ./ad_password_changer.py
    


## 📝 Desktop Shortcut (Optional)

To integrate the app into your GNOME/KDE application menu, create a .desktop file:


    sudo nano /usr/share/applications/ad-password-changer.desktop

Paste the following:

    Ini, TOML

    [Desktop Entry]
    Version=1.0
    Name=AD Password Change
    Comment=Change Active Directory Password
    Exec=/path/to/your/ad_password_changer.py
    Icon=dialog-password
    Terminal=false
    Type=Application
    Categories=Utility;Security;System;

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
