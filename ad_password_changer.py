#!/usr/bin/env python3
"""
AD Admin Toolkit (Linux GUI) - Bezpieczna Wersja Finalna
Moduły: Zmiana Hasła AD (LDAP3), Diagnostyka Kerberos/SSSD
Architektura: Extreme Security (Blue Team), OOP, i18n
Wymagania: pip3 install ldap3
Autor: hatterp && AI support (2026)
"""

import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
import subprocess
import socket
import re
import os
import sys
import ctypes
import gc

# -------------------------------------------------------------------------
# IMPORT I WALIDACJA ZALEŻNOŚCI
# -------------------------------------------------------------------------
try:
    from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
except ImportError:
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror("Krytyczny błąd środowiska",
                         "Brak zainstalowanej biblioteki 'ldap3'.\n\n"
                         "Zainstaluj ją poleceniem:\n"
                         "pip3 install ldap3")
    sys.exit(1)


# -------------------------------------------------------------------------
# BEZPIECZNE CZYSZCZENIE PAMIĘCI
# -------------------------------------------------------------------------
def secure_scrub_memory(var: str) -> None:
    """Fizyczne zerowanie pamięci stringa (ochrona przed RAM dump)."""
    if isinstance(var, str) and len(var) > 0:
        try:
            length = len(var)
            offset = sys.getsizeof(var) - length - 1
            ctypes.memset(id(var) + offset, 0, length)
        except Exception:
            pass


# -------------------------------------------------------------------------
# POMOCNICZE
# -------------------------------------------------------------------------
def get_domain() -> str:
    """Autowykrywanie domeny."""
    try:
        res = subprocess.run(['realm', 'list'], capture_output=True, text=True, timeout=5)
        for line in res.stdout.splitlines():
            if 'domain-name:' in line.lower():
                return line.split(':', 1)[1].strip()
        res = subprocess.run(['dnsdomainname'], capture_output=True, text=True, timeout=3)
        return res.stdout.strip()
    except Exception:
        return ""


# -------------------------------------------------------------------------
# TŁUMACZENIA
# -------------------------------------------------------------------------
TRANSLATIONS = {
    "Polski": {
        "tab_pass": "Zmiana hasła",
        "tab_diag": "Diagnostyka AD",
        "btn_test": "Test LDAP",
        "old_pwd": "Obecne hasło:",
        "new_pwd": "Nowe hasło:",
        "confirm_pwd": "Potwierdź hasło:",
        "btn_submit": "Zmień hasło (LDAP)",
        "msg_fill_all": "Wypełnij wszystkie pola formularza!",
        "msg_mismatch": "Nowe hasła nie są identyczne!",
        "msg_success": "Hasło zostało pomyślnie zmienione w Active Directory!",
        "diag_target": "Cel diagnostyki (user@domena):",
        "diag_pwd": "Hasło (do testu kinit):",
        "btn_time_status": "Status Czasu (timedatectl)",
        "btn_time_restart": "Restart Timesyncd",
        "btn_sss_cache": "Czyszczenie sss_cache (-E)",
        "btn_sss_restart": "Restart SSSD",
        "btn_klist": "Sprawdź bilety (klist)",
        "btn_kinit": "Pobierz bilet (kinit)",
        "btn_id": "Sprawdź uprawnienia (id)",
        "btn_logs": "Logi SSSD (journalctl)",
        "err_root": "Ta operacja systemowa wymaga uprawnień administratora (sudo)!"
    },
    "English": {
        "tab_pass": "Change Password",
        "tab_diag": "AD Diagnostics",
        "btn_test": "Test LDAP",
        "old_pwd": "Current password:",
        "new_pwd": "New password:",
        "confirm_pwd": "Confirm password:",
        "btn_submit": "Change Password (LDAP)",
        "msg_fill_all": "Please fill all fields!",
        "msg_mismatch": "New passwords do not match!",
        "msg_success": "Password changed successfully in Active Directory!",
        "diag_target": "Target (user@domain):",
        "diag_pwd": "Password (for kinit test):",
        "btn_time_status": "Time Status (timedatectl)",
        "btn_time_restart": "Restart Timesyncd",
        "btn_sss_cache": "Clear sss_cache (-E)",
        "btn_sss_restart": "Restart SSSD",
        "btn_klist": "Check tickets (klist)",
        "btn_kinit": "Get ticket (kinit)",
        "btn_id": "Check permissions (id)",
        "btn_logs": "SSSD Logs (journalctl)",
        "err_root": "This system operation requires administrator (sudo) privileges!"
    }
}


class ADAdminToolkit:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("AD Admin Toolkit - Secure Native LDAP")
        self.root.geometry("690x700")
        self.root.resizable(False, False)
        self.root.eval('tk::PlaceWindow . center')

        # Ikona (opcjonalna)
        try:
            img = tk.PhotoImage(file='/usr/share/icons/Yaru/16x16/status/dialog-password.png')
            self.root.tk.call('wm', 'iconphoto', self.root._w, img)
        except:
            pass

        self.current_lang = tk.StringVar(value="Polski")
        self.is_root = os.geteuid() == 0

        self._build_top_bar()
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=(5, 10))

        self.tab_pass = ttk.Frame(self.notebook)
        self.tab_diag = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_pass, text="Zmiana hasła")
        self.notebook.add(self.tab_diag, text="Diagnostyka AD")

        self.create_pass_tab()
        self.create_diag_tab()
        self.update_texts()

    def _(self, key):
        return TRANSLATIONS[self.current_lang.get()][key]

    def _build_top_bar(self):
        top_bar = tk.Frame(self.root)
        top_bar.pack(fill=tk.X, padx=10, pady=5)

        priv_text = "ROOT MODE" if self.is_root else "USER MODE"
        priv_color = "#008000" if self.is_root else "#d90000"
        self.lbl_priv = tk.Label(top_bar, text=priv_text, fg=priv_color, font=("Arial", 10, "bold"))
        self.lbl_priv.pack(side=tk.LEFT)

        tk.OptionMenu(top_bar, self.current_lang, "Polski", "English", 
                      command=self.update_texts).pack(side=tk.RIGHT)

    # =========================================================================
    # ZMIANA HASŁA - LDAP
    # =========================================================================
    def create_pass_tab(self):
        frame = tk.Frame(self.tab_pass, padx=25, pady=25)
        frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(frame, text="Login (sAMAccountName):", font=("Arial", 10)).grid(row=0, column=0, sticky=tk.W, pady=6)
        self.entry_login = tk.Entry(frame, width=32, font=("Arial", 10))
        self.entry_login.grid(row=0, column=1, sticky=tk.W, pady=6)

        tk.Label(frame, text="Domena:", font=("Arial", 10)).grid(row=1, column=0, sticky=tk.W, pady=6)
        self.entry_domain = tk.Entry(frame, width=32, font=("Arial", 10))
        self.entry_domain.grid(row=1, column=1, sticky=tk.W, pady=6)
        self.entry_domain.insert(0, get_domain())

        self.btn_test = tk.Button(frame, command=self.test_ldap_bind)
        self.btn_test.grid(row=1, column=2, padx=8)

        ttk.Separator(frame, orient='horizontal').grid(row=2, column=0, columnspan=3, sticky=tk.EW, pady=15)

        self.lbl_old = tk.Label(frame, font=("Arial", 10))
        self.lbl_old.grid(row=3, column=0, sticky=tk.W, pady=6)
        self.entry_old = tk.Entry(frame, width=32, show="*", font=("Arial", 10))
        self.entry_old.grid(row=3, column=1, columnspan=2, sticky=tk.W, pady=6)

        self.lbl_new = tk.Label(frame, font=("Arial", 10))
        self.lbl_new.grid(row=4, column=0, sticky=tk.W, pady=6)
        self.entry_new = tk.Entry(frame, width=32, show="*", font=("Arial", 10))
        self.entry_new.grid(row=4, column=1, columnspan=2, sticky=tk.W, pady=6)

        self.lbl_confirm = tk.Label(frame, font=("Arial", 10))
        self.lbl_confirm.grid(row=5, column=0, sticky=tk.W, pady=6)
        self.entry_confirm = tk.Entry(frame, width=32, show="*", font=("Arial", 10))
        self.entry_confirm.grid(row=5, column=1, columnspan=2, sticky=tk.W, pady=6)

        self.btn_submit = tk.Button(frame, bg="#0078D7", fg="white", font=("Arial", 11, "bold"),
                                    command=self.change_password_ldap)
        self.btn_submit.grid(row=6, column=0, columnspan=3, pady=30, sticky=tk.EW, ipady=8)

    def test_ldap_bind(self):
        domain = self.entry_domain.get().strip()
        if not domain:
            messagebox.showwarning("Błąd", "Wprowadź domenę")
            return

        self.root.config(cursor="watch")
        self.root.update()
        try:
            server = Server(domain, get_info=ALL, connect_timeout=4)
            conn = Connection(server, auto_bind=True)
            conn.unbind()
            messagebox.showinfo("Sukces", f"Serwer LDAP dostępny:\n{domain}")
        except Exception as e:
            messagebox.showerror("Błąd", f"Nie można połączyć z LDAP:\n{str(e)}")
        finally:
            self.root.config(cursor="")

    def format_ad_password(self, password: str) -> bytes:
        return ('"' + password + '"').encode('utf-16-le')

    def change_password_ldap(self):
        user = self.entry_login.get().strip()
        domain = self.entry_domain.get().strip()
        old_pwd = self.entry_old.get()
        new_pwd = self.entry_new.get()
        confirm_pwd = self.entry_confirm.get()

        if not all([user, domain, old_pwd, new_pwd, confirm_pwd]):
            messagebox.showwarning("Błąd", self._("msg_fill_all"))
            return
        if new_pwd != confirm_pwd:
            messagebox.showerror("Błąd", self._("msg_mismatch"))
            return

        # Czyszczenie GUI
        self.entry_old.delete(0, tk.END)
        self.entry_new.delete(0, tk.END)
        self.entry_confirm.delete(0, tk.END)
        self.root.config(cursor="watch")
        self.root.update()

        try:
            upn = f"{user}@{domain}"
            server = Server(domain, get_info=ALL, connect_timeout=6)
            conn = Connection(server, user=upn, password=old_pwd, auto_bind=True)

            conn.search(server.info.other['defaultNamingContext'][0],
                        f'(sAMAccountName={user})', attributes=['distinguishedName'])

            if not conn.entries:
                messagebox.showerror("Błąd", "Nie znaleziono konta użytkownika.")
                return

            user_dn = str(conn.entries[0].distinguishedName)
            new_pwd_enc = self.format_ad_password(new_pwd)

            success = conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [new_pwd_enc])]})

            if success:
                messagebox.showinfo("Sukces", self._("msg_success"))
            else:
                desc = conn.result.get('description', 'Brak szczegółów')
                messagebox.showerror("Odmowa", f"AD odrzuciło zmianę hasła.\n\n{desc}")

            conn.unbind()
        except Exception as e:
            messagebox.showerror("Błąd LDAP", f"{str(e)}")
        finally:
            self.root.config(cursor="")
            for pwd in (old_pwd, new_pwd, confirm_pwd):
                secure_scrub_memory(pwd)
            gc.collect()

    # =========================================================================
    # DIAGNOSTYKA
    # =========================================================================
    def create_diag_tab(self):
        frame = tk.Frame(self.tab_diag, padx=15, pady=15)
        frame.pack(fill=tk.BOTH, expand=True)

        input_frame = tk.Frame(frame)
        input_frame.pack(fill=tk.X, pady=8)

        self.lbl_diag_target = tk.Label(input_frame, font=("Arial", 10))
        self.lbl_diag_target.grid(row=0, column=0, sticky=tk.W, pady=2)
        self.entry_diag_target = tk.Entry(input_frame, width=38)
        self.entry_diag_target.grid(row=0, column=1, padx=10, pady=2)

        self.lbl_diag_pwd = tk.Label(input_frame, font=("Arial", 10))
        self.lbl_diag_pwd.grid(row=1, column=0, sticky=tk.W, pady=4)
        self.entry_diag_pwd = tk.Entry(input_frame, width=38, show="*")
        self.entry_diag_pwd.grid(row=1, column=1, padx=10, pady=4)

        btn_frame = tk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=12)
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)

        commands = [
            ("btn_time_status", ["timedatectl", "status"], False),
            ("btn_time_restart", ["systemctl", "restart", "systemd-timesyncd"], True),
            ("btn_sss_cache", ["sss_cache", "-E"], True),
            ("btn_sss_restart", ["systemctl", "restart", "sssd"], True),
            ("btn_klist", ["klist"], False),
            ("btn_id", self.run_id, False),
            ("btn_kinit", self.test_kinit, False),
            ("btn_logs", ["journalctl", "-u", "sssd", "-e", "--no-pager", "-n", "30"], True),
        ]

        self.buttons = {}
        for i, (text_key, action, needs_root) in enumerate(commands):
            if isinstance(action, list):
                cmd_func = lambda c=action, r=needs_root: self.run_cli(c, r)
            else:
                cmd_func = action

            btn = tk.Button(btn_frame, command=cmd_func)
            btn.grid(row=i//2, column=i%2, sticky=tk.EW, padx=4, pady=3)
            self.buttons[text_key] = btn

        tk.Label(frame, text="Konsola wyników:", font=("Arial", 9, "italic")).pack(anchor=tk.W, pady=(15, 2))
        self.console = scrolledtext.ScrolledText(frame, height=14, bg="#101010", fg="#4af626", font=("Consolas", 10))
        self.console.pack(fill=tk.BOTH, expand=True)

    def log_to_console(self, text: str):
        self.console.insert(tk.END, f"\n{text}\n{'─' * 70}\n")
        self.console.see(tk.END)

    def run_cli(self, cmd_list, req_root=False):
        if req_root and not self.is_root:
            messagebox.showwarning("Brak uprawnień", self._("err_root"))
            return

        self.root.config(cursor="watch")
        self.root.update()
        try:
            res = subprocess.run(cmd_list, capture_output=True, text=True, timeout=15)
            output = res.stdout if res.returncode == 0 else res.stderr + "\n" + res.stdout
            self.log_to_console(f"$ {' '.join(cmd_list)}\n\n{output.strip()}")
        except Exception as e:
            self.log_to_console(f"BŁĄD: {e}")
        finally:
            self.root.config(cursor="")

    def run_id(self):
        target = self.entry_diag_target.get().strip()
        if not target or target.startswith("-"):
            messagebox.showwarning("Błąd", "Wprowadź prawidłowego użytkownika")
            return
        self.run_cli(["id", target])

    def test_kinit(self):
        target = self.entry_diag_target.get().strip()
        pwd = self.entry_diag_pwd.get()
        if not target or not pwd:
            messagebox.showwarning("Brak danych", "Podaj użytkownika i hasło")
            return

        self.entry_diag_pwd.delete(0, tk.END)
        self.root.config(cursor="watch")
        self.root.update()

        try:
            process = subprocess.Popen(['kinit', target], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out, err = process.communicate(input=f"{pwd}\n", timeout=12)

            if process.returncode == 0:
                self.log_to_console(f"kinit {target} → SUKCES")
            else:
                self.log_to_console(f"kinit {target} → BŁĄD\n{err.strip()}")
        except Exception as e:
            self.log_to_console(f"Błąd kinit: {e}")
        finally:
            self.root.config(cursor="")
            secure_scrub_memory(pwd)
            gc.collect()

    # =========================================================================
    # i18n
    # =========================================================================
    def update_texts(self, *args):
        self.notebook.tab(self.tab_pass, text=self._("tab_pass"))
        self.notebook.tab(self.tab_diag, text=self._("tab_diag"))

        self.lbl_old.config(text=self._("old_pwd"))
        self.lbl_new.config(text=self._("new_pwd"))
        self.lbl_confirm.config(text=self._("confirm_pwd"))
        self.btn_submit.config(text=self._("btn_submit"))
        self.btn_test.config(text=self._("btn_test"))

        self.lbl_diag_target.config(text=self._("diag_target"))
        self.lbl_diag_pwd.config(text=self._("diag_pwd"))

        for key, btn in self.buttons.items():
            if key in TRANSLATIONS["Polski"]:
                btn.config(text=self._(key))


if __name__ == "__main__":
    app = ADAdminToolkit()
    app.root.mainloop()#!/usr/bin/env python3
"""
Bezpieczny skrypt zmiany hasła Active Directory (GUI)
Wersja produkcyjna - Multi-Language i18n (2026)
Twórca: Paweł Kapeluszny "hatterp" & AI support
"""

import tkinter as tk
from tkinter import messagebox
import subprocess
import socket
import re

# Centralny słownik tłumaczeń (i18n)
TRANSLATIONS = {
    "Polski": {
        "title": "Zmiana hasła Active Directory",
        "header": "Zmiana hasła w Active Directory",
        "login": "Login:",
        "domain": "Domena AD:",
        "btn_test": "Test połączenia",
        "old_pwd": "Obecne hasło:",
        "new_pwd": "Nowe hasło:",
        "confirm_pwd": "Potwierdź hasło:",
        "btn_submit": "Zmień hasło",
        "title_success": "Sukces",
        "title_error": "Błąd",
        "title_warn": "Uwaga",
        "msg_fill_all": "Wszystkie pola muszą być wypełnione!",
        "msg_mismatch": "Nowe hasła nie są identyczne!",
        "msg_success": "Hasło zostało pomyślnie zmienione w Active Directory!",
        "msg_fail_auth": "Nieprawidłowe obecne hasło lub konto zostało zablokowane.",
        "msg_fail_policy": "Nowe hasło nie spełnia restrykcyjnej polityki domeny.",
        "msg_fail_other": "Nie udało się zmienić hasła. Sprawdź dane i spróbuj ponownie.",
        "msg_no_smb": "Pakiet 'smbpasswd' nie jest zainstalowany.\n\nUruchom w terminalu: sudo apt install samba-common-bin",
        "msg_timeout": "Operacja przekroczyła czas oczekiwania (Timeout serwera).",
        "msg_domain_req": "Podaj nazwę domeny.",
        "msg_conn_ok": "Domena '{domain}' jest osiągalna (port 389).",
        "msg_conn_to": "Timeout połączenia z '{domain}'.\nSprawdź połączenie sieciowe lub VPN.",
        "msg_dns_err": "Nie można rozwiązać nazwy domeny: {domain}",
        "msg_err_crit": "Wystąpił nieoczekiwany wyjątek:\n{error}",
        "err_len": "Hasło musi mieć co najmniej 8 znaków.",
        "err_upper": "Hasło musi zawierać co najmniej jedną wielką literę.",
        "err_lower": "Hasło musi zawierać co najmniej jedną małą literę.",
        "err_digit": "Hasło musi zawierać co najmniej jedną cyfrę.",
        "err_spec": "Hasło musi zawierać co najmniej jeden znak specjalny."
    },
    "English": {
        "title": "Active Directory Password Change",
        "header": "Change Active Directory Password",
        "login": "Username:",
        "domain": "AD Domain:",
        "btn_test": "Test Connection",
        "old_pwd": "Current Password:",
        "new_pwd": "New Password:",
        "confirm_pwd": "Confirm Password:",
        "btn_submit": "Change Password",
        "title_success": "Success",
        "title_error": "Error",
        "title_warn": "Warning",
        "msg_fill_all": "All fields must be filled!",
        "msg_mismatch": "New passwords do not match!",
        "msg_success": "Password successfully changed in Active Directory!",
        "msg_fail_auth": "Incorrect current password or account is locked.",
        "msg_fail_policy": "New password does not meet strict domain policy.",
        "msg_fail_other": "Failed to change password. Check details and try again.",
        "msg_no_smb": "'smbpasswd' package is not installed.\n\nRun in terminal: sudo apt install samba-common-bin",
        "msg_timeout": "Operation timed out (Server Timeout).",
        "msg_domain_req": "Please enter a domain name.",
        "msg_conn_ok": "Domain '{domain}' is reachable (port 389).",
        "msg_conn_to": "Connection timeout for '{domain}'.\nCheck network or VPN.",
        "msg_dns_err": "Cannot resolve domain name: {domain}",
        "msg_err_crit": "An unexpected exception occurred:\n{error}",
        "err_len": "Password must be at least 8 characters long.",
        "err_upper": "Password must contain at least one uppercase letter.",
        "err_lower": "Password must contain at least one lowercase letter.",
        "err_digit": "Password must contain at least one number.",
        "err_spec": "Password must contain at least one special character."
    },
    "Deutsch": {
        "title": "Active Directory Passwort ändern",
        "header": "AD Passwort ändern",
        "login": "Benutzername:",
        "domain": "AD-Domäne:",
        "btn_test": "Verbindung testen",
        "old_pwd": "Aktuelles Passwort:",
        "new_pwd": "Neues Passwort:",
        "confirm_pwd": "Passwort bestätigen:",
        "btn_submit": "Passwort ändern",
        "title_success": "Erfolg",
        "title_error": "Fehler",
        "title_warn": "Warnung",
        "msg_fill_all": "Alle Felder müssen ausgefüllt werden!",
        "msg_mismatch": "Die neuen Passwörter stimmen nicht überein!",
        "msg_success": "Das Passwort wurde erfolgreich im Active Directory geändert!",
        "msg_fail_auth": "Falsches aktuelles Passwort oder Konto ist gesperrt.",
        "msg_fail_policy": "Das neue Passwort entspricht nicht den Domänenrichtlinien.",
        "msg_fail_other": "Passwort konnte nicht geändert werden. Bitte erneut versuchen.",
        "msg_no_smb": "Das Paket 'smbpasswd' ist nicht installiert.\n\nIm Terminal ausführen: sudo apt install samba-common-bin",
        "msg_timeout": "Zeitüberschreitung der Anforderung (Server-Timeout).",
        "msg_domain_req": "Bitte geben Sie einen Domänennamen ein.",
        "msg_conn_ok": "Domäne '{domain}' ist erreichbar (Port 389).",
        "msg_conn_to": "Zeitüberschreitung bei '{domain}'.\nNetzwerk oder VPN prüfen.",
        "msg_dns_err": "Domänenname kann nicht aufgelöst werden: {domain}",
        "msg_err_crit": "Ein unerwarteter Fehler ist aufgetreten:\n{error}",
        "err_len": "Das Passwort muss mindestens 8 Zeichen lang sein.",
        "err_upper": "Das Passwort muss mindestens einen Großbuchstaben enthalten.",
        "err_lower": "Das Passwort muss mindestens einen Kleinbuchstaben enthalten.",
        "err_digit": "Das Passwort muss mindestens eine Ziffer enthalten.",
        "err_spec": "Das Passwort muss mindestens ein Sonderzeichen enthalten."
    },
    "Español": {
        "title": "Cambiar contraseña de AD",
        "header": "Cambiar contraseña de AD",
        "login": "Usuario:",
        "domain": "Dominio AD:",
        "btn_test": "Probar conexión",
        "old_pwd": "Contraseña actual:",
        "new_pwd": "Nueva contraseña:",
        "confirm_pwd": "Confirmar contraseña:",
        "btn_submit": "Cambiar contraseña",
        "title_success": "Éxito",
        "title_error": "Error",
        "title_warn": "Advertencia",
        "msg_fill_all": "¡Todos los campos deben estar llenos!",
        "msg_mismatch": "¡Las nuevas contraseñas no coinciden!",
        "msg_success": "¡Contraseña cambiada con éxito en Active Directory!",
        "msg_fail_auth": "Contraseña actual incorrecta o cuenta bloqueada.",
        "msg_fail_policy": "La nueva contraseña no cumple con la política del dominio.",
        "msg_fail_other": "No se pudo cambiar la contraseña. Verifique e intente nuevamente.",
        "msg_no_smb": "El paquete 'smbpasswd' no está instalado.\n\nEjecute: sudo apt install samba-common-bin",
        "msg_timeout": "La operación agotó el tiempo de espera (Timeout).",
        "msg_domain_req": "Ingrese un nombre de dominio.",
        "msg_conn_ok": "El dominio '{domain}' está accesible (puerto 389).",
        "msg_conn_to": "Tiempo de espera agotado para '{domain}'.\nVerifique su red o VPN.",
        "msg_dns_err": "No se puede resolver el nombre de dominio: {domain}",
        "msg_err_crit": "Ocurrió una excepción inesperada:\n{error}",
        "err_len": "La contraseña debe tener al menos 8 caracteres.",
        "err_upper": "La contraseña debe contener al menos una letra mayúscula.",
        "err_lower": "La contraseña debe contener al menos una letra minúscula.",
        "err_digit": "La contraseña debe contener al menos un número.",
        "err_spec": "La contraseña debe contener al menos un carácter especial."
    }
}

def get_domain():
    """Automatyczne wykrywanie domeny AD w systemach Linux."""
    try:
        result = subprocess.run(['realm', 'list'], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if 'domain-name:' in line:
                return line.split(':', 1)[1].strip()

        result = subprocess.run(['dnsdomainname'], capture_output=True, text=True, timeout=3)
        domain = result.stdout.strip()
        if domain:
            return domain
    except Exception:
        pass
    return "twojadomena.local"

class PasswordChanger:
    def __init__(self):
        self.root = tk.Tk()
        # Lekko poszerzamy okno na rzecz dłuższych słów w j. hiszpańskim i niemieckim
        self.root.geometry("540x445")
        self.root.resizable(False, False)
        self.root.eval('tk::PlaceWindow . center')

        # Konfiguracja aktywnego języka
        self.current_lang = tk.StringVar(value="Polski")

        try:
            img = tk.PhotoImage(file='/usr/share/icons/Yaru/16x16/status/dialog-password.png')
            self.root.tk.call('wm', 'iconphoto', self.root._w, img)
        except Exception:
            pass

        self.create_gui()
        self.update_texts() # Inicjalizacja tekstów dla domyślnego języka

    def _(self, key):
        """Pomocnicza metoda pobierająca odpowiedni tekst z tłumaczeń."""
        return TRANSLATIONS[self.current_lang.get()][key]

    def is_strong_password(self, password: str) -> tuple[bool, str]:
        """Weryfikacja złożoności hasła korzystająca z wbudowanych tłumaczeń."""
        if len(password) < 8: return False, self._("err_len")
        if not re.search(r"[A-Z]", password): return False, self._("err_upper")
        if not re.search(r"[a-z]", password): return False, self._("err_lower")
        if not re.search(r"\d", password): return False, self._("err_digit")
        if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password): return False, self._("err_spec")
        return True, ""

    def create_gui(self):
        """Buduje zarys interfejsu graficznego bez wpisywania sztywnych tekstów."""
        frame = tk.Frame(self.root, padx=25, pady=25)
        frame.pack(fill=tk.BOTH, expand=True)

        # Kontener na nagłówek i wybór języka
        top_frame = tk.Frame(frame)
        top_frame.grid(row=0, column=0, columnspan=3, sticky=tk.EW, pady=(0, 20))
        top_frame.columnconfigure(0, weight=1)

        self.lbl_header = tk.Label(top_frame, font=("Arial", 14, "bold"))
        self.lbl_header.grid(row=0, column=0, sticky=tk.W)

        # Dropdown wyboru języka
        lang_menu = tk.OptionMenu(top_frame, self.current_lang, "Polski", "English", "Deutsch", "Español", command=self.update_texts)
        lang_menu.config(font=("Arial", 8))
        lang_menu.grid(row=0, column=1, sticky=tk.E)

        # Pola formularza
        self.lbl_login = tk.Label(frame, font=("Arial", 10))
        self.lbl_login.grid(row=1, column=0, sticky=tk.W, pady=6)
        self.entry_login = tk.Entry(frame, width=28, font=("Arial", 10))
        self.entry_login.grid(row=1, column=1, sticky=tk.W, pady=6)

        self.lbl_domain = tk.Label(frame, font=("Arial", 10))
        self.lbl_domain.grid(row=2, column=0, sticky=tk.W, pady=6)
        self.entry_domain = tk.Entry(frame, width=28, font=("Arial", 10))
        self.entry_domain.grid(row=2, column=1, sticky=tk.W, pady=6)
        self.entry_domain.insert(0, get_domain())

        self.btn_test = tk.Button(frame, font=("Arial", 9), command=self.test_connection)
        self.btn_test.grid(row=2, column=2, padx=(8, 0))

        tk.Frame(frame, height=2, bd=1, relief=tk.SUNKEN).grid(row=3, column=0, columnspan=3, sticky=tk.EW, pady=18)

        self.lbl_old = tk.Label(frame, font=("Arial", 10))
        self.lbl_old.grid(row=4, column=0, sticky=tk.W, pady=6)
        self.entry_old = tk.Entry(frame, width=28, show="*", font=("Arial", 10))
        self.entry_old.grid(row=4, column=1, columnspan=2, sticky=tk.W, pady=6)

        self.lbl_new = tk.Label(frame, font=("Arial", 10))
        self.lbl_new.grid(row=5, column=0, sticky=tk.W, pady=6)
        self.entry_new = tk.Entry(frame, width=28, show="*", font=("Arial", 10))
        self.entry_new.grid(row=5, column=1, columnspan=2, sticky=tk.W, pady=6)

        self.lbl_confirm = tk.Label(frame, font=("Arial", 10))
        self.lbl_confirm.grid(row=6, column=0, sticky=tk.W, pady=6)
        self.entry_confirm = tk.Entry(frame, width=28, show="*", font=("Arial", 10))
        self.entry_confirm.grid(row=6, column=1, columnspan=2, sticky=tk.W, pady=6)

        self.btn_submit = tk.Button(frame, bg="#0078D7", fg="white", font=("Arial", 11, "bold"), command=self.change_password, height=2)
        self.btn_submit.grid(row=7, column=0, columnspan=3, pady=30, sticky=tk.EW)

    def update_texts(self, *args):
        """Aktualizuje wszystkie etykiety interfejsu graficznego zgodnie z wybranym językiem."""
        self.root.title(self._("title"))
        self.lbl_header.config(text=self._("header"))
        self.lbl_login.config(text=self._("login"))
        self.lbl_domain.config(text=self._("domain"))
        self.btn_test.config(text=self._("btn_test"))
        self.lbl_old.config(text=self._("old_pwd"))
        self.lbl_new.config(text=self._("new_pwd"))
        self.lbl_confirm.config(text=self._("confirm_pwd"))
        self.btn_submit.config(text=self._("btn_submit"))

    def clear_password_fields(self):
        """Błyskawicznie czyści pola haseł."""
        self.entry_old.delete(0, tk.END)
        self.entry_new.delete(0, tk.END)
        self.entry_confirm.delete(0, tk.END)
        self.root.update()

    def test_connection(self):
        """Test połączenia sieciowego (LDAP) z obsługą i18n."""
        domain = self.entry_domain.get().strip()
        if not domain:
            messagebox.showwarning(self._("title_warn"), self._("msg_domain_req"))
            return

        self.root.config(cursor="watch")
        self.root.update()

        try:
            with socket.create_connection((domain, 389), timeout=3):
                messagebox.showinfo(self._("title_success"), self._("msg_conn_ok").format(domain=domain))
        except socket.timeout:
            messagebox.showwarning(self._("title_warn"), self._("msg_conn_to").format(domain=domain))
        except socket.gaierror:
            messagebox.showerror(self._("title_error"), self._("msg_dns_err").format(domain=domain))
        except Exception as e:
            messagebox.showerror(self._("title_error"), self._("msg_err_crit").format(error=str(e)))
        finally:
            self.root.config(cursor="")

    def change_password(self):
        """Główna metoda zmieniająca hasło (i18n ready)."""
        user = self.entry_login.get().strip()
        domain = self.entry_domain.get().strip()
        
        old_pwd = self.entry_old.get()
        new_pwd = self.entry_new.get()
        confirm_pwd = self.entry_confirm.get()

        try:
            if not all([user, domain, old_pwd, new_pwd, confirm_pwd]):
                messagebox.showwarning(self._("title_warn"), self._("msg_fill_all"))
                return

            if new_pwd != confirm_pwd:
                messagebox.showerror(self._("title_error"), self._("msg_mismatch"))
                self.entry_new.delete(0, tk.END)
                self.entry_confirm.delete(0, tk.END)
                return

            strong, msg = self.is_strong_password(new_pwd)
            if not strong:
                messagebox.showerror(self._("title_error"), msg)
                self.entry_new.delete(0, tk.END)
                self.entry_confirm.delete(0, tk.END)
                return

            self.clear_password_fields()

            process = subprocess.Popen(
                ['smbpasswd', '-r', domain, '-U', user],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = process.communicate(
                input=f"{old_pwd}\n{new_pwd}\n{confirm_pwd}\n",
                timeout=15
            )

            if process.returncode == 0:
                messagebox.showinfo(self._("title_success"), self._("msg_success"))
                self.root.destroy()
            else:
                error = (stderr + stdout).lower()
                if any(x in error for x in ["fail", "incorrect", "wrong", "denied"]):
                    msg = self._("msg_fail_auth")
                elif any(x in error for x in ["not permitted", "constraint", "complexity", "policy"]):
                    msg = self._("msg_fail_policy")
                else:
                    msg = self._("msg_fail_other")
                
                messagebox.showerror(self._("title_error"), msg)

        except FileNotFoundError:
            messagebox.showerror(self._("title_error"), self._("msg_no_smb"))
        except subprocess.TimeoutExpired:
            messagebox.showerror(self._("title_error"), self._("msg_timeout"))
        except Exception as e:
            messagebox.showerror(self._("title_error"), self._("msg_err_crit").format(error=str(e)))
        finally:
            try:
                del old_pwd, new_pwd, confirm_pwd
            except NameError:
                pass

if __name__ == "__main__":
    app = PasswordChanger()
    app.root.mainloop()
