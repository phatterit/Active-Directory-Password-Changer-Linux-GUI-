#!/usr/bin/env python3
"""
Bezpieczny skrypt zmiany hasła Active Directory (GUI)
Wersja produkcyjna - Multi-Language i18n (2026)
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
