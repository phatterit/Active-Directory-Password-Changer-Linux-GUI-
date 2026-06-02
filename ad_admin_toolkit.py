#!/usr/bin/env python3
"""
AD Admin Toolkit (Linux GUI) - Wersja Korporacyjna
Moduły: Zmiana Hasła AD (LDAPS/NTLM), Diagnostyka, Banner Prawny
Architektura: Extreme Security (Blue Team), OOP, i18n
Wymagania: pip3 install ldap3
Autor: hatterp (2026)
"""

import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
import subprocess
import socket
import re
import os
import sys
import gc
import secrets

# -------------------------------------------------------------------------
# IMPORT I WALIDACJA ZALEŻNOŚCI
# -------------------------------------------------------------------------
try:
    from ldap3 import Server, Connection, ALL, MODIFY_REPLACE, NTLM
except ImportError:
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror("Krytyczny błąd środowiska",
                         "Brak zainstalowanej biblioteki 'ldap3'.\n\n"
                         "Zainstaluj ją poleceniem:\n"
                         "sudo apt install python3-ldap3")
    sys.exit(1)


# -------------------------------------------------------------------------
# BEZPIECZNE CZYSZCZENIE PAMIĘCI (Best Effort w CPython)
# -------------------------------------------------------------------------
def secure_clear_string(s: str) -> None:
    """
    Bezpieczne dla stabilności (Brak SegFault) próby czyszczenia kopii hasła.
    W czystym Pythonie ostatecznie polegamy na usunięciu referencji i gc.collect().
    """
    if not isinstance(s, str) or not s:
        return
    try:
        # Nadpisanie losowymi bajtami (operuje na kopii, ale utrudnia odzysk)
        b = bytearray(s.encode('utf-8'))
        for _ in range(3):
            for i in range(len(b)):
                b[i] = secrets.randbelow(256)
        b[:] = b'\x00' * len(b)
    except Exception:
        pass


def get_domain() -> str:
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
        "btn_test": "Test Połączenia (AD)",
        "old_pwd": "Obecne hasło:",
        "new_pwd": "Nowe hasło:",
        "confirm_pwd": "Potwierdź hasło:",
        "btn_submit": "Zmień hasło (LDAP)",
        "msg_fill_all": "Wypełnij wszystkie pola formularza!",
        "msg_mismatch": "Nowe hasła nie są identyczne!",
        "msg_weak_password": "Hasło jest zbyt słabe! Użyj silniejszego hasła zgodnego z polityką domeny.",
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
        "err_root": "Ta operacja systemowa wymaga uprawnień administratora (sudo)!",
        "pwd_weak": "Słabe",
        "pwd_fair": "Średnie",
        "pwd_strong": "Silne",
        "chk_unlock": "Odblokuj tryb edycji / zmian systemowych",
        "legal_title": "OSTRZEŻENIE SYSTEMOWE / LEGAL NOTICE",
        "legal_text": "UWAGA! To urządzenie oraz system informatyczny stanowią własność firmy. "
                      "Dostęp do zasobów jest ograniczony wyłącznie do uprawnionych pracowników w celach służbowych.\n\n"
                      "Wszelkie działania w systemie podlegają monitorowaniu, rejestracji oraz audytowi (zgodnie z normą ISO 27001 i wytycznymi NIST). "
                      "Użycie tego narzędzia bez autoryzacji lub do celów niezgodnych z obowiązkami służbowymi jest surowo zabronione "
                      " i może skutkować odpowiedzialnością dyscyplinarną oraz karną.\n\n"
                      "Klikając 'Akceptuję', oświadczasz, że posiadasz odpowiednie uprawnienia i działasz w celach autoryzowanych.",
        "btn_accept": "Akceptuję",
        "btn_decline": "Odrzucam i wychodzę"
    },
    "English": {
        "tab_pass": "Change Password",
        "tab_diag": "AD Diagnostics",
        "btn_test": "Test Connection (AD)",
        "old_pwd": "Current password:",
        "new_pwd": "New password:",
        "confirm_pwd": "Confirm password:",
        "btn_submit": "Change Password (LDAP)",
        "msg_fill_all": "Please fill all fields!",
        "msg_mismatch": "New passwords do not match!",
        "msg_weak_password": "Password is too weak! Please use a stronger password meeting domain policy.",
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
        "err_root": "This system operation requires administrator (sudo) privileges!",
        "pwd_weak": "Weak",
        "pwd_fair": "Fair",
        "pwd_strong": "Strong",
        "chk_unlock": "Unlock editing / system modifications mode",
        "legal_title": "SYSTEM WARNING / LEGAL NOTICE",
        "legal_text": "WARNING! This device and computer system are the property of the company. "
                      "Access is strictly limited to authorized personnel for official business purposes only.\n\n"
                      "All activities on this system are monitored, logged, and audited (in compliance with ISO 27001 and NIST guidelines). "
                      "Unauthorized use or use outside the scope of official duties is strictly prohibited "
                      "and may lead to disciplinary action and criminal prosecution.\n\n"
                      "By clicking 'Accept', you confirm that you possess proper authorization and are acting within your official duties.",
        "btn_accept": "Accept",
        "btn_decline": "Decline and Exit"
    }
}


class ADAdminToolkit:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("AD Admin Toolkit")
        self.root.geometry("740x760")
        self.root.resizable(False, False)
        self.root.eval('tk::PlaceWindow . center')
        
        self.root.withdraw()
        self.current_lang = tk.StringVar(value="Polski")
        self.is_root = os.geteuid() == 0
        self.var_unlock = tk.BooleanVar(value=False)

        self.show_legal_banner()

        self.root.deiconify()
        self._build_top_bar()
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=(5, 10))

        self.tab_pass = ttk.Frame(self.notebook)
        self.tab_diag = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_pass, text="Zmiana hasła")
        self.notebook.add(self.tab_diag, text="Diagnostyka AD")

        # INICJALIZACJA ZAKŁADEK (Musi nastąpić przed toggle_read_only)
        self.create_pass_tab()
        self.create_diag_tab()
        
        self.update_texts()
        self.toggle_read_only()

    def _(self, key):
        return TRANSLATIONS[self.current_lang.get()][key]

    # =========================================================================
    # MODALNY BANNER PRAWNY
    # =========================================================================
    def show_legal_banner(self):
        banner = tk.Toplevel(self.root)
        banner.title(self._("legal_title"))
        banner.geometry("550x380")
        banner.resizable(False, False)
        banner.protocol("WM_DELETE_WINDOW", sys.exit)
        banner.eval('tk::PlaceWindow . center')
        
        banner.transient(self.root)
        banner.grab_set()

        frame = tk.Frame(banner, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)

        lbl_title = tk.Label(frame, text=self._("legal_title"), fg="#d90000", font=("Arial", 12, "bold"))
        lbl_title.pack(pady=(0, 10))

        text_widget = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=10, font=("Arial", 9))
        text_widget.insert(tk.END, self._("legal_text"))
        text_widget.config(state=tk.DISABLED)
        text_widget.pack(fill=tk.BOTH, expand=True, pady=10)

        btn_frame = tk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        btn_decline = tk.Button(btn_frame, text=self._("btn_decline"), fg="black", command=sys.exit)
        btn_decline.pack(side=tk.LEFT, padx=5)

        btn_accept = tk.Button(btn_frame, text=self._("btn_accept"), bg="#008000", fg="white", font=("Arial", 10, "bold"),
                               command=banner.destroy)
        btn_accept.pack(side=tk.RIGHT, padx=5)

        self.root.wait_window(banner)

    def _build_top_bar(self):
        top_bar = tk.Frame(self.root)
        top_bar.pack(fill=tk.X, padx=10, pady=5)
        
        priv_text = "ROOT MODE" if self.is_root else "USER MODE"
        priv_color = "#008000" if self.is_root else "#d90000"
        self.lbl_priv = tk.Label(top_bar, text=priv_text, fg=priv_color, font=("Arial", 10, "bold"))
        self.lbl_priv.pack(side=tk.LEFT)
        
        tk.OptionMenu(top_bar, self.current_lang, "Polski", "English", command=self.update_texts).pack(side=tk.RIGHT)

    # =========================================================================
    # OBSŁUGA TRYBU READ-ONLY
    # =========================================================================
    def toggle_read_only(self):
        state = "normal" if self.var_unlock.get() else "disabled"
        
        widgets_to_toggle = [
            self.entry_login, self.entry_domain, self.entry_old, 
            self.entry_new, self.entry_confirm, self.btn_submit,
            self.entry_diag_target, self.entry_diag_pwd
        ]
        
        for btn in self.buttons.values():
            btn.config(state=state)

        for widget in widgets_to_toggle:
            widget.config(state=state)

    def _calculate_pwd_score(self, pwd: str) -> int:
        if not pwd: return 0
        score = 0
        if len(pwd) >= 8: score += 1
        if len(pwd) >= 12: score += 1
        if re.search(r"[A-Z]", pwd): score += 1
        if re.search(r"[a-z]", pwd): score += 1
        if re.search(r"\d", pwd): score += 1
        if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", pwd): score += 1
        return score

    def clear_password_fields(self):
        self.entry_old.delete(0, tk.END)
        self.entry_new.delete(0, tk.END)
        self.entry_confirm.delete(0, tk.END)
        self.lbl_strength.config(text="")
        self.root.update()

    # =========================================================================
    # ZAKŁADKA ZMIANY HASŁA
    # =========================================================================
    def create_pass_tab(self):
        frame = tk.Frame(self.tab_pass, padx=25, pady=25)
        frame.pack(fill=tk.BOTH, expand=True)

        self.chk_unlock = tk.Checkbutton(frame, text=self._("chk_unlock"), variable=self.var_unlock, 
                                         command=self.toggle_read_only, font=("Arial", 10, "italic"), fg="#0078D7")
        self.chk_unlock.grid(row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 15))

        tk.Label(frame, text="Login (sAMAccountName):", font=("Arial", 10)).grid(row=1, column=0, sticky=tk.W, pady=6)
        self.entry_login = tk.Entry(frame, width=32, font=("Arial", 10))
        self.entry_login.grid(row=1, column=1, sticky=tk.W, pady=6)

        tk.Label(frame, text="Domena:", font=("Arial", 10)).grid(row=2, column=0, sticky=tk.W, pady=6)
        self.entry_domain = tk.Entry(frame, width=32, font=("Arial", 10))
        self.entry_domain.grid(row=2, column=1, sticky=tk.W, pady=6)
        self.entry_domain.insert(0, get_domain())

        self.btn_test = tk.Button(frame, command=self.test_ldap_bind)
        self.btn_test.grid(row=2, column=2, padx=8)

        ttk.Separator(frame, orient='horizontal').grid(row=3, column=0, columnspan=3, sticky=tk.EW, pady=15)

        self.lbl_old = tk.Label(frame, font=("Arial", 10))
        self.lbl_old.grid(row=4, column=0, sticky=tk.W, pady=6)
        self.entry_old = tk.Entry(frame, width=32, show="*", font=("Arial", 10))
        self.entry_old.grid(row=4, column=1, columnspan=2, sticky=tk.W, pady=6)

        self.lbl_new = tk.Label(frame, font=("Arial", 10))
        self.lbl_new.grid(row=5, column=0, sticky=tk.W, pady=6)
        self.entry_new = tk.Entry(frame, width=32, show="*", font=("Arial", 10))
        self.entry_new.grid(row=5, column=1, sticky=tk.W, pady=6)

        self.lbl_strength = tk.Label(frame, text="", width=10, font=("Arial", 9, "bold"))
        self.lbl_strength.grid(row=5, column=2, sticky=tk.W, padx=10)

        self.entry_new.bind("<KeyRelease>", self.evaluate_strength)

        self.lbl_confirm = tk.Label(frame, font=("Arial", 10))
        self.lbl_confirm.grid(row=6, column=0, sticky=tk.W, pady=6)
        self.entry_confirm = tk.Entry(frame, width=32, show="*", font=("Arial", 10))
        self.entry_confirm.grid(row=6, column=1, columnspan=2, sticky=tk.W, pady=6)

        self.btn_submit = tk.Button(frame, bg="#0078D7", fg="white", font=("Arial", 11, "bold"),
                                    command=self.change_password_ldap)
        self.btn_submit.grid(row=7, column=0, columnspan=3, pady=25, sticky=tk.EW, ipady=8)

    def evaluate_strength(self, event=None):
        pwd = self.entry_new.get()
        if not pwd:
            self.lbl_strength.config(text="")
            return

        score = self._calculate_pwd_score(pwd)
        if score <= 3:
            color, text = "#d90000", self._("pwd_weak")
        elif score <= 4:
            color, text = "#ff8c00", self._("pwd_fair")
        else:
            color, text = "#008000", self._("pwd_strong")

        self.lbl_strength.config(text=text, fg=color)

    def test_ldap_bind(self):
        """Sprawdza porty 636 i 389 unikając tworzenia logów o Anonymous Bind w AD."""
        domain = self.entry_domain.get().strip()
        if not domain:
            messagebox.showwarning("Błąd", "Wprowadź domenę")
            return

        self.root.config(cursor="watch")
        self.root.update()
        success = False
        port = None
        
        try:
            for p in (636, 389):
                try:
                    with socket.create_connection((domain, p), timeout=3):
                        success = True
                        port = p
                        break
                except OSError:
                    continue
            
            if success:
                messagebox.showinfo("Sukces", f"Kontroler domeny {domain} dostępny na porcie {port}.")
            else:
                messagebox.showerror("Błąd", f"Nie można połączyć się z siecią AD ({domain}) na portach 389 ani 636.")
        finally:
            self.root.config(cursor="")

    def change_password_ldap(self):
        user = self.entry_login.get().strip()
        domain = self.entry_domain.get().strip() or get_domain()
        old_pwd = self.entry_old.get()
        new_pwd = self.entry_new.get()
        confirm_pwd = self.entry_confirm.get()

        try:
            if not all([user, domain, old_pwd, new_pwd, confirm_pwd]):
                messagebox.showwarning("Błąd", self._("msg_fill_all"))
                return
            if new_pwd != confirm_pwd:
                messagebox.showerror("Błąd", self._("msg_mismatch"))
                return

            if self._calculate_pwd_score(new_pwd) < 4:
                messagebox.showerror("Słabe hasło", self._("msg_weak_password"))
                return

            self.var_unlock.set(False)
            self.clear_password_fields()
            self.toggle_read_only()
            self.root.config(cursor="watch")
            self.root.update()

            upn = f"{user}@{domain}"
            
            # Próba LDAPS (Port 636, NTLM)
            server = Server(domain, use_ssl=True, get_info=ALL, connect_timeout=6)
            conn = Connection(server, user=upn, password=old_pwd, authentication=NTLM)
            
            if not conn.bind():
                # Fallback do zwykłego LDAP (Port 389, NTLM)
                server = Server(domain, use_ssl=False, get_info=ALL, connect_timeout=6)
                conn = Connection(server, user=upn, password=old_pwd, authentication=NTLM)
                if not conn.bind():
                    messagebox.showerror("Błąd logowania", "Nieprawidłowe dane logowania lub konto zostało zablokowane.")
                    return

            # Zabezpieczenie przed brakiem struktury domeny w obiekcie serwera
            search_base = server.info.other.get('defaultNamingContext', [None])[0]
            if not search_base:
                messagebox.showerror("Błąd", "Nie można pobrać podstawowej struktury (Naming Context) domeny.")
                return

            conn.search(search_base, f'(sAMAccountName={user})', attributes=['distinguishedName'])

            if not conn.entries:
                messagebox.showerror("Błąd", "Nie znaleziono konta w strukturze Active Directory.")
                return

            user_dn = str(conn.entries[0].distinguishedName)
            new_pwd_enc = ('"' + new_pwd + '"').encode('utf-16-le')

            success = conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [new_pwd_enc])]})

            if success:
                messagebox.showinfo("Sukces", self._("msg_success"))
            else:
                desc = conn.result.get('description', str(conn.result))
                messagebox.showerror("Odmowa AD", f"Zmiana hasła odrzucona przez serwer:\n{desc}")

            conn.unbind()
        except Exception as e:
            messagebox.showerror("Błąd LDAP", f"{type(e).__name__}: {str(e)}")
        finally:
            self.root.config(cursor="")
            for pwd in (old_pwd, new_pwd, confirm_pwd):
                secure_clear_string(pwd)
            try: del old_pwd, new_pwd, confirm_pwd
            except NameError: pass
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

        self.var_unlock.set(False)
        self.entry_diag_pwd.delete(0, tk.END)
        self.toggle_read_only()
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
            secure_clear_string(pwd)
            try: del pwd
            except NameError: pass
            gc.collect()

    # =========================================================================
    # INTENACJONALIZACJA (i18n)
    # =========================================================================
    def update_texts(self, *args):
        self.notebook.tab(self.tab_pass, text=self._("tab_pass"))
        self.notebook.tab(self.tab_diag, text=self._("tab_diag"))

        self.chk_unlock.config(text=self._("chk_unlock"))
        self.lbl_old.config(text=self._("old_pwd"))
        self.lbl_new.config(text=self._("new_pwd"))
        self.lbl_confirm.config(text=self._("confirm_pwd"))
        self.btn_submit.config(text=self._("btn_submit"))
        self.btn_test.config(text=self._("btn_test"))
        self.lbl_diag_target.config(text=self._("diag_target"))
        self.lbl_diag_pwd.config(text=self._("diag_pwd"))

        for key, btn in getattr(self, 'buttons', {}).items():
            if key in TRANSLATIONS["Polski"]:
                btn.config(text=self._(key))

        self.evaluate_strength()


if __name__ == "__main__":
    app = ADAdminToolkit()
    app.root.mainloop()
