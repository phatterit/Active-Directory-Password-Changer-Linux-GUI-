#!/usr/bin/env python3
"""
Bezpieczny skrypt zmiany hasła Active Directory (GUI)
Wersja produkcyjna - Ostateczna (2026)
"""

import tkinter as tk
from tkinter import messagebox
import subprocess
import socket
import re

def get_domain():
    """Automatyczne wykrywanie domeny AD w systemach Linux."""
    try:
        # Próba 1: realm (SSSD)
        result = subprocess.run(['realm', 'list'], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if 'domain-name:' in line:
                return line.split(':', 1)[1].strip()

        # Próba 2: dnsdomainname
        result = subprocess.run(['dnsdomainname'], capture_output=True, text=True, timeout=3)
        domain = result.stdout.strip()
        if domain:
            return domain
    except Exception:
        pass

    return "twojadomena.local"  # Fallback

def is_strong_password(password: str) -> tuple[bool, str]:
    """Weryfikacja złożoności hasła (polityka domeny)."""
    if len(password) < 8:
        return False, "Hasło musi mieć co najmniej 8 znaków."
    if not re.search(r"[A-Z]", password):
        return False, "Hasło musi zawierać co najmniej jedną wielką literę."
    if not re.search(r"[a-z]", password):
        return False, "Hasło musi zawierać co najmniej jedną małą literę."
    if not re.search(r"\d", password):
        return False, "Hasło musi zawierać co najmniej jedną cyfrę."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
        return False, "Hasło musi zawierać co najmniej jeden znak specjalny."
    return True, ""


class PasswordChanger:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Zmiana hasła Active Directory")
        self.root.geometry("480x430")
        self.root.resizable(False, False)
        self.root.eval('tk::PlaceWindow . center')

        # Próba załadowania systemowej ikony
        try:
            img = tk.PhotoImage(file='/usr/share/icons/Yaru/16x16/status/dialog-password.png')
            self.root.tk.call('wm', 'iconphoto', self.root._w, img)
        except Exception:
            pass

        self.create_gui()

    def create_gui(self):
        """Buduje interfejs graficzny użytkownika."""
        frame = tk.Frame(self.root, padx=25, pady=25)
        frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(frame, text="Zmiana hasła w Active Directory",
                 font=("Arial", 14, "bold")).grid(row=0, column=0, columnspan=3, pady=(0, 20))

        # Sekcja Loginu
        tk.Label(frame, text="Login:", font=("Arial", 10)).grid(row=1, column=0, sticky=tk.W, pady=6)
        self.entry_login = tk.Entry(frame, width=28, font=("Arial", 10))
        self.entry_login.grid(row=1, column=1, columnspan=2, sticky=tk.W, pady=6)

        # Sekcja Domeny
        tk.Label(frame, text="Domena AD:", font=("Arial", 10)).grid(row=2, column=0, sticky=tk.W, pady=6)
        self.entry_domain = tk.Entry(frame, width=28, font=("Arial", 10))
        self.entry_domain.grid(row=2, column=1, sticky=tk.W, pady=6)
        self.entry_domain.insert(0, get_domain())

        btn_test = tk.Button(frame, text="Test połączenia", font=("Arial", 9), command=self.test_connection)
        btn_test.grid(row=2, column=2, padx=(8, 0))

        # Separator wizualny
        tk.Frame(frame, height=2, bd=1, relief=tk.SUNKEN).grid(row=3, column=0, columnspan=3, sticky=tk.EW, pady=18)

        # Sekcja wprowadzania haseł
        tk.Label(frame, text="Obecne hasło:", font=("Arial", 10)).grid(row=4, column=0, sticky=tk.W, pady=6)
        self.entry_old = tk.Entry(frame, width=28, show="*", font=("Arial", 10))
        self.entry_old.grid(row=4, column=1, columnspan=2, sticky=tk.W, pady=6)

        tk.Label(frame, text="Nowe hasło:", font=("Arial", 10)).grid(row=5, column=0, sticky=tk.W, pady=6)
        self.entry_new = tk.Entry(frame, width=28, show="*", font=("Arial", 10))
        self.entry_new.grid(row=5, column=1, columnspan=2, sticky=tk.W, pady=6)

        tk.Label(frame, text="Potwierdź hasło:", font=("Arial", 10)).grid(row=6, column=0, sticky=tk.W, pady=6)
        self.entry_confirm = tk.Entry(frame, width=28, show="*", font=("Arial", 10))
        self.entry_confirm.grid(row=6, column=1, columnspan=2, sticky=tk.W, pady=6)

        # Przycisk wykonawczy
        btn_submit = tk.Button(
            frame,
            text="Zmień hasło",
            bg="#0078D7",
            fg="white",
            font=("Arial", 11, "bold"),
            command=self.change_password,
            height=2
        )
        btn_submit.grid(row=7, column=0, columnspan=3, pady=30, sticky=tk.EW)

    def clear_password_fields(self):
        """Błyskawicznie czyści pola haseł w interfejsie graficznym."""
        self.entry_old.delete(0, tk.END)
        self.entry_new.delete(0, tk.END)
        self.entry_confirm.delete(0, tk.END)
        self.root.update()

    def test_connection(self):
        """Sprawdza osiągalność kontrolera domeny za pomocą portu LDAP (odporne na blokady ICMP)."""
        domain = self.entry_domain.get().strip()
        if not domain:
            messagebox.showwarning("Błąd", "Podaj nazwę domeny.")
            return

        self.root.config(cursor="watch")
        self.root.update()

        try:
            # Testujemy faktyczny port usługi katalogowej (389)
            with socket.create_connection((domain, 389), timeout=3):
                messagebox.showinfo("Sukces", f"Domena '{domain}' odpowiada (port 389).")
        except socket.timeout:
            messagebox.showwarning("Brak połączenia", 
                f"Domena '{domain}' nie odpowiada (Timeout).\n\n"
                "Sprawdź połączenie VPN, sieć lub firewall.")
        except socket.gaierror:
            messagebox.showerror("Błąd DNS", f"Nie można rozwiązać nazwy domeny '{domain}'.")
        except Exception as e:
            messagebox.showerror("Błąd", f"Nie można wykonać testu:\n{str(e)}")
        finally:
            self.root.config(cursor="")

    def change_password(self):
        """Główna metoda zmieniająca hasło z rygorystycznym zarządzaniem pamięcią RAM."""
        user = self.entry_login.get().strip()
        domain = self.entry_domain.get().strip()
        
        # Pobranie wartości z interfejsu bezpośrednio do zmiennych lokalnych
        old_pwd = self.entry_old.get()
        new_pwd = self.entry_new.get()
        confirm_pwd = self.entry_confirm.get()

        # Cała logika MUST be w bloku try, aby finally wymusiło usunięcie haseł
        try:
            if not all([user, domain, old_pwd, new_pwd, confirm_pwd]):
                messagebox.showwarning("Braki w formularzu", "Wszystkie pola muszą być wypełnione!")
                return 

            if new_pwd != confirm_pwd:
                messagebox.showerror("Błąd", "Nowe hasła nie są identyczne!")
                self.entry_new.delete(0, tk.END)
                self.entry_confirm.delete(0, tk.END)
                return

            strong, msg = is_strong_password(new_pwd)
            if not strong:
                messagebox.showerror("Słabe hasło", msg)
                self.entry_new.delete(0, tk.END)
                self.entry_confirm.delete(0, tk.END)
                return

            # Czyszczenie interfejsu na czas pracy procesu smbpasswd
            self.clear_password_fields()

            # Bezpieczne wstrzyknięcie haseł bez pokazywania ich w systemie
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

            # Weryfikacja kodu wyjścia
            if process.returncode == 0:
                messagebox.showinfo("Sukces", "Hasło zostało pomyślnie zmienione w Active Directory!")
                self.root.destroy()
            else:
                error_lower = (stderr + stdout).lower()
                if "password" in error_lower and ("fail" in error_lower or "incorrect" in error_lower):
                    msg = "Nieprawidłowe obecne hasło lub konto zablokowane na kontrolerze."
                elif "not permitted" in error_lower or "constraint" in error_lower or "complexity" in error_lower:
                    msg = "Nowe hasło nie spełnia wymagań restrykcyjnej polityki domeny."
                else:
                    msg = "Nie udało się zmienić hasła. Sprawdź dane i spróbuj ponownie."

                messagebox.showerror("Błąd zmiany hasła", msg)

        except FileNotFoundError:
            messagebox.showerror("Brak narzędzia", 
                "Aplikacja 'smbpasswd' nie jest zainstalowana w systemie.\n\n"
                "Zainstaluj pakiet za pomocą:\nsudo apt install samba-common-bin")
        except subprocess.TimeoutExpired:
            messagebox.showerror("Błąd", "Operacja przekroczyła czas oczekiwania (Timeout).")
        except Exception as e:
            messagebox.showerror("Błąd krytyczny", f"Nieoczekiwany wyjątek:\n{str(e)}")
        finally:
            # Gwarantowane, fizyczne usunięcie zmiennych z przestrzeni pamięci Pythona
            if 'old_pwd' in locals(): del old_pwd
            if 'new_pwd' in locals(): del new_pwd
            if 'confirm_pwd' in locals(): del confirm_pwd


if __name__ == "__main__":
    app = PasswordChanger()
    app.root.mainloop()
