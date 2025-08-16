import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import datetime
import platform
import os

from detector import get_suspicious_processes  
from process_scanner import scan_processes_with_scores
from secure_typing import SecureTypingApp
from report_viewer import ThreatReportViewer
from admin_db_handler import AdminDB
from credential_pannel import Credentials  # ✅ Corrected import


class KeySentinelApp:
    def __init__(self, root):
        self.root = root
        self.admin_db = AdminDB()
        self.root.title("🛡️ KeySentinel – Anti-Keylogger Shield")
        self.root.geometry("900x600")
        self.root.configure(bg="#0f172a")

        if not self.verify_admin_login():
            self.root.destroy()
            return

        self.setup_ui()

    def verify_admin_login(self):
        password = simpledialog.askstring("🔐 Admin Login", "Enter Admin Password:", show="*")
        if not password or not self.admin_db.verify_password(password):
            messagebox.showerror("Access Denied", "Incorrect password!")
            return False
        return True

    def setup_ui(self):
        title = tk.Label(self.root, text="🛡️KeySentinel", font=("Helvetica", 28, "bold"), fg="white", bg="#0f172a")
        title.pack(pady=20)

        subtitle = tk.Label(self.root, text=" Keylogger Detection System", font=("Helvetica", 14), fg="#38bdf8", bg="#0f172a")
        subtitle.pack(pady=5)

        # Info Frame
        info_frame = tk.Frame(self.root, bg="#1e293b", bd=2, relief="groove")
        info_frame.pack(pady=20, fill="x", padx=40)

        self.sys_info_label = tk.Label(info_frame, text="", font=("Courier", 12), fg="white", bg="#1e293b", justify="left")
        self.sys_info_label.pack(padx=10, pady=10)
        self.display_system_info()

        # Buttons
        btn_frame = tk.Frame(self.root, bg="#0f172a")
        btn_frame.pack(pady=20)

        scan_btn = tk.Button(btn_frame, text="🔍 Start Keylogger Scan", font=("Helvetica", 14), bg="#38bdf8", fg="black", command=self.scan_keyloggers)
        scan_btn.grid(row=0, column=0, padx=15)

        secure_typing_btn = tk.Button(btn_frame, text="✏️ Secure Typing Mode", font=("Helvetica", 14), bg="#22c55e", fg="black", command=self.secure_typing)
        secure_typing_btn.grid(row=0, column=1, padx=15)

        report_btn = tk.Button(btn_frame, text="📊 Generate Report", font=("Helvetica", 14), bg="#facc15", fg="black", command=self.generate_report)
        report_btn.grid(row=0, column=2, padx=15)

        change_pass_btn = tk.Button(btn_frame, text="🔒 Change Password", font=("Helvetica", 14), bg="#f87171", fg="black", command=self.change_password)
        change_pass_btn.grid(row=0, column=3, padx=15)

        go_to_pro_btn = tk.Button(btn_frame, text="👑 Go to Pro", font=("Helvetica", 14), bg="#f87171", fg="black", command=self.get_credentials)
        go_to_pro_btn.grid(row=0, column=4, padx=14)

        # Log box
        self.log_box = tk.Text(self.root, height=10, bg="#1e293b", fg="white", font=("Courier", 11))
        self.log_box.pack(padx=40, pady=10, fill="both", expand=True)
        self.log_box.insert(tk.END, "[INFO] Welcome to KeySentinel ...\n")

    def scan_keyloggers(self):
        self.log_box.insert(tk.END, "[SCAN] Advanced Heuristic Scan Started...\n")
        threats = scan_processes_with_scores()

        if threats:
            for threat in threats:
                risk_color = "RED" if threat['score'] > 70 else "YELLOW" if threat['score'] > 30 else "GREEN"
                self.log_box.insert(tk.END, f"[THREAT - {risk_color}] Process: {threat['name']} (PID: {threat['pid']})\n")
                self.log_box.insert(tk.END, f" → Path: {threat['path']}\n")
                self.log_box.insert(tk.END, f" → Threat Score: {threat['score']}\n")
                self.log_box.insert(tk.END, f" → Reasons: {', '.join(threat['reasons'])}\n\n")
        else:
            self.log_box.insert(tk.END, "[SAFE] No suspicious processes found.\n")

    def secure_typing(self):
        SecureTypingApp()

    def generate_report(self):
        ThreatReportViewer()

    def get_credentials(self):
        Credentials().run()  # ✅ Launch credentials GUI

    def display_system_info(self):
        os_info = f"Operating System: {platform.system()} {platform.release()}"
        python_ver = f"Python Version: {platform.python_version()}"
        timestamp = f"Launch Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        arch = f"Architecture: {platform.machine()}"
        user = f"Username: {os.getlogin()}"

        full_info = f"{os_info}\n{python_ver}\n{arch}\n{user}\n{timestamp}"
        self.sys_info_label.config(text=full_info)

    def change_password(self):
        current = simpledialog.askstring("🔑 Change Password", "Enter current password:", show="*")
        if not self.admin_db.verify_password(current):
            messagebox.showerror("Error", "Current password is incorrect.")
            return

        new_pass = simpledialog.askstring("🔐 New Password", "Enter new password:", show="*")
        confirm = simpledialog.askstring("🔐 Confirm Password", "Re-enter new password:", show="*")

        if new_pass != confirm:
            messagebox.showerror("Mismatch", "Passwords do not match.")
            return

        self.admin_db.set_password(new_pass)
        messagebox.showinfo("Success", "Password changed successfully!")


# Start the app
if __name__ == "__main__":
    root = tk.Tk()
    app = KeySentinelApp(root)
    root.mainloop()
