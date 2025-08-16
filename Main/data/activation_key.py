import customtkinter as ctk
from tkinter import messagebox
import json
import os


# Load credentials using absolute path
import os
base_dir = os.path.dirname(os.path.abspath(__file__))
cred_path = os.path.join(base_dir, "credentials.json")
if not os.path.exists(cred_path):
    messagebox.showerror("Error", "No credentials found! Please run credential_pannel.py first.")
    exit()

with open(cred_path, "r") as f:
    creds = json.load(f)

expected_key = creds["name"] + creds["dob"]

# GUI Settings
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("Activation Key Portal")
app.geometry("500x350")
app.resizable(False, False)

def validate_key():
    key = key_entry.get().strip()
    if key == expected_key:
        messagebox.showinfo("Success ✅", "Activation Key Accepted. Welcome!")
        # Close the activation window
        app.destroy()
        # Launch the advanced main application using absolute path
        import subprocess
        import sys
        import os
        base_dir = os.path.dirname(os.path.abspath(__file__))
        advanced_main_path = os.path.join(base_dir, "advanced_main.py")
        try:
            subprocess.Popen([sys.executable, advanced_main_path])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to launch advanced application: {e}")
    else:
        messagebox.showerror("Invalid ❌", "Activation Key is incorrect.")

def toggle_theme():
    ctk.set_appearance_mode("light" if ctk.get_appearance_mode() == "Dark" else "dark")

title_label = ctk.CTkLabel(
    app, text="🔐 Activation Portal",
    font=ctk.CTkFont(size=22, weight="bold")
)
title_label.pack(pady=20)

instruction_label = ctk.CTkLabel(
    app, text="Enter your activation key",
    font=ctk.CTkFont(size=15), text_color="gray"
)
instruction_label.pack(pady=5)

key_entry = ctk.CTkEntry(
    app, placeholder_text="Activation Key",
    width=300, height=40,
    font=ctk.CTkFont(size=14),
    justify="center"
)
key_entry.pack(pady=15)

activate_button = ctk.CTkButton(
    app, text="Activate Now",
    width=200, height=40,
    font=ctk.CTkFont(size=16, weight="bold"),
    corner_radius=15,
    command=validate_key
)
activate_button.pack(pady=10)

theme_button = ctk.CTkButton(
    app, text="Toggle Light/Dark",
    width=150, height=30,
    font=ctk.CTkFont(size=13),
    fg_color="gray20", hover_color="gray30",
    corner_radius=15, command=toggle_theme
)
theme_button.pack(pady=10)

app.mainloop()
