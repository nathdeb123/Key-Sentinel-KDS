import tkinter as tk
from tkinter import messagebox
import subprocess
import sys
import json

class Credentials:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("User Credentials")

        self.name = ""
        self.dob = ""

        tk.Label(self.root, text="Name:").grid(row=0, column=0, padx=10, pady=10)
        self.name_entry = tk.Entry(self.root, width=30)
        self.name_entry.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(self.root, text="Date of Birth (YYYY-MM-DD):").grid(row=1, column=0, padx=10, pady=10)
        self.dob_entry = tk.Entry(self.root, width=30)
        self.dob_entry.grid(row=1, column=1, padx=10, pady=10)

        submit_btn = tk.Button(self.root, text="Submit", command=self.submit)
        submit_btn.grid(row=2, column=0, columnspan=2, pady=20)

    def submit(self):
        self.name = self.name_entry.get().strip().upper()
        self.dob = self.dob_entry.get().strip()

        if not self.name or not self.dob:
            messagebox.showwarning("Input Error", "Please enter both Name and DOB.")
            return

        # Use absolute paths for credentials.json and activation_key.py
        import os
        base_dir = os.path.dirname(os.path.abspath(__file__))
        cred_path = os.path.join(base_dir, "credentials.json")
        activation_path = os.path.join(base_dir, "activation_key.py")

        # Save to JSON so activation_key.py can read
        with open(cred_path, "w") as f:
            json.dump({"name": self.name, "dob": self.dob}, f)

        self.root.destroy()

        # Open activation_key.py with absolute path
        subprocess.Popen([sys.executable, activation_path])

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = Credentials()
    app.run()
