# secure_typing.py
import tkinter as tk
from tkinter import messagebox

class SecureTypingApp:
    def __init__(self):
        self.window = tk.Tk()
        try:
            import os
            icon_path = os.path.join(os.path.dirname(__file__), "KeySentinel_logo.ico")
            if os.path.exists(icon_path):
                self.window.iconbitmap(icon_path)
            else:
                self.window.iconbitmap("KeySentinel_logo.ico")
        except Exception:
            try:
                self.window.iconbitmap(default="KeySentinel_logo.ico")
            except Exception:
                pass
        self.window.title("Secure Typing Mode - KeySentinel 🛡️")
        self.window.geometry("600x400")
        self.window.resizable(False, False)
        self.window.configure(bg="#1e1e1e")

        self.text_box = tk.Text(self.window, font=("Consolas", 14), bg="#111", fg="#00FF00", insertbackground="white", undo=True)
        self.text_box.pack(padx=20, pady=20, fill="both", expand=True)
        self.text_box.bind("<Control-c>", lambda e: "break")
        self.text_box.bind("<Control-v>", lambda e: "break")
        self.text_box.bind("<Control-x>", lambda e: "break")

        self.build_virtual_keyboard()

        self.window.protocol("WM_DELETE_WINDOW", self.secure_exit)
        self.window.mainloop()

    def build_virtual_keyboard(self):
        keys_frame = tk.Frame(self.window, bg="#1e1e1e")
        keys_frame.pack(pady=10)

        buttons = [
            'Q','W','E','R','T','Y','U','I','O','P',
            'A','S','D','F','G','H','J','K','L',
            'Z','X','C','V','B','N','M',
            'SPACE','DELETE'
        ]

        row = 0
        col = 0
        for key in buttons:
            action = lambda x=key: self.insert_char(x)
            b = tk.Button(keys_frame, text=key, width=5, height=2, command=action, bg="#444", fg="white", relief="flat")
            b.grid(row=row, column=col, padx=2, pady=2)
            col += 1
            if (key == 'P') or (key == 'L') or (key == 'M'):
                row += 1
                col = 0

    def insert_char(self, char):
        if char == "SPACE":
            self.text_box.insert(tk.INSERT, " ")
        elif char == "DELETE":
            self.text_box.delete("insert-1c", tk.INSERT)
        else:
            self.text_box.insert(tk.INSERT, char)

    def secure_exit(self):
        if messagebox.askokcancel("Secure Exit", "Clear all text and exit Secure Typing Mode?"):
            self.text_box.delete("1.0", tk.END)
            self.window.clipboard_clear()
            self.window.destroy()

# Run as standalone
if __name__ == "__main__":
    SecureTypingApp()
