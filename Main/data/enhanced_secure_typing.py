# enhanced_secure_typing.py
import tkinter as tk
from tkinter import messagebox, filedialog, font
import datetime
import hashlib
import os
import tempfile
from cryptography.fernet import Fernet
import base64
import subprocess


class AdvancedSecureTypingApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("🛡️ KeySentinel Secure Typing  - Ultimate Protection")
        self.window.geometry("1000x700")
        self.window.configure(bg="#0a0a0a")
        self.window.resizable(True, True)
        
        # Security features
        self.encryption_key = self.generate_session_key()
        self.cipher_suite = Fernet(self.encryption_key)
        self.typing_protected = True
        self.auto_clear_timer = None
        self.session_id = self.generate_session_id()
        
        # Virtual keyboard reference
        self.virtual_keyboard = None
        
        self.setup_ui()
        self.setup_security_features()
        
        # Bind security events
        self.window.protocol("WM_DELETE_WINDOW", self.secure_exit)
        self.window.bind("<Control-c>", lambda e: self.secure_copy())
        self.window.bind("<Control-v>", lambda e: self.secure_paste())
        self.window.bind("<Control-s>", lambda e: self.secure_save())
        
        self.window.mainloop()

    def generate_session_key(self):
        """Generate a unique encryption key for this session"""
        return Fernet.generate_key()
    
    def generate_session_id(self):
        """Generate unique session identifier"""
        timestamp = str(datetime.datetime.now().timestamp())
        return hashlib.sha256(timestamp.encode()).hexdigest()[:16]

    def setup_ui(self):
        # Title and session info
        header_frame = tk.Frame(self.window, bg="#1a1a1a", relief="raised", bd=2)
        header_frame.pack(fill="x", padx=5, pady=5)
        
        title = tk.Label(header_frame, text="🛡️ Secure Typing Pro", 
                        font=("Helvetica", 16, "bold"), fg="#00ff41", bg="#1a1a1a")
        title.pack(side="left", padx=10, pady=5)
        
        session_info = tk.Label(header_frame, text=f"Session: {self.session_id} | Encrypted", 
                               font=("Helvetica", 9), fg="#888", bg="#1a1a1a")
        session_info.pack(side="right", padx=10, pady=5)
        
        # Security status indicators
        security_frame = tk.Frame(self.window, bg="#0a0a0a")
        security_frame.pack(fill="x", padx=5)
        
        self.protection_indicator = tk.Label(security_frame, text="🔐 PROTECTED", 
                                           font=("Helvetica", 10, "bold"), 
                                           fg="#00aa00", bg="#0a0a0a")
        self.protection_indicator.pack(side="left", padx=5)
        
        self.encryption_indicator = tk.Label(security_frame, text="🔒 ENCRYPTED", 
                                           font=("Helvetica", 10, "bold"), 
                                           fg="#00aa00", bg="#0a0a0a")
        self.encryption_indicator.pack(side="left", padx=5)
        
        self.vkeyboard_indicator = tk.Label(security_frame, text="⌨️ V-KEYBOARD", 
                                          font=("Helvetica", 10, "bold"), 
                                          fg="#666", bg="#0a0a0a")
        self.vkeyboard_indicator.pack(side="left", padx=5)
        
        # Main text editor
        editor_frame = tk.LabelFrame(self.window, text="Secure Text Editor", 
                                   font=("Helvetica", 12, "bold"),
                                   fg="#00ff41", bg="#1a1a1a", bd=2)
        editor_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Text widget with enhanced security
        self.text_editor = tk.Text(editor_frame, font=("Consolas", 12), bg="#0a0a0a", 
                                 fg="#00ff41", insertbackground="white", undo=True,
                                 wrap="word", relief="flat", bd=5)
        
        # Scrollbars
        v_scrollbar = tk.Scrollbar(editor_frame, orient="vertical", command=self.text_editor.yview)
        h_scrollbar = tk.Scrollbar(editor_frame, orient="horizontal", command=self.text_editor.xview)
        
        self.text_editor.config(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack scrollbars and text widget
        v_scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        self.text_editor.pack(fill="both", expand=True, padx=2, pady=2)
        
        # Control panel
        control_frame = tk.Frame(self.window, bg="#1a1a1a", relief="raised", bd=2)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        # Left side - File operations
        file_frame = tk.Frame(control_frame, bg="#1a1a1a")
        file_frame.pack(side="left", padx=10, pady=5)
        
        tk.Button(file_frame, text="📂 Open", font=("Helvetica", 9), bg="#333", fg="white",
                 command=self.secure_open, width=8).pack(side="left", padx=2)
        
        tk.Button(file_frame, text="💾 Save", font=("Helvetica", 9), bg="#333", fg="white",
                 command=self.secure_save, width=8).pack(side="left", padx=2)
        
        tk.Button(file_frame, text="📤 Export", font=("Helvetica", 9), bg="#333", fg="white",
                 command=self.export_text, width=8).pack(side="left", padx=2)
        
        # Center - Security controls
        security_controls = tk.Frame(control_frame, bg="#1a1a1a")
        security_controls.pack(side="left", expand=True, padx=20)
        
        tk.Button(security_controls, text="⌨️ Virtual Keyboard", font=("Helvetica", 10, "bold"), 
                 bg="#6600aa", fg="white", command=self.toggle_virtual_keyboard, width=15).pack(side="left", padx=5)
        
        tk.Button(security_controls, text="🔐 Toggle Protection", font=("Helvetica", 10), 
                 bg="#aa6600", fg="white", command=self.toggle_protection, width=15).pack(side="left", padx=5)
        
        tk.Button(security_controls, text="🧹 Clear All", font=("Helvetica", 10), 
                 bg="#aa0000", fg="white", command=self.clear_all, width=10).pack(side="left", padx=5)
        
        # Right side - Advanced features
        advanced_frame = tk.Frame(control_frame, bg="#1a1a1a")
        advanced_frame.pack(side="right", padx=10, pady=5)
        
        tk.Button(advanced_frame, text="🔍 Word Count", font=("Helvetica", 9), bg="#333", fg="white",
                 command=self.show_word_count, width=10).pack(side="left", padx=2)
        
        tk.Button(advanced_frame, text="🎨 Font", font=("Helvetica", 9), bg="#333", fg="white",
                 command=self.change_font, width=8).pack(side="left", padx=2)
        
        # Status bar
        self.status_bar = tk.Frame(self.window, bg="#1a1a1a", relief="sunken", bd=1)
        self.status_bar.pack(fill="x", side="bottom")
        
        self.status_label = tk.Label(self.status_bar, text="Ready - Secure mode active", 
                                   font=("Helvetica", 9), fg="white", bg="#1a1a1a")
        self.status_label.pack(side="left", padx=10, pady=2)
        
        self.chars_label = tk.Label(self.status_bar, text="Characters: 0", 
                                  font=("Helvetica", 9), fg="#888", bg="#1a1a1a")
        self.chars_label.pack(side="right", padx=10, pady=2)
        
        # Bind events for character counting
        self.text_editor.bind("<KeyRelease>", self.update_char_count)
        self.text_editor.bind("<Button-1>", self.update_char_count)

    def setup_security_features(self):
        """Initialize advanced security features"""
        # Disable standard clipboard operations
        self.text_editor.bind("<Control-c>", lambda e: "break")
        self.text_editor.bind("<Control-v>", lambda e: "break") 
        self.text_editor.bind("<Control-x>", lambda e: "break")
        
        # Disable right-click context menu
        self.text_editor.bind("<Button-3>", lambda e: "break")
        
        # Start auto-clear timer (optional)
        self.reset_auto_clear_timer()

    def open_system_keyboard(self):
        """Open the system's On-Screen Keyboard (Windows only, with fallbacks)"""
        import sys
        import shutil
        tried = []
        try:
            # Try Touch Keyboard (tabtip.exe) first
            tabtip_path = r"C:\\Program Files\\Common Files\\microsoft shared\\ink\\tabtip.exe"
            if os.path.exists(tabtip_path):
                subprocess.Popen([tabtip_path])
                self.vkeyboard_indicator.config(text="⌨️ Touch Keyboard", fg="#00aa00")
                self.status_label.config(text="Touch Keyboard opened")
                return
            tried.append('tabtip.exe')
        except Exception as e:
            tried.append(f'tabtip.exe: {e}')
        try:
            # Try osk.exe with shell=True
            subprocess.Popen("osk.exe", shell=True)
            self.vkeyboard_indicator.config(text="⌨️ OSK", fg="#00aa00")
            self.status_label.config(text="On-Screen Keyboard opened (shell=True)")
            return
        except Exception as e:
            tried.append(f'osk.exe shell=True: {e}')
        try:
            # Try osk.exe via start command
            subprocess.Popen('start osk', shell=True)
            self.vkeyboard_indicator.config(text="⌨️ OSK", fg="#00aa00")
            self.status_label.config(text="On-Screen Keyboard opened (start)")
            return
        except Exception as e:
            tried.append(f'start osk: {e}')
        try:
            # Try direct osk.exe
            subprocess.Popen(["osk.exe"])
            self.vkeyboard_indicator.config(text="⌨️ OSK", fg="#00aa00")
            self.status_label.config(text="On-Screen Keyboard opened (direct)")
            return
        except Exception as e:
            tried.append(f'osk.exe direct: {e}')
        messagebox.showerror("Error", f"Failed to open On-Screen Keyboard. Tried: {tried}")

    def toggle_virtual_keyboard(self):
        """Open the system On-Screen Keyboard (OSK)"""
        self.open_system_keyboard()

    def virtual_keyboard_input(self, key):
        """Handle input from virtual keyboard"""
        if key == 'BACKSPACE':
            self.text_editor.delete("insert-1c", tk.INSERT)
        else:
            self.text_editor.insert(tk.INSERT, key)
        
        self.update_char_count()
        self.reset_auto_clear_timer()

    def toggle_protection(self):
        """Toggle typing protection mode"""
        self.typing_protected = not self.typing_protected
        if self.typing_protected:
            self.protection_indicator.config(text="🔐 PROTECTED", fg="#00aa00")
            self.status_label.config(text="Protection mode enabled")
            self.setup_security_features()
        else:
            self.protection_indicator.config(text="⚠️ UNPROTECTED", fg="#aa0000")
            self.status_label.config(text="Protection mode disabled - USE CAUTION")

    def secure_copy(self):
        """Secure copy operation with encryption"""
        if not self.typing_protected:
            return "break"
        
        try:
            selected_text = self.text_editor.selection_get()
            encrypted_text = self.cipher_suite.encrypt(selected_text.encode())
            # Store in temporary secure location instead of system clipboard
            self.secure_clipboard = encrypted_text
            self.status_label.config(text="Text copied to secure clipboard")
        except tk.TclError:
            self.status_label.config(text="No text selected")
        return "break"

    def secure_paste(self):
        """Secure paste operation with decryption"""
        if not self.typing_protected:
            return "break"
        
        try:
            if hasattr(self, 'secure_clipboard'):
                decrypted_text = self.cipher_suite.decrypt(self.secure_clipboard).decode()
                self.text_editor.insert(tk.INSERT, decrypted_text)
                self.status_label.config(text="Text pasted from secure clipboard")
                self.update_char_count()
        except Exception as e:
            self.status_label.config(text="Secure clipboard empty or invalid")
        return "break"

    def secure_save(self):
        """Save with encryption"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".enc",
                filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
            )
            if filename:
                content = self.text_editor.get("1.0", tk.END)
                encrypted_content = self.cipher_suite.encrypt(content.encode())
                
                with open(filename, 'wb') as f:
                    f.write(encrypted_content)
                
                self.status_label.config(text=f"File saved securely: {os.path.basename(filename)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {str(e)}")
        return "break"

    def secure_open(self):
        """Open and decrypt file"""
        try:
            filename = filedialog.askopenfilename(
                filetypes=[("Encrypted files", "*.enc"), ("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'rb') as f:
                    content = f.read()
                
                try:
                    # Try to decrypt if it's an encrypted file
                    decrypted_content = self.cipher_suite.decrypt(content).decode()
                    self.text_editor.delete("1.0", tk.END)
                    self.text_editor.insert("1.0", decrypted_content)
                    self.status_label.config(text=f"Encrypted file opened: {os.path.basename(filename)}")
                except:
                    # If decryption fails, treat as plain text
                    self.text_editor.delete("1.0", tk.END)
                    self.text_editor.insert("1.0", content.decode('utf-8', errors='ignore'))
                    self.status_label.config(text=f"Text file opened: {os.path.basename(filename)}")
                
                self.update_char_count()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open file: {str(e)}")

    def export_text(self):
        """Export as plain text with warning"""
        response = messagebox.askyesno("Export Warning", 
                                     "This will export as unencrypted text.\nContinue?")
        if response:
            try:
                filename = filedialog.asksaveasfilename(
                    defaultextension=".txt",
                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
                )
                if filename:
                    content = self.text_editor.get("1.0", tk.END)
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(content)
                    self.status_label.config(text=f"Exported: {os.path.basename(filename)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")

    def clear_all(self):
        """Secure clear all content"""
        if messagebox.askyesno("Clear All", "This will permanently clear all text.\nContinue?"):
            self.text_editor.delete("1.0", tk.END)
            if hasattr(self, 'secure_clipboard'):
                del self.secure_clipboard
            self.status_label.config(text="All content cleared securely")
            self.update_char_count()

    def show_word_count(self):
        """Display word and character count"""
        content = self.text_editor.get("1.0", tk.END)
        chars = len(content) - 1  # Subtract the automatic newline at end
        words = len([word for word in content.split() if word])
        lines = content.count('\n')
        
        info = f"Characters: {chars}\nWords: {words}\nLines: {lines}"
        messagebox.showinfo("Document Statistics", info)

    def change_font(self):
        """Font selection dialog"""
        current_font = font.Font(font=self.text_editor['font'])
        
        font_window = tk.Toplevel(self.window)
        font_window.title("Font Settings")
        font_window.geometry("300x200")
        font_window.configure(bg="#1a1a1a")
        
        # Font family
        tk.Label(font_window, text="Font Family:", fg="white", bg="#1a1a1a").pack(pady=5)
        font_var = tk.StringVar(value=current_font.actual()['family'])
        font_combo = tk.Entry(font_window, textvariable=font_var, bg="#333", fg="white")
        font_combo.pack(pady=5)
        
        # Font size
        tk.Label(font_window, text="Font Size:", fg="white", bg="#1a1a1a").pack(pady=5)
        size_var = tk.StringVar(value=str(current_font.actual()['size']))
        size_combo = tk.Entry(font_window, textvariable=size_var, bg="#333", fg="white")
        size_combo.pack(pady=5)
        
        def apply_font():
            try:
                new_font = (font_var.get(), int(size_var.get()))
                self.text_editor.config(font=new_font)
                font_window.destroy()
                self.status_label.config(text="Font updated")
            except ValueError:
                messagebox.showerror("Error", "Invalid font size")
        
        tk.Button(font_window, text="Apply", command=apply_font, 
                 bg="#00aa00", fg="white").pack(pady=10)

    def update_char_count(self, event=None):
        """Update character count in status bar"""
        content = self.text_editor.get("1.0", tk.END)
        char_count = len(content) - 1  # Subtract automatic newline
        self.chars_label.config(text=f"Characters: {char_count}")

    def reset_auto_clear_timer(self):
        """Reset auto-clear timer (optional security feature)"""
        if self.auto_clear_timer:
            self.window.after_cancel(self.auto_clear_timer)
        # Auto-clear after 30 minutes of inactivity (disabled by default)
        # self.auto_clear_timer = self.window.after(1800000, self.auto_clear)

    def auto_clear(self):
        """Auto-clear content after timeout"""
        if messagebox.askyesno("Auto-Clear", "Session timeout. Clear content for security?"):
            self.clear_all()

    def secure_exit(self):
        """Secure exit with content clearing"""
        if messagebox.askokcancel("Secure Exit", "Clear all content and exit?"):
            # Clear text content
            self.text_editor.delete("1.0", tk.END)
            
            # Clear clipboard
            try:
                self.window.clipboard_clear()
            except:
                pass
            
            # Clear secure clipboard
            if hasattr(self, 'secure_clipboard'):
                del self.secure_clipboard
            
            # Close virtual keyboard if open
            if self.virtual_keyboard:
                self.virtual_keyboard.close_keyboard()
            
            self.window.destroy()


class AdvancedVirtualKeyboard:
    """Enhanced Virtual Keyboard with advanced security features"""
    
    def __init__(self, parent_callback=None):
        self.parent_callback = parent_callback
        self.window = tk.Toplevel()
        self.window.title("🛡️ KeySentinel Virtual Keyboard Pro")
        self.window.geometry("900x400")
        self.window.configure(bg="#0a0a0a")
        self.window.resizable(False, False)
        self.window.attributes('-topmost', True)
        
        # Security features
        self.caps_lock = False
        self.shift_active = False
        self.ctrl_active = False
        self.alt_active = False
        self.fn_active = False
        
        # Layouts
        self.current_layout = "qwerty"
        self.layouts = {
            "qwerty": {
                "row1": ['`', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '='],
                "row2": ['Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '[', ']', '\\'],
                "row3": ['A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ';', "'"],
                "row4": ['Z', 'X', 'C', 'V', 'B', 'N', 'M', ',', '.', '/']
            },
            "dvorak": {
                "row1": ['`', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '[', ']'],
                "row2": ["'", ',', '.', 'P', 'Y', 'F', 'G', 'C', 'R', 'L', '/', '=', '\\'],
                "row3": ['A', 'O', 'E', 'U', 'I', 'D', 'H', 'T', 'N', 'S', '-'],
                "row4": [';', 'Q', 'J', 'K', 'X', 'B', 'M', 'W', 'V', 'Z']
            }
        }
        
        self.setup_keyboard()
        
    def setup_keyboard(self):
        # Title bar
        title_frame = tk.Frame(self.window, bg="#1a1a1a", height=40)
        title_frame.pack(fill="x")
        title_frame.pack_propagate(False)
        
        title = tk.Label(title_frame, text="🔐 Advanced Virtual Keyboard Pro", 
                        font=("Helvetica", 14, "bold"), fg="#00ff41", bg="#1a1a1a")
        title.pack(side="left", padx=10, pady=10)
        
        # Layout selector
        layout_frame = tk.Frame(title_frame, bg="#1a1a1a")
        layout_frame.pack(side="right", padx=10, pady=5)
        
        tk.Label(layout_frame, text="Layout:", font=("Arial", 9), 
                fg="white", bg="#1a1a1a").pack(side="left")
        
        self.layout_var = tk.StringVar(value=self.current_layout)
        layout_menu = tk.OptionMenu(layout_frame, self.layout_var, *self.layouts.keys(), 
                                  command=self.change_layout)
        layout_menu.config(bg="#333", fg="white", font=("Arial", 8))
        layout_menu.pack(side="left", padx=5)
        
        # Status indicators
        self.setup_status_indicators()
        
        # Function row
        self.setup_function_row()
        
        # Main keyboard
        self.setup_main_keyboard()
        
        # Control row
        self.setup_control_row()
        
        # Numeric keypad (optional)
        self.setup_numeric_keypad()

    def setup_status_indicators(self):
        status_frame = tk.Frame(self.window, bg="#1a1a1a", height=30)
        status_frame.pack(fill="x")
        status_frame.pack_propagate(False)
        
        indicator_container = tk.Frame(status_frame, bg="#1a1a1a")
        indicator_container.pack(side="left", padx=10, pady=5)
        
        self.caps_indicator = tk.Label(indicator_container, text="CAPS", font=("Arial", 8, "bold"), 
                                     bg="#333", fg="#666", width=6, relief="raised")
        self.caps_indicator.pack(side="left", padx=2)
        
        self.shift_indicator = tk.Label(indicator_container, text="SHIFT", font=("Arial", 8, "bold"), 
                                      bg="#333", fg="#666", width=6, relief="raised")
        self.shift_indicator.pack(side="left", padx=2)
        
        self.ctrl_indicator = tk.Label(indicator_container, text="CTRL", font=("Arial", 8, "bold"), 
                                     bg="#333", fg="#666", width=6, relief="raised")
        self.ctrl_indicator.pack(side="left", padx=2)
        
        self.alt_indicator = tk.Label(indicator_container, text="ALT", font=("Arial", 8, "bold"), 
                                    bg="#333", fg="#666", width=6, relief="raised")
        self.alt_indicator.pack(side="left", padx=2)
        
        self.fn_indicator = tk.Label(indicator_container, text="FN", font=("Arial", 8, "bold"), 
                                   bg="#333", fg="#666", width=6, relief="raised")
        self.fn_indicator.pack(side="left", padx=2)

    def setup_function_row(self):
        func_frame = tk.Frame(self.window, bg="#0a0a0a")
        func_frame.pack(pady=2)
        
        # Function keys F1-F12
        function_keys = ['F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12']
        
        for i, key in enumerate(function_keys):
            btn = tk.Button(func_frame, text=key, width=5, height=1,
                          command=lambda k=key: self.key_press(k),
                          bg="#444", fg="white", font=("Arial", 8))
            btn.grid(row=0, column=i, padx=1)

    def setup_main_keyboard(self):
        main_frame = tk.Frame(self.window, bg="#0a0a0a")
        main_frame.pack(pady=5)
        
        layout = self.layouts[self.current_layout]
        
        # Number row
        num_frame = tk.Frame(main_frame, bg="#0a0a0a")
        num_frame.grid(row=0, column=0, sticky="w")
        
        numbers = layout["row1"] + ['Backspace']
        for i, key in enumerate(numbers):
            if key == 'Backspace':
                btn = tk.Button(num_frame, text=key, width=8, height=2, 
                              command=lambda: self.key_press('BACKSPACE'),
                              bg="#ff4444", fg="white", font=("Arial", 9, "bold"))
            else:
                btn = tk.Button(num_frame, text=key, width=4, height=2,
                              command=lambda k=key: self.key_press(k),
                              bg="#333", fg="white", font=("Arial", 9))
            btn.grid(row=0, column=i, padx=1)
        
        # First letter row (QWERTY top row)
        row1_frame = tk.Frame(main_frame, bg="#0a0a0a")
        row1_frame.grid(row=1, column=0, sticky="w")
        
        # Tab key
        tab_btn = tk.Button(row1_frame, text="Tab", width=6, height=2,
                          command=lambda: self.key_press('TAB'),
                          bg="#555", fg="white", font=("Arial", 9))
        tab_btn.grid(row=0, column=0, padx=1)
        
        row1_keys = layout["row2"]
        for i, key in enumerate(row1_keys):
            btn = tk.Button(row1_frame, text=key, width=4, height=2,
                          command=lambda k=key: self.key_press(k),
                          bg="#333", fg="white", font=("Arial", 9))
            btn.grid(row=0, column=i+1, padx=1)
        
        # Second letter row (QWERTY home row)
        row2_frame = tk.Frame(main_frame, bg="#0a0a0a")
        row2_frame.grid(row=2, column=0, sticky="w")
        
        # Caps Lock
        caps_btn = tk.Button(row2_frame, text="Caps", width=7, height=2,
                           command=self.toggle_caps_lock,
                           bg="#666", fg="white", font=("Arial", 9))
        caps_btn.grid(row=0, column=0, padx=1)
        
        row2_keys = layout["row3"]
        for i, key in enumerate(row2_keys):
            btn = tk.Button(row2_frame, text=key, width=4, height=2,
                          command=lambda k=key: self.key_press(k),
                          bg="#333", fg="white", font=("Arial", 9))
            btn.grid(row=0, column=i+1, padx=1)
        
        # Enter key
        enter_btn = tk.Button(row2_frame, text="Enter", width=9, height=2,
                            command=lambda: self.key_press('ENTER'),
                            bg="#00aa00", fg="white", font=("Arial", 9, "bold"))
        enter_btn.grid(row=0, column=len(row2_keys)+1, padx=1)
        
        # Third letter row (QWERTY bottom row)
        row3_frame = tk.Frame(main_frame, bg="#0a0a0a")
        row3_frame.grid(row=3, column=0, sticky="w")
        
        # Left Shift
        lshift_btn = tk.Button(row3_frame, text="Shift", width=9, height=2,
                             command=self.toggle_shift,
                             bg="#666", fg="white", font=("Arial", 9))
        lshift_btn.grid(row=0, column=0, padx=1)
        
        row3_keys = layout["row4"]
        for i, key in enumerate(row3_keys):
            btn = tk.Button(row3_frame, text=key, width=4, height=2,
                          command=lambda k=key: self.key_press(k),
                          bg="#333", fg="white", font=("Arial", 9))
            btn.grid(row=0, column=i+1, padx=1)
        
        # Right Shift
        rshift_btn = tk.Button(row3_frame, text="Shift", width=9, height=2,
                             command=self.toggle_shift,
                             bg="#666", fg="white", font=("Arial", 9))
        rshift_btn.grid(row=0, column=len(row3_keys)+1, padx=1)

    def setup_control_row(self):
        control_frame = tk.Frame(self.window, bg="#0a0a0a")
        control_frame.pack(pady=5)
        
        # Left side modifiers
        left_frame = tk.Frame(control_frame, bg="#0a0a0a")
        left_frame.pack(side="left")
        
        ctrl_btn = tk.Button(left_frame, text="Ctrl", width=6, height=2,
                           command=self.toggle_ctrl,
                           bg="#666", fg="white", font=("Arial", 9))
        ctrl_btn.grid(row=0, column=0, padx=1)
        
        fn_btn = tk.Button(left_frame, text="Fn", width=6, height=2,
                         command=self.toggle_fn,
                         bg="#666", fg="white", font=("Arial", 9))
        fn_btn.grid(row=0, column=1, padx=1)
        
        alt_btn = tk.Button(left_frame, text="Alt", width=6, height=2,
                          command=self.toggle_alt,
                          bg="#666", fg="white", font=("Arial", 9))
        alt_btn.grid(row=0, column=2, padx=1)
        
        # Center - Space bar
        space_btn = tk.Button(control_frame, text="Space", width=50, height=2,
                            command=lambda: self.key_press('SPACE'),
                            bg="#444", fg="white", font=("Arial", 9))
        space_btn.pack(side="left", padx=10)
        
        # Right side modifiers and controls
        right_frame = tk.Frame(control_frame, bg="#0a0a0a")
        right_frame.pack(side="right")
        
        alt_gr_btn = tk.Button(right_frame, text="Alt Gr", width=6, height=2,
                             command=self.toggle_alt,
                             bg="#666", fg="white", font=("Arial", 9))
        alt_gr_btn.grid(row=0, column=0, padx=1)
        
        menu_btn = tk.Button(right_frame, text="Menu", width=6, height=2,
                           command=lambda: self.key_press('MENU'),
                           bg="#666", fg="white", font=("Arial", 9))
        menu_btn.grid(row=0, column=1, padx=1)
        
        close_btn = tk.Button(right_frame, text="Close", width=8, height=2,
                            command=self.close_keyboard,
                            bg="#aa0000", fg="white", font=("Arial", 9, "bold"))
        close_btn.grid(row=0, column=2, padx=1)

    def setup_numeric_keypad(self):
        """Optional numeric keypad"""
        numpad_frame = tk.Frame(self.window, bg="#0a0a0a")
        numpad_frame.pack(side="right", padx=10, pady=5)
        
        # Numeric keypad layout
        numpad_keys = [
            ['Num', '/', '*', '-'],
            ['7', '8', '9', '+'],
            ['4', '5', '6', '+'],
            ['1', '2', '3', 'Enter'],
            ['0', '0', '.', 'Enter']
        ]
        
        for row_idx, row in enumerate(numpad_keys):
            for col_idx, key in enumerate(row):
                if key == 'Enter' and row_idx == 3:
                    # Large Enter key
                    btn = tk.Button(numpad_frame, text=key, width=4, height=4,
                                  command=lambda: self.key_press('ENTER'),
                                  bg="#00aa00", fg="white", font=("Arial", 9))
                    btn.grid(row=row_idx, column=col_idx, rowspan=2, padx=1, pady=1, sticky="ns")
                elif key == '0' and col_idx == 0:
                    # Wide 0 key
                    btn = tk.Button(numpad_frame, text=key, width=8, height=2,
                                  command=lambda k=key: self.key_press(k),
                                  bg="#333", fg="white", font=("Arial", 9))
                    btn.grid(row=row_idx, column=col_idx, columnspan=2, padx=1, pady=1)
                elif key == '+' and row_idx == 1:
                    # Tall + key
                    btn = tk.Button(numpad_frame, text=key, width=4, height=4,
                                  command=lambda k=key: self.key_press(k),
                                  bg="#333", fg="white", font=("Arial", 9))
                    btn.grid(row=row_idx, column=col_idx, rowspan=2, padx=1, pady=1, sticky="ns")
                elif not (key == '0' and col_idx == 1) and not (key == '+' and row_idx == 2) and not (key == 'Enter' and row_idx == 4):
                    # Regular keys
                    btn = tk.Button(numpad_frame, text=key, width=4, height=2,
                                  command=lambda k=key: self.key_press(k),
                                  bg="#333", fg="white", font=("Arial", 9))
                    btn.grid(row=row_idx, column=col_idx, padx=1, pady=1)

    def change_layout(self, layout_name):
        """Change keyboard layout"""
        self.current_layout = layout_name
        # Rebuild the main keyboard section
        # This would require rebuilding the keyboard - simplified for demo
        
    def key_press(self, key):
        """Handle key press with security features"""
        if self.parent_callback:
            processed_key = self.process_key(key)
            self.parent_callback(processed_key)
        
        # Reset shift after use (except for special keys)
        if self.shift_active and key not in ['SHIFT', 'BACKSPACE', 'ENTER', 'TAB', 'SPACE']:
            self.shift_active = False
            self.update_indicators()
    
    def process_key(self, key):
        """Process key based on modifiers and current state"""
        if key == 'SPACE':
            return ' '
        elif key == 'ENTER':
            return '\n'
        elif key == 'TAB':
            return '\t'
        elif key == 'BACKSPACE':
            return 'BACKSPACE'
        elif len(key) == 1:
            if key.isalpha():
                if self.caps_lock or self.shift_active:
                    return key.upper()
                return key.lower()
            elif self.shift_active:
                # Handle special character shifts
                shift_map = {
                    '1': '!', '2': '@', '3': '#', '4': '$', '5': '%',
                    '6': '^', '7': '&', '8': '*', '9': '(', '0': ')',
                    '-': '_', '=': '+', '[': '{', ']': '}', '\\': '|',
                    ';': ':', "'": '"', ',': '<', '.': '>', '/': '?',
                    '`': '~'
                }
                return shift_map.get(key, key)
        return key
    
    def toggle_caps_lock(self):
        self.caps_lock = not self.caps_lock
        self.update_indicators()
    
    def toggle_shift(self):
        self.shift_active = not self.shift_active
        self.update_indicators()
    
    def toggle_ctrl(self):
        self.ctrl_active = not self.ctrl_active
        self.update_indicators()
    
    def toggle_alt(self):
        self.alt_active = not self.alt_active
        self.update_indicators()
    
    def toggle_fn(self):
        self.fn_active = not self.fn_active
        self.update_indicators()
    
    def update_indicators(self):
        """Update status indicators"""
        self.caps_indicator.config(bg="#00aa00" if self.caps_lock else "#333",
                                 fg="white" if self.caps_lock else "#666")
        self.shift_indicator.config(bg="#00aa00" if self.shift_active else "#333",
                                  fg="white" if self.shift_active else "#666")
        self.ctrl_indicator.config(bg="#00aa00" if self.ctrl_active else "#333",
                                 fg="white" if self.ctrl_active else "#666")
        self.alt_indicator.config(bg="#00aa00" if self.alt_active else "#333",
                                fg="white" if self.alt_active else "#666")
        self.fn_indicator.config(bg="#00aa00" if self.fn_active else "#333",
                               fg="white" if self.fn_active else "#666")
    
    def close_keyboard(self):
        self.window.destroy()


# Run as standalone
if __name__ == "__main__":
    AdvancedSecureTypingApp()
