import tkinter as tk
import customtkinter as ctk
from tkinter import ttk, messagebox, simpledialog, font
import datetime
import platform
import os
import threading
import time
import psutil
from pathlib import Path

from detector import get_suspicious_processes  
from process_scanner import scan_processes_with_scores
from secure_typing import SecureTypingApp
from report_viewer import ThreatReportViewer
from admin_db_handler import AdminDB
from keylogger_db import KeyloggerThreatDB
from enhanced_secure_typing import AdvancedSecureTypingApp
from ai_chat import SambanovaClient
import json
import os


def _set_window_icon(win):
    import os
    import sys
    try:
        # Try to get icon from current directory first
        icon_path = "KeySentinel_logo.ico"
        
        # If running as PyInstaller bundle, use the bundled path
        if getattr(sys, 'frozen', False):
            icon_path = os.path.join(sys._MEIPASS, "KeySentinel_logo.ico")
        else:
            # Otherwise, check script directory
            icon_path = os.path.join(os.path.dirname(__file__), "KeySentinel_logo.ico")
        
        if os.path.exists(icon_path):
            win.iconbitmap(icon_path)
        else:
            # Try current working directory as last resort
            if os.path.exists("KeySentinel_logo.ico"):
                win.iconbitmap("KeySentinel_logo.ico")
    except Exception:
        # Silently fail - Tkinter default will be used but won't crash
        pass


class AdvancedVirtualKeyboard:
    """Advanced Virtual Keyboard with enhanced security features"""
    
    def __init__(self, parent_callback=None):
        self.parent_callback = parent_callback
        self.window = tk.Toplevel()
        _set_window_icon(self.window)
        self.window.title("🛡️ KeySentinel Virtual Keyboard")
        self.window.geometry("800x350")
        self.window.configure(bg="#0a0a0a")
        self.window.resizable(False, False)
        self.window.attributes('-topmost', True)
        
        # Security features
        self.caps_lock = False
        self.shift_active = False
        self.ctrl_active = False
        self.alt_active = False
        
        self.setup_keyboard()
        
    def setup_keyboard(self):
        # Title
        title = tk.Label(self.window, text="🔐 Advanced Virtual Keyboard", 
                        font=("Helvetica", 16, "bold"), fg="#00ff41", bg="#0a0a0a")
        title.pack(pady=10)
        
        # Status bar
        self.status_frame = tk.Frame(self.window, bg="#1a1a1a", height=30)
        self.status_frame.pack(fill="x", padx=10, pady=5)
        
        self.caps_indicator = tk.Label(self.status_frame, text="CAPS", font=("Arial", 8), 
                                     bg="#333", fg="#666", width=6)
        self.caps_indicator.pack(side="left", padx=2)
        
        self.shift_indicator = tk.Label(self.status_frame, text="SHIFT", font=("Arial", 8), 
                                      bg="#333", fg="#666", width=6)
        self.shift_indicator.pack(side="left", padx=2)
        
        self.ctrl_indicator = tk.Label(self.status_frame, text="CTRL", font=("Arial", 8), 
                                     bg="#333", fg="#666", width=6)
        self.ctrl_indicator.pack(side="left", padx=2)
        
        # Number row
        num_frame = tk.Frame(self.window, bg="#0a0a0a")
        num_frame.pack(pady=2)
        
        numbers = ['`', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', 'Backspace']
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
        
        # First letter row
        row1_frame = tk.Frame(self.window, bg="#0a0a0a")
        row1_frame.pack(pady=2)
        
        row1 = ['Tab', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '[', ']', '\\']
        for i, key in enumerate(row1):
            if key == 'Tab':
                btn = tk.Button(row1_frame, text=key, width=6, height=2,
                              command=lambda: self.key_press('TAB'),
                              bg="#555", fg="white", font=("Arial", 9))
            else:
                btn = tk.Button(row1_frame, text=key, width=4, height=2,
                              command=lambda k=key: self.key_press(k),
                              bg="#333", fg="white", font=("Arial", 9))
            btn.grid(row=0, column=i, padx=1)
        
        # Second letter row
        row2_frame = tk.Frame(self.window, bg="#0a0a0a")
        row2_frame.pack(pady=2)
        
        # Caps Lock button
        caps_btn = tk.Button(row2_frame, text="Caps", width=6, height=2,
                           command=self.toggle_caps_lock,
                           bg="#666", fg="white", font=("Arial", 9))
        caps_btn.grid(row=0, column=0, padx=1)
        
        row2 = ['A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ';', "'", 'Enter']
        for i, key in enumerate(row2):
            if key == 'Enter':
                btn = tk.Button(row2_frame, text=key, width=8, height=2,
                              command=lambda: self.key_press('ENTER'),
                              bg="#00aa00", fg="white", font=("Arial", 9, "bold"))
            else:
                btn = tk.Button(row2_frame, text=key, width=4, height=2,
                              command=lambda k=key: self.key_press(k),
                              bg="#333", fg="white", font=("Arial", 9))
            btn.grid(row=0, column=i+1, padx=1)
        
        # Third letter row
        row3_frame = tk.Frame(self.window, bg="#0a0a0a")
        row3_frame.pack(pady=2)
        
        # Shift button
        shift_btn = tk.Button(row3_frame, text="Shift", width=8, height=2,
                            command=self.toggle_shift,
                            bg="#666", fg="white", font=("Arial", 9))
        shift_btn.grid(row=0, column=0, padx=1)
        
        row3 = ['Z', 'X', 'C', 'V', 'B', 'N', 'M', ',', '.', '/', 'Shift']
        for i, key in enumerate(row3):
            if key == 'Shift':
                btn = tk.Button(row3_frame, text=key, width=8, height=2,
                              command=self.toggle_shift,
                              bg="#666", fg="white", font=("Arial", 9))
            else:
                btn = tk.Button(row3_frame, text=key, width=4, height=2,
                              command=lambda k=key: self.key_press(k),
                              bg="#333", fg="white", font=("Arial", 9))
            btn.grid(row=0, column=i+1, padx=1)
        
        # Bottom row (space, ctrl, alt, etc.)
        bottom_frame = tk.Frame(self.window, bg="#0a0a0a")
        bottom_frame.pack(pady=2)
        
        ctrl_btn = tk.Button(bottom_frame, text="Ctrl", width=6, height=2,
                           command=self.toggle_ctrl,
                           bg="#666", fg="white", font=("Arial", 9))
        ctrl_btn.grid(row=0, column=0, padx=1)
        
        alt_btn = tk.Button(bottom_frame, text="Alt", width=6, height=2,
                          command=self.toggle_alt,
                          bg="#666", fg="white", font=("Arial", 9))
        alt_btn.grid(row=0, column=1, padx=1)
        
        space_btn = tk.Button(bottom_frame, text="Space", width=40, height=2,
                            command=lambda: self.key_press('SPACE'),
                            bg="#444", fg="white", font=("Arial", 9))
        space_btn.grid(row=0, column=2, padx=1)
        
        alt_gr_btn = tk.Button(bottom_frame, text="Alt Gr", width=6, height=2,
                             command=self.toggle_alt,
                             bg="#666", fg="white", font=("Arial", 9))
        alt_gr_btn.grid(row=0, column=3, padx=1)
        
        close_btn = tk.Button(bottom_frame, text="Close", width=8, height=2,
                            command=self.close_keyboard,
                            bg="#aa0000", fg="white", font=("Arial", 9, "bold"))
        close_btn.grid(row=0, column=4, padx=1)
        
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
        """Process key based on modifiers"""
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
    
    def update_indicators(self):
        """Update status indicators"""
        self.caps_indicator.config(bg="#00aa00" if self.caps_lock else "#333",
                                 fg="white" if self.caps_lock else "#666")
        self.shift_indicator.config(bg="#00aa00" if self.shift_active else "#333",
                                  fg="white" if self.shift_active else "#666")
        self.ctrl_indicator.config(bg="#00aa00" if self.ctrl_active else "#333",
                                 fg="white" if self.ctrl_active else "#666")
    
    def close_keyboard(self):
        self.window.destroy()


class AdvancedKeyloggerScanner:
    """Advanced real-time keylogger detection system"""
    
    def __init__(self, callback):
        self.callback = callback
        self.scanning = False
        self.db = KeyloggerThreatDB()
        
    def start_realtime_scan(self):
        self.scanning = True
        thread = threading.Thread(target=self._continuous_scan, daemon=True)
        thread.start()
    
    def stop_scan(self):
        self.scanning = False
    
    def _continuous_scan(self):
        while self.scanning:
            try:
                threats = scan_processes_with_scores()
                if threats:
                    for threat in threats:
                        if threat['score'] > 50:  # High-risk threats
                            self.db.log_threat(
                                threat['name'], 
                                threat['pid'], 
                                "High" if threat['score'] > 70 else "Medium",
                                "Detected"
                            )
                            self.callback(threat)
                time.sleep(5)  # Scan every 5 seconds
            except Exception as e:
                print(f"Scan error: {e}")
                time.sleep(10)


class NetworkSecurityMonitor:
    """Monitor network connections for suspicious activity"""
    
    def __init__(self):
        self.suspicious_ports = [1337, 31337, 12345, 54321, 9999]
        self.monitoring = False
    
    def start_monitoring(self):
        self.monitoring = True
        thread = threading.Thread(target=self._monitor_connections, daemon=True)
        thread.start()
    
    def stop_monitoring(self):
        self.monitoring = False
    
    def _monitor_connections(self):
        while self.monitoring:
            try:
                connections = psutil.net_connections()
                for conn in connections:
                    if conn.laddr and conn.laddr.port in self.suspicious_ports:
                        yield {
                            'type': 'network',
                            'port': conn.laddr.port,
                            'status': conn.status,
                            'pid': conn.pid
                        }
                time.sleep(10)
            except:
                time.sleep(15)


class AdvancedKeySenintelProApp:
    def __init__(self, root):
        self.root = root
        self.admin_db = AdminDB()
        self.db = KeyloggerThreatDB()
        # store the most recent scan results so reports can include them
        self.last_scan_results = []
        
        # Initialize monitoring systems
        self.scanner = AdvancedKeyloggerScanner(self.on_threat_detected)
        self.network_monitor = NetworkSecurityMonitor()
        
        self.root.title("🛡️ KeySentinel  - Keylogger Defense System")
        try:
            _set_window_icon(self.root)
        except Exception:
            pass
        self.root.geometry("1200x800")
        self.root.configure(bg="#0a0a0a")
        self.root.state('zoomed')
        
        # Security state
        self.realtime_scanning = False
        self.network_monitoring = False
        self.threat_count = 0
        
        if not self.verify_admin_login():
            self.root.destroy()
            return
            
        self.setup_advanced_ui()
        self.setup_menubar()
        self.start_system_monitoring()

    def verify_admin_login(self):
        login_window = tk.Toplevel(self.root)
        _set_window_icon(login_window)
        login_window.title("🔐 KeySentinel - Admin Authentication")
        login_window.geometry("400x300")
        login_window.configure(bg="#0a0a0a")
        login_window.transient(self.root)
        login_window.grab_set()
        
        # Center the window
        login_window.update_idletasks()
        x = (login_window.winfo_screenwidth() // 2) - (400 // 2)
        y = (login_window.winfo_screenheight() // 2) - (300 // 2)
        login_window.geometry(f"400x300+{x}+{y}")
        
        # Title
        title = tk.Label(login_window, text="🛡️ KeySentinel ", 
                        font=("Helvetica", 20, "bold"), fg="#00ff41", bg="#0a0a0a")
        title.pack(pady=20)
        
        subtitle = tk.Label(login_window, text="Advanced Keylogger Defense", 
                           font=("Helvetica", 12), fg="#888", bg="#0a0a0a")
        subtitle.pack(pady=5)
        
        # Login frame
        login_frame = tk.Frame(login_window, bg="#1a1a1a", relief="raised", bd=2)
        login_frame.pack(pady=30, padx=40, fill="both", expand=True)
        
        tk.Label(login_frame, text="Admin Password:", font=("Helvetica", 12), 
                fg="white", bg="#1a1a1a").pack(pady=10)
        
        password_var = tk.StringVar()
        password_entry = tk.Entry(login_frame, textvariable=password_var, show="*", 
                                 font=("Helvetica", 12), bg="#333", fg="white", 
                                 insertbackground="white", relief="flat", bd=5)
        password_entry.pack(pady=10, padx=20, fill="x")
        password_entry.focus()
        
        result = {'authenticated': False}
        
        def authenticate():
            if self.admin_db.verify_password(password_var.get()):
                result['authenticated'] = True
                login_window.destroy()
            else:
                messagebox.showerror("Access Denied", "Incorrect password!")
                password_entry.delete(0, tk.END)
        
        def on_enter(event):
            authenticate()
        
        password_entry.bind('<Return>', on_enter)
        
        btn_frame = tk.Frame(login_frame, bg="#1a1a1a")
        btn_frame.pack(pady=20)
        
        login_btn = tk.Button(btn_frame, text="🔓 Login", font=("Helvetica", 12, "bold"),
                             bg="#00aa00", fg="white", command=authenticate, width=10)
        login_btn.pack(side="left", padx=10)
        
        cancel_btn = tk.Button(btn_frame, text="❌ Cancel", font=("Helvetica", 12),
                              bg="#aa0000", fg="white", 
                              command=lambda: login_window.destroy(), width=10)
        cancel_btn.pack(side="left", padx=10)
        
        login_window.wait_window()
        return result['authenticated']

    def setup_menubar(self):
        menubar = tk.Menu(self.root, bg="#1a1a1a", fg="white")
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg="#1a1a1a", fg="white")
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Report", command=self.export_report)
        file_menu.add_command(label="Import Settings", command=self.import_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0, bg="#1a1a1a", fg="white")
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Process Manager", command=self.open_process_manager)
        tools_menu.add_command(label="Network Monitor", command=self.toggle_network_monitoring)
        tools_menu.add_command(label="System Info", command=self.show_system_info)
        tools_menu.add_separator()
        tools_menu.add_command(label="Standalone Report Viewer", command=self.open_standalone_report_viewer)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg="#1a1a1a", fg="white")
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def setup_advanced_ui(self):
        # Main container with dark theme
        main_container = tk.Frame(self.root, bg="#0a0a0a")
        main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Header section
        self.setup_header(main_container)
        
        # Create main content area with tabs
        self.setup_tabbed_interface(main_container)
        
        # Status bar
        self.setup_status_bar(main_container)

    def setup_header(self, parent):
        header_frame = tk.Frame(parent, bg="#1a1a1a", relief="raised", bd=2)
        header_frame.pack(fill="x", pady=(0, 10))
        
        # Left side - Title and status
        left_frame = tk.Frame(header_frame, bg="#1a1a1a")
        left_frame.pack(side="left", fill="both", expand=True, padx=20, pady=15)
        
        title = tk.Label(left_frame, text="🛡️ KeySentinel-(KDS) ", 
                        font=("Helvetica", 24, "bold"), fg="#00ff41", bg="#1a1a1a")
        title.pack(anchor="w")
        
        subtitle = tk.Label(left_frame, text="                      Advanced Keylogger Defense System", 
                           font=("Helvetica", 12), fg="#888", bg="#1a1a1a")
        subtitle.pack(anchor="w")
        
        # Right side - Status indicators
        right_frame = tk.Frame(header_frame, bg="#1a1a1a")
        right_frame.pack(side="right", padx=20, pady=15)
        
        # Security status indicators
        self.security_status = tk.Label(right_frame, text="🔴 OFFLINE", 
                                       font=("Helvetica", 12, "bold"), 
                                       fg="#ff4444", bg="#1a1a1a")
        self.security_status.pack(anchor="e")
        
        self.threat_counter = tk.Label(right_frame, text="Threats Detected: 0", 
                                      font=("Helvetica", 10), fg="#888", bg="#1a1a1a")
        self.threat_counter.pack(anchor="e")

    def setup_tabbed_interface(self, parent):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill="both", expand=True)
        
        # Configure dark theme for notebook
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#1a1a1a', borderwidth=0)
        style.configure('TNotebook.Tab', background='#333', foreground='white', 
                       padding=[12, 8], font=('Helvetica', 10))
        style.map('TNotebook.Tab', background=[('selected', '#00aa00')])
        
        # Dashboard Tab
        self.setup_dashboard_tab()
        
        # Real-time Scanner Tab
        self.setup_scanner_tab()
        
        # Secure Tools Tab
        self.setup_secure_tools_tab()
        
        # Reports Tab
        self.setup_reports_tab()
        
        # Settings Tab
        self.setup_settings_tab()

    def setup_dashboard_tab(self):
        dashboard_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(dashboard_frame, text="📊 Dashboard")

        # Use a two-column grid: left for overview/actions/activity, right for AI chat
        dashboard_frame.columnconfigure(0, weight=3)
        dashboard_frame.columnconfigure(1, weight=1)
        dashboard_frame.rowconfigure(0, weight=1)

        left_col = tk.Frame(dashboard_frame, bg="#0a0a0a")
        left_col.grid(row=0, column=0, sticky="nsew", padx=(10,5), pady=10)

        right_col = tk.Frame(dashboard_frame, bg="#0a0a0a")
        right_col.grid(row=0, column=1, sticky="nsew", padx=(5,10), pady=10)

        # System overview (top of left column)
        overview_frame = tk.LabelFrame(left_col, text="System Overview",
                                       font=("Helvetica", 12, "bold"),
                                       fg="#00ff41", bg="#1a1a1a", bd=2)
        overview_frame.pack(fill="x", padx=0, pady=(0,8))

        self.system_info_label = tk.Label(overview_frame, text="Loading system info...",
                                         font=("Consolas", 10), fg="white", bg="#1a1a1a",
                                         justify="left")
        self.system_info_label.pack(padx=10, pady=10, anchor="w")

        # Quick Actions (middle of left column)
        actions_frame = tk.LabelFrame(left_col, text="Quick Actions",
                                      font=("Helvetica", 12, "bold"),
                                      fg="#00ff41", bg="#1a1a1a", bd=2)
        actions_frame.pack(fill="x", padx=0, pady=(0,8))

        btn_container = tk.Frame(actions_frame, bg="#1a1a1a")
        btn_container.pack(pady=10, padx=5, fill="x")

        # Use a small grid for action buttons so they align nicely
        btn_container.columnconfigure((0,1,2), weight=1)
        self.create_action_button(btn_container, "🔍", "Quick Scan",
                                  "Immediate threat detection", self.quick_scan, 0, 0)
        self.create_action_button(btn_container, "🛡️", "Real-time Protection",
                                  "Toggle continuous monitoring", self.toggle_realtime_scan, 0, 1)
        self.create_action_button(btn_container, "⌨️", "Virtual Keyboard",
                                  "Secure input method", self.open_virtual_keyboard, 0, 2)
        self.create_action_button(btn_container, "🔒", "Secure Typing",
                                  "Protected text editor", self.secure_typing, 1, 0)
        self.create_action_button(btn_container, "📈", "Live Monitor",
                                  "Real-time process viewer", self.open_live_monitor, 1, 1)
        self.create_action_button(btn_container, "🚨", "Emergency Mode",
                                  "Lockdown suspicious processes", self.emergency_mode, 1, 2)

        # Recent Activity (bottom of left column) - expands
        activity_frame = tk.LabelFrame(left_col, text="Recent Activity",
                                       font=("Helvetica", 12, "bold"),
                                       fg="#00ff41", bg="#1a1a1a", bd=2)
        activity_frame.pack(fill="both", expand=True, padx=0, pady=(0,0))

        self.activity_text = tk.Text(activity_frame, height=8, bg="#0a0a0a", fg="#00ff41",
                                     font=("Consolas", 10), insertbackground="white")
        activity_text_scroll = tk.Scrollbar(activity_frame, command=self.activity_text.yview)
        self.activity_text.config(yscrollcommand=activity_text_scroll.set)
        self.activity_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        activity_text_scroll.pack(side="right", fill="y")

        # --- AI Chat Side Panel (Sambanova) placed in right column ---
        ai_frame = tk.LabelFrame(right_col, text="AI Chat (Sambanova)",
                                 font=("Helvetica", 12, "bold"),
                                 fg="#00ff41", bg="#1a1a1a", bd=2)
        ai_frame.pack(fill="both", expand=True, padx=0, pady=0)

        # Conversation display (fills most of right column)
        self.ai_chat_text = tk.Text(ai_frame, height=20, bg="#0a0a0a", fg="#ffffff",
                                    font=("Consolas", 10), wrap="word", state="disabled", insertbackground="white")
        ai_chat_scroll = tk.Scrollbar(ai_frame, command=self.ai_chat_text.yview)
        self.ai_chat_text.config(yscrollcommand=ai_chat_scroll.set)
        self.ai_chat_text.pack(side="top", fill="both", expand=True, padx=5, pady=5)
        ai_chat_scroll.pack(side="right", fill="y")

        # Input and controls (bottom of right column)
        input_frame = tk.Frame(ai_frame, bg="#1a1a1a")
        input_frame.pack(fill="x", padx=5, pady=(0,8))

        self.ai_input_var = tk.StringVar()
        ai_entry = tk.Entry(input_frame, textvariable=self.ai_input_var, bg="#333", fg="white",
                            insertbackground="white")
        ai_entry.pack(side="left", fill="x", expand=True, padx=(0,5))
        ai_entry.bind('<Return>', lambda e: self.send_ai_message())

        send_btn = tk.Button(input_frame, text="Send", bg="#0066aa", fg="white", command=self.send_ai_message)
        send_btn.pack(side="left", padx=(0,5))

        clear_btn = tk.Button(input_frame, text="Clear", bg="#333", fg="white", command=lambda: self.clear_ai_chat())
        clear_btn.pack(side="left", padx=(0,5))

        key_btn = tk.Button(input_frame, text="Set API Key", bg="#aa6600", fg="white", command=self.set_api_key)
        key_btn.pack(side="left", padx=(0,5))

        # Sambanova client instance (will be created on demand)
        self._sambanova_client = SambanovaClient()
        self._ai_config_path = os.path.join(os.path.dirname(__file__), "config", "ai_config.json")
        # Ensure config directory exists
        try:
            os.makedirs(os.path.dirname(self._ai_config_path), exist_ok=True)
        except Exception:
            pass

    def create_action_button(self, parent, icon, title, description, command, row, col):
        btn_frame = tk.Frame(parent, bg="#2a2a2a", relief="raised", bd=2)
        btn_frame.grid(row=row, column=col, padx=10, pady=5, sticky="ew")
        parent.grid_columnconfigure(col, weight=1)
        
        btn = tk.Button(btn_frame, text=f"{icon}\n{title}", font=("Helvetica", 11, "bold"),
                       bg="#333", fg="white", relief="flat", command=command,
                       width=15, height=3)
        btn.pack(padx=5, pady=5)
        
        desc_label = tk.Label(btn_frame, text=description, font=("Helvetica", 8),
                             fg="#888", bg="#2a2a2a")
        desc_label.pack()

    def setup_scanner_tab(self):
        scanner_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(scanner_frame, text="🔍 Scanner")
        
        # Scanner controls
        control_frame = tk.LabelFrame(scanner_frame, text="Scanner Controls", 
                                    font=("Helvetica", 12, "bold"),
                                    fg="#00ff41", bg="#1a1a1a", bd=2)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        control_buttons = tk.Frame(control_frame, bg="#1a1a1a")
        control_buttons.pack(pady=10)
        
        self.scan_btn = tk.Button(control_buttons, text="🔍 Start Deep Scan", 
                                 font=("Helvetica", 12, "bold"), bg="#00aa00", fg="white",
                                 command=self.start_deep_scan, width=15)
        self.scan_btn.pack(side="left", padx=10)
        
        self.realtime_btn = tk.Button(control_buttons, text="🛡️ Start Real-time", 
                                     font=("Helvetica", 12, "bold"), bg="#0066aa", fg="white",
                                     command=self.toggle_realtime_scan, width=15)
        self.realtime_btn.pack(side="left", padx=10)
        
        # Scanner results
        results_frame = tk.LabelFrame(scanner_frame, text="Scan Results", 
                                    font=("Helvetica", 12, "bold"),
                                    fg="#00ff41", bg="#1a1a1a", bd=2)
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Treeview for results
        columns = ("Process", "PID", "Threat Level", "Score", "Status", "Action")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=100, anchor="center")
        
        results_scroll = tk.Scrollbar(results_frame, orient="vertical", 
                                    command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=results_scroll.set)
        
        self.results_tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        results_scroll.pack(side="right", fill="y")
        
        # Configure treeview style
        style = ttk.Style()
        style.configure("Treeview", background="#1a1a1a", foreground="white", 
                       fieldbackground="#1a1a1a", rowheight=25)
        style.map("Treeview", background=[("selected", "#00aa00")])

    def setup_secure_tools_tab(self):
        tools_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(tools_frame, text="🔧 Secure Tools")
        
        # Virtual Keyboard Section
        keyboard_frame = tk.LabelFrame(tools_frame, text="Virtual Keyboard", 
                                     font=("Helvetica", 12, "bold"),
                                     fg="#00ff41", bg="#1a1a1a", bd=2)
        keyboard_frame.pack(fill="x", padx=10, pady=5)
        
        keyboard_desc = tk.Label(keyboard_frame, 
                               text="Virtual keyboard with keylogger protection",
                               font=("Helvetica", 10), fg="#888", bg="#1a1a1a")
        keyboard_desc.pack(pady=5)
        
        keyboard_btn = tk.Button(keyboard_frame, text="🔐 Open Virtual Keyboard", 
                               font=("Helvetica", 12, "bold"), bg="#6600aa", fg="white",
                               command=self.open_virtual_keyboard, width=25)
        keyboard_btn.pack(pady=10)
        
        # Secure Typing Section
        typing_frame = tk.LabelFrame(tools_frame, text="Secure Text Editor", 
                                   font=("Helvetica", 12, "bold"),
                                   fg="#00ff41", bg="#1a1a1a", bd=2)
        typing_frame.pack(fill="x", padx=10, pady=5)
        
        typing_desc = tk.Label(typing_frame, 
                             text="Protected text editor with memory encryption",
                             font=("Helvetica", 10), fg="#888", bg="#1a1a1a")
        typing_desc.pack(pady=5)
        
        typing_btn = tk.Button(typing_frame, text="✏️ Open Secure Editor", 
                             font=("Helvetica", 12, "bold"), bg="#aa6600", fg="white",
                             command=self.secure_typing, width=25)
        typing_btn.pack(pady=10)
        
        # Process Protection
        protection_frame = tk.LabelFrame(tools_frame, text="Process Protection", 
                                       font=("Helvetica", 12, "bold"),
                                       fg="#00ff41", bg="#1a1a1a", bd=2)
        protection_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        protection_desc = tk.Label(protection_frame, 
                                 text="Advanced process protection and management system",
                                 font=("Helvetica", 10), fg="#888", bg="#1a1a1a")
        protection_desc.pack(pady=5)
        
        protection_btn = tk.Button(protection_frame, text="🛡️ Open Process Protection Manager", 
                                 font=("Helvetica", 12, "bold"), bg="#ff6600", fg="white",
                                 command=self.open_process_manager, width=30)
        protection_btn.pack(pady=10)
        
        protection_controls = tk.Frame(protection_frame, bg="#1a1a1a")
        protection_controls.pack(pady=10)
        
        whitelist_btn = tk.Button(protection_controls, text="📝 Manage Whitelist", 
                                font=("Helvetica", 11), bg="#333", fg="white",
                                command=self.manage_whitelist, width=18)
        whitelist_btn.pack(side="left", padx=5)
        
        quarantine_btn = tk.Button(protection_controls, text="🔒 Quarantine Manager", 
                                 font=("Helvetica", 11), bg="#333", fg="white",
                                 command=self.manage_quarantine, width=18)
        quarantine_btn.pack(side="left", padx=5)
        
        autoprotect_btn = tk.Button(protection_controls, text="🛡️ Auto-Protection", 
                                  font=("Helvetica", 11), bg="#333", fg="white",
                                  command=self.toggle_auto_protection, width=18)
        autoprotect_btn.pack(side="left", padx=5)

    def setup_reports_tab(self):
        reports_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(reports_frame, text="📊 Reports")
        
        # Report generation controls
        gen_frame = tk.LabelFrame(reports_frame, text="Report Generation", 
                                font=("Helvetica", 12, "bold"),
                                fg="#00ff41", bg="#1a1a1a", bd=2)
        gen_frame.pack(fill="x", padx=10, pady=5)
        
        gen_controls = tk.Frame(gen_frame, bg="#1a1a1a")
        gen_controls.pack(pady=10)
        
        daily_btn = tk.Button(gen_controls, text="📅 Daily Report", 
                            font=("Helvetica", 11), bg="#0066aa", fg="white",
                            command=lambda: self.generate_report("daily"), width=15)
        daily_btn.pack(side="left", padx=5)
        
        weekly_btn = tk.Button(gen_controls, text="📊 Weekly Summary", 
                             font=("Helvetica", 11), bg="#0066aa", fg="white",
                             command=lambda: self.generate_report("weekly"), width=15)
        weekly_btn.pack(side="left", padx=5)
        
        export_btn = tk.Button(gen_controls, text="💾 Export Data", 
                             font=("Helvetica", 11), bg="#aa6600", fg="white",
                             command=self.export_report, width=15)
        export_btn.pack(side="left", padx=5)
        
        # Report viewer
        viewer_frame = tk.LabelFrame(reports_frame, text="Report Viewer", 
                                   font=("Helvetica", 12, "bold"),
                                   fg="#00ff41", bg="#1a1a1a", bd=2)
        viewer_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.report_text = tk.Text(viewer_frame, bg="#0a0a0a", fg="#00ff41", 
                                 font=("Consolas", 10), insertbackground="white")
        report_scroll = tk.Scrollbar(viewer_frame, command=self.report_text.yview)
        self.report_text.config(yscrollcommand=report_scroll.set)
        
        self.report_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        report_scroll.pack(side="right", fill="y")

    def setup_settings_tab(self):
        settings_frame = tk.Frame(self.notebook, bg="#0a0a0a")
        self.notebook.add(settings_frame, text="⚙️ Settings")
        
        # Security Settings
        security_frame = tk.LabelFrame(settings_frame, text="Security Settings", 
                                     font=("Helvetica", 12, "bold"),
                                     fg="#00ff41", bg="#1a1a1a", bd=2)
        security_frame.pack(fill="x", padx=10, pady=5)
        
        self.auto_scan_var = tk.BooleanVar(value=True)
        auto_scan_check = tk.Checkbutton(security_frame, text="Auto-scan on startup", 
                                       variable=self.auto_scan_var, font=("Helvetica", 10),
                                       fg="white", bg="#1a1a1a", selectcolor="#333")
        auto_scan_check.pack(anchor="w", padx=10, pady=5)
        
        self.realtime_alerts_var = tk.BooleanVar(value=True)
        alerts_check = tk.Checkbutton(security_frame, text="Real-time threat alerts", 
                                    variable=self.realtime_alerts_var, font=("Helvetica", 10),
                                    fg="white", bg="#1a1a1a", selectcolor="#333")
        alerts_check.pack(anchor="w", padx=10, pady=5)
        
        # Scan interval
        interval_frame = tk.Frame(security_frame, bg="#1a1a1a")
        interval_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(interval_frame, text="Scan Interval (seconds):", 
                font=("Helvetica", 10), fg="white", bg="#1a1a1a").pack(side="left")
        
        self.scan_interval = tk.StringVar(value="5")
        interval_entry = tk.Entry(interval_frame, textvariable=self.scan_interval, 
                                width=10, bg="#333", fg="white", insertbackground="white")
        interval_entry.pack(side="left", padx=10)
        
        # Admin Settings
        admin_frame = tk.LabelFrame(settings_frame, text="Admin Settings", 
                                  font=("Helvetica", 12, "bold"),
                                  fg="#00ff41", bg="#1a1a1a", bd=2)
        admin_frame.pack(fill="x", padx=10, pady=5)
        
        change_pass_btn = tk.Button(admin_frame, text="🔒 Change Password", 
                                  font=("Helvetica", 11), bg="#aa0000", fg="white",
                                  command=self.change_password, width=20)
        change_pass_btn.pack(pady=10)

    def setup_status_bar(self, parent):
        self.status_bar = tk.Frame(parent, bg="#1a1a1a", relief="sunken", bd=1)
        self.status_bar.pack(fill="x", side="bottom")
        
        self.status_label = tk.Label(self.status_bar, text="Ready", 
                                   font=("Helvetica", 9), fg="white", bg="#1a1a1a")
        self.status_label.pack(side="left", padx=10, pady=2)
        
        self.time_label = tk.Label(self.status_bar, text="", 
                                 font=("Helvetica", 9), fg="#888", bg="#1a1a1a")
        self.time_label.pack(side="right", padx=10, pady=2)
        
        self.update_time()

    def update_time(self):
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)

    def start_system_monitoring(self):
        self.display_system_info()
        self.log_activity("[SYSTEM] KeySentinel   started successfully")
        
        # Auto-start features if enabled
        if self.auto_scan_var.get():
            self.root.after(2000, self.quick_scan)

    def display_system_info(self):
        try:
            os_info = f"OS: {platform.system()} {platform.release()}"
            python_ver = f"Python: {platform.python_version()}"
            arch = f"Architecture: {platform.machine()}"
            user = f"User: {os.getlogin()}"
            timestamp = f"Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            
            # System resources
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            resource_info = f"CPU: {cpu_percent}% | RAM: {memory.percent}% | Disk: {disk.percent}%"
            
            full_info = f"{os_info} | {python_ver} | {arch}\n{user} | {timestamp}\nResources: {resource_info}"
            self.system_info_label.config(text=full_info)
            
        except Exception as e:
            self.system_info_label.config(text=f"System info unavailable: {e}")

    def log_activity(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        self.activity_text.insert(tk.END, formatted_message)
        self.activity_text.see(tk.END)
        
        # Update status bar
        self.status_label.config(text=message[:50] + "..." if len(message) > 50 else message)

    # ---------------- AI Chat helpers ----------------
    def load_api_key(self):
        # Return hardcoded API key
        return "84733d1e-2c98-4db2-a1f9-47182b05ce24"

    def save_api_key(self, key_value):
        # Save to local config (WARNING: stored in plaintext)
        try:
            with open(self._ai_config_path, 'w', encoding='utf-8') as f:
                json.dump({'api_key': key_value}, f)
            self.log_activity('[AI] API key saved to local config')
        except Exception as e:
            self.log_activity(f'[AI] Failed to save API key: {e}')

    def set_api_key(self):
        # Prompt user to enter API key (we deliberately do not hardcode keys into repo)
        key = simpledialog.askstring('Sambanova API Key', 'Enter your Sambanova API key (will be stored locally):', show='*')
        if key:
            self.save_api_key(key)

    def clear_ai_chat(self):
        self.ai_chat_text.config(state='normal')
        self.ai_chat_text.delete(1.0, tk.END)
        self.ai_chat_text.config(state='disabled')

    def append_ai_message(self, speaker, message):
        self.ai_chat_text.config(state='normal')
        self.ai_chat_text.insert(tk.END, f"{speaker}: {message}\n\n")
        self.ai_chat_text.see(tk.END)
        self.ai_chat_text.config(state='disabled')

    def send_ai_message(self):
        user_msg = self.ai_input_var.get().strip()
        if not user_msg:
            return

        # Display user's message
        self.append_ai_message('User', user_msg)
        self.ai_input_var.set('')

        # Get API key
        api_key = self.load_api_key()
        if not api_key:
            self.append_ai_message('AI', 'API key not set. Click "Set API Key" or set SAMBANOVA_API_KEY environment variable.')
            return

        # Call Sambanova client in a background thread to avoid blocking UI
        def worker():
            try:
                response = self._sambanova_client.send_message(api_key, user_msg)
                self.root.after(0, lambda: self.append_ai_message('AI', response))
            except Exception as e:
                self.root.after(0, lambda: self.append_ai_message('AI', f'Error: {e}'))

        threading.Thread(target=worker, daemon=True).start()

    # Button command methods
    def quick_scan(self):
        self.log_activity("[SCAN] Starting quick keylogger scan...")
        self.scan_btn.config(state="disabled", text="🔄 Scanning...")
        
        def scan_thread():
            try:
                threats = scan_processes_with_scores()
                self.root.after(0, lambda: self.display_scan_results(threats))
            except Exception as e:
                self.root.after(0, lambda: self.log_activity(f"[ERROR] Scan failed: {e}"))
            finally:
                self.root.after(0, lambda: self.scan_btn.config(state="normal", text="🔍 Start Deep Scan"))
        
        threading.Thread(target=scan_thread, daemon=True).start()

    def display_scan_results(self, threats):
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        # Save the last scan results so reports can include all scanned items
        try:
            self.last_scan_results = threats if threats is not None else []
        except Exception:
            self.last_scan_results = []
        
        if threats:
            for threat in threats:
                risk_level = "HIGH" if threat['score'] > 70 else "MEDIUM" if threat['score'] > 30 else "LOW"
                status = "DETECTED"
                action = "Monitor" if threat['score'] < 50 else "Quarantine"
                
                self.results_tree.insert("", tk.END, values=(
                    threat['name'], threat['pid'], risk_level, 
                    threat['score'], status, action
                ))
                
                # Log high-risk threats
                if threat['score'] > 50:
                    self.db.log_threat(threat['name'], threat['pid'], risk_level, "Detected")
                    self.threat_count += 1
                    
            self.log_activity(f"[SCAN] Found {len(threats)} potential threats")
            self.threat_counter.config(text=f"Threats Detected: {self.threat_count}")
        else:
            self.log_activity("[SCAN] No threats detected - System clean")

    def toggle_realtime_scan(self):
        if not self.realtime_scanning:
            self.realtime_scanning = True
            self.scanner.start_realtime_scan()
            self.realtime_btn.config(text="🛑 Stop Real-time", bg="#aa0000")
            self.security_status.config(text="🟢 ACTIVE", fg="#00aa00")
            self.log_activity("[PROTECTION] Real-time scanning activated")
        else:
            self.realtime_scanning = False
            self.scanner.stop_scan()
            self.realtime_btn.config(text="🛡️ Start Real-time", bg="#0066aa")
            self.security_status.config(text="🔴 OFFLINE", fg="#ff4444")
            self.log_activity("[PROTECTION] Real-time scanning deactivated")

    def on_threat_detected(self, threat):
        """Callback for real-time threat detection"""
        self.threat_count += 1
        self.threat_counter.config(text=f"Threats Detected: {self.threat_count}")
        
        if self.realtime_alerts_var.get():
            messagebox.showwarning("Threat Detected!", 
                                 f"Suspicious process detected:\n{threat['name']} (PID: {threat['pid']})\n"
                                 f"Threat Score: {threat['score']}")
        
        self.log_activity(f"[THREAT] {threat['name']} detected with score {threat['score']}")

    def open_virtual_keyboard(self):
        # Use the OSK-opening method from enhanced_secure_typing
        try:
            AdvancedSecureTypingApp().open_system_keyboard()
            self.log_activity("[TOOL] On-Screen Keyboard opened")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open On-Screen Keyboard: {e}")

    def secure_typing(self):
        SecureTypingApp()
        self.log_activity("[TOOL] Secure typing mode activated")

    def open_live_monitor(self):
        self.log_activity("[TOOL] Live process monitor opened")
        try:
            win = tk.Toplevel(self.root)
            _set_window_icon(win)
            win.title("Live Monitor - Scan Statistics")
            win.geometry("700x420")
            win.configure(bg="#0a0a0a")

            container = tk.Frame(win, bg="#0a0a0a")
            container.pack(fill="both", expand=True)

            canvas = tk.Canvas(container, bg="#1a1a1a", highlightthickness=0)
            canvas.pack(fill="both", expand=True, padx=10, pady=10)

            info_lbl = tk.Label(win, text="Updating...", bg="#0a0a0a", fg="white")
            info_lbl.pack(side="bottom", pady=(0,8))

            def draw_stats():
                scans = getattr(self, 'last_scan_results', []) or []
                # compute counts
                def score_of(s):
                    try:
                        return float(s.get('score', 0)) if isinstance(s, dict) else 0
                    except Exception:
                        return 0

                high = len([s for s in scans if score_of(s) > 70])
                medium = len([s for s in scans if 30 < score_of(s) <= 70])
                low = len([s for s in scans if score_of(s) <= 30])

                canvas.delete('all')
                w = max(canvas.winfo_width(), 300)
                h = max(canvas.winfo_height(), 200)

                # draw title
                canvas.create_text(w//2, 20, text='Scan Results (Live)', fill='white', font=('Helvetica', 14, 'bold'))

                labels = ['High', 'Medium', 'Low']
                values = [high, medium, low]
                colors = ['#ff4444', '#ffaa00', '#00aa00']

                # bar chart layout
                maxv = max(1, max(values))
                bar_width = min(140, (w - 120) // 3)
                gap = (w - (bar_width * 3)) // 4
                x = gap + 40
                base_y = h - 80

                for i, val in enumerate(values):
                    bar_h = int((val / maxv) * (h * 0.45))
                    canvas.create_rectangle(x, base_y - bar_h, x + bar_width, base_y, fill=colors[i], outline='')
                    canvas.create_text(x + bar_width//2, base_y + 18, text=f"{labels[i]}: {val}", fill='white')
                    x += bar_width + gap

                # small summary text
                canvas.create_text(10, 40, anchor='w', text=f"Total scanned: {len(scans)}", fill='white')
                canvas.create_text(10, 60, anchor='w', text=f"Threats detected (total): {self.threat_count}", fill='white')

                info_lbl.config(text=f"Last update: {datetime.datetime.now().strftime('%H:%M:%S')}")

                # schedule next update
                win.after(2000, draw_stats)

            # Start updating after UI settles
            win.after(200, draw_stats)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to open Live Monitor: {e}")
            self.log_activity(f"[ERROR] Failed to open Live Monitor: {e}")

    def emergency_mode(self):
        response = messagebox.askyesno("Emergency Mode", 
                                     "This will terminate all suspicious processes.\nContinue?")
        if response:
            self.log_activity("[EMERGENCY] Emergency mode activated - Terminating threats")
            # Implementation for emergency process termination

    def start_deep_scan(self):
        self.log_activity("[SCAN] Starting comprehensive deep scan...")
        # Implementation for deep scan with extended heuristics

    def toggle_network_monitoring(self):
        if not self.network_monitoring:
            self.network_monitoring = True
            self.network_monitor.start_monitoring()
            self.log_activity("[NETWORK] Network monitoring activated")
        else:
            self.network_monitoring = False
            self.network_monitor.stop_monitoring()
            self.log_activity("[NETWORK] Network monitoring deactivated")

    def manage_whitelist(self):
        self.log_activity("[SETTINGS] Opening Process Protection Manager...")
        try:
            # Import and open the ProcessProtectionManager
            from process_protection_manager import ProcessProtectionManager
            protection_manager = ProcessProtectionManager()
            protection_manager.run()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open Process Protection Manager: {e}")
            self.log_activity(f"[ERROR] Failed to open Process Protection Manager: {e}")

    def manage_quarantine(self):
        self.log_activity("[SETTINGS] Opening Process Protection Manager...")
        try:
            # Import and open the ProcessProtectionManager
            from process_protection_manager import ProcessProtectionManager
            protection_manager = ProcessProtectionManager()
            protection_manager.run()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open Process Protection Manager: {e}")
            self.log_activity(f"[ERROR] Failed to open Process Protection Manager: {e}")

    def toggle_auto_protection(self):
        self.log_activity("[SETTINGS] Opening Process Protection Manager...")
        try:
            # Import and open the ProcessProtectionManager
            from process_protection_manager import ProcessProtectionManager
            protection_manager = ProcessProtectionManager()
            protection_manager.run()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open Process Protection Manager: {e}")
            self.log_activity(f"[ERROR] Failed to open Process Protection Manager: {e}")

    def generate_report(self, report_type="daily"):
        self.log_activity(f"[REPORT] Generating {report_type} report...")
        
        # Clear previous report
        self.report_text.delete(1.0, tk.END)
        
        try:
            # Get threat data from database
            # We intentionally show only the most recent scan results in the report
            scans = getattr(self, 'last_scan_results', []) or []

            # Calculate overview from last scan results (score -> severity)
            def _severity_from_score(s):
                try:
                    s = float(s)
                except Exception:
                    return 'Low'
                return 'High' if s > 70 else 'Medium' if s > 30 else 'Low'

            total_scanned = len(scans)
            high_count = len([s for s in scans if _severity_from_score(s.get('score', 0)) == 'High'])
            medium_count = len([s for s in scans if _severity_from_score(s.get('score', 0)) == 'Medium'])
            low_count = len([s for s in scans if _severity_from_score(s.get('score', 0)) == 'Low'])

            report_content = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                        KeySentinel - Threat Report                         ║
║                              {report_type.upper()} SUMMARY                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

Report Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Report Type: {report_type.capitalize()}

SYSTEM OVERVIEW (based on most recent scan):
• Processes Scanned: {total_scanned}
• High Severity (score>70): {high_count}
• Medium Severity (30<score<=70): {medium_count}
• Low Severity (score<=30): {low_count}

LAST SCAN RESULTS (most recent run):
"""
            
            # Append scan results listing
            if scans:
                for s in scans:
                    try:
                        name = s.get('name', s.get('process', 'Unknown')) if isinstance(s, dict) else str(s)
                        pid = s.get('pid', '') if isinstance(s, dict) else ''
                        score = s.get('score', '') if isinstance(s, dict) else ''
                        reason = s.get('reason', '') if isinstance(s, dict) else ''
                    except Exception:
                        name = str(s)
                        pid = ''
                        score = ''
                        reason = ''
                    report_content += f"- {name} (PID: {pid}) | Score: {score} | Reason: {reason}\n"
            else:
                report_content += "- No recent scan results available.\n"
            
            # Add system statistics
            try:
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                report_content += f"""

SYSTEM STATISTICS:
• CPU Usage: {cpu_percent:.1f}%
• Memory Usage: {memory.percent:.1f}%
• Disk Usage: {disk.percent:.1f}%
• Active Processes: {len(psutil.pids())}

PROTECTION STATUS:
• Real-time Scanning: {'🟢 ACTIVE' if self.realtime_scanning else '🔴 INACTIVE'}
• Network Monitoring: {'🟢 ACTIVE' if self.network_monitoring else '🔴 INACTIVE'}
• Threats Blocked: {self.threat_count}

═══════════════════════════════════════════════════════════════════════════════════
"""
            except Exception as e:
                report_content += f"\n⚠️ Error retrieving system statistics: {e}\n"
            
            # Display the report
            self.report_text.insert(1.0, report_content)
            self.log_activity(f"[REPORT] {report_type.capitalize()} report generated successfully")
            
        except Exception as e:
            error_msg = f"Error generating report: {str(e)}"
            self.report_text.insert(1.0, f"❌ {error_msg}")
            self.log_activity(f"[ERROR] {error_msg}")

    def export_report(self):
        self.log_activity("[EXPORT] Exporting threat data...")
        try:
            from tkinter import filedialog
            filename = filedialog.asksaveasfilename(
                title="Export Threat Report",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if filename:
                # Get current report content
                report_content = self.report_text.get(1.0, tk.END)
                
                # Write to file
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                
                messagebox.showinfo("Export Successful", f"Report exported to:\n{filename}")
                self.log_activity(f"[EXPORT] Report exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report: {e}")
            self.log_activity(f"[ERROR] Export failed: {e}")

    def import_settings(self):
        self.log_activity("[IMPORT] Importing settings...")
        # Implementation for settings import

    def open_process_manager(self):
        self.log_activity("[TOOL] Opening Process Protection Manager...")
        try:
            # Import and open the ProcessProtectionManager
            from process_protection_manager import ProcessProtectionManager
            protection_manager = ProcessProtectionManager()
            protection_manager.run()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open Process Protection Manager: {e}")
            self.log_activity(f"[ERROR] Failed to open Process Protection Manager: {e}")

    def show_system_info(self):
        info_window = tk.Toplevel(self.root)
        _set_window_icon(info_window)
        info_window.title("System Information")
        info_window.geometry("500x400")
        info_window.configure(bg="#0a0a0a")
        
        # Display detailed system information
        self.log_activity("[INFO] System information displayed")

    def show_about(self):
        about_text = """
KeySentinel -
Keylogger Defense System

Features:
• Real-time process monitoring
• Advanced threat detection
• Virtual keyboard protection
• Secure typing environment
• System process monitoring
• Comprehensive reporting

© 2024 KeySentinel Security Solutions
        """
        messagebox.showinfo("About KeySentinel", about_text)
        
        

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
        self.log_activity("[ADMIN] Password changed successfully")

    def open_standalone_report_viewer(self):
        """Open the standalone report viewer"""
        self.log_activity("[TOOL] Opening standalone report viewer...")
        try:
            from report_viewer import ThreatReportViewer
            ThreatReportViewer()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open report viewer: {e}")
            self.log_activity(f"[ERROR] Failed to open report viewer: {e}")


# Start the advanced application
if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedKeySenintelProApp(root)
    root.mainloop()
